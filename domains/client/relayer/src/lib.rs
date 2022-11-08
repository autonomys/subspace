// TODO(ved): remove once the code is connected.
#![allow(dead_code)]

mod worker;

use parity_scale_codec::{Decode, Encode};
use sc_client_api::{AuxStore, HeaderBackend, ProofProvider, StorageKey};
use sp_api::{ProvideRuntimeApi, StateBackend};
use sp_domains::DomainId;
use sp_messenger::messages::{
    CrossDomainMessage, Proof, RelayerMessageWithStorageKey, RelayerMessagesWithStorageKey,
};
use sp_messenger::RelayerApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use sp_runtime::ArithmeticError;
use std::marker::PhantomData;
use std::sync::Arc;
use system_runtime_primitives::RelayerId;

/// The logging target.
const LOG_TARGET: &str = "message::relayer";

/// Relayer relays messages between core domains using system domain as trusted third party.
struct Relayer<Client, Block>(PhantomData<(Client, Block)>);

/// Relayer error types.
#[derive(Debug)]
pub enum Error {
    /// Emits when storage proof construction fails.
    ConstructStorageProof,
    /// Emits when failed to fetch assigned messages for a given relayer.
    FetchAssignedMessages,
    /// Emits when failed to store the processed block id.
    StoreRelayedBlockId,
    /// Emits when failed to fetch stored processed block id.
    UnableToFetchProcessedBlockId,
    /// Emits when unable to fetch domain_id.
    UnableToFetchDomainId,
    /// Emits when unable to fetch relay confirmation depth.
    UnableToFetchRelayConfirmationDepth,
    /// Blockchain related error.
    BlockchainError(Box<sp_blockchain::Error>),
    /// Arithmatic related error.
    ArithmaticError(ArithmeticError),
}

impl From<sp_blockchain::Error> for Error {
    fn from(err: sp_blockchain::Error) -> Self {
        Error::BlockchainError(Box::new(err))
    }
}

impl From<ArithmeticError> for Error {
    fn from(err: ArithmeticError) -> Self {
        Error::ArithmaticError(err)
    }
}

impl<Client, Block> Relayer<Client, Block>
where
    Block: BlockT,
    Client: HeaderBackend<Block>
        + AuxStore
        + StateBackend<<Block::Header as HeaderT>::Hashing>
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, RelayerId, NumberFor<Block>>,
{
    pub(crate) fn domain_id(client: &Arc<Client>) -> Result<DomainId, Error> {
        let best_block_id = BlockId::Hash(client.info().best_hash);
        let api = client.runtime_api();
        api.domain_id(&best_block_id)
            .map_err(|_| Error::UnableToFetchDomainId)
    }

    pub(crate) fn relay_confirmation_depth(
        client: &Arc<Client>,
    ) -> Result<NumberFor<Block>, Error> {
        let best_block_id = BlockId::Hash(client.info().best_hash);
        let api = client.runtime_api();
        api.relay_confirmation_depth(&best_block_id)
            .map_err(|_| Error::UnableToFetchRelayConfirmationDepth)
    }

    /// Constructs the proof for the given key using the system domain backend.
    fn construct_system_domain_storage_proof_for_key_at(
        system_domain_client: &Arc<Client>,
        block_id: BlockId<Block>,
        key: &StorageKey,
    ) -> Result<Proof<NumberFor<Block>, Block::Hash>, Error> {
        system_domain_client
            .header(block_id)?
            .map(|header| *header.state_root())
            .and_then(|state_root| {
                let proof = system_domain_client
                    .read_proof(&block_id, &mut [key.as_ref()].into_iter())
                    .ok()?;
                Some(Proof {
                    state_root,
                    core_domain_proof: None,
                    message_proof: proof,
                })
            })
            .ok_or(Error::ConstructStorageProof)
    }

    fn construct_cross_domain_message_and_submit<
        Submitter: Fn(CrossDomainMessage<Block::Hash, NumberFor<Block>>) -> Result<(), sp_api::ApiError>,
        ProofConstructor: Fn(BlockId<Block>, &StorageKey) -> Result<Proof<NumberFor<Block>, Block::Hash>, Error>,
    >(
        block_id: BlockId<Block>,
        msgs: Vec<RelayerMessageWithStorageKey>,
        proof_constructor: ProofConstructor,
        submitter: Submitter,
    ) -> Result<(), Error> {
        for msg in msgs {
            let proof = match proof_constructor(block_id, &msg.storage_key) {
                Ok(proof) => proof,
                Err(err) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        "Failed to construct storage proof for message: {:?} bound to domain: {:?} with error: {:?}",
                        (msg.channel_id, msg.nonce),
                        msg.dst_domain_id,
                        err
                    );
                    continue;
                }
            };
            let msg = CrossDomainMessage::from_relayer_msg_with_proof(msg, proof);
            let (dst_domain, msg_id) = (msg.dst_domain_id, (msg.channel_id, msg.nonce));
            if let Err(err) = submitter(msg) {
                tracing::error!(
                    target: LOG_TARGET,
                    ?err,
                    "Failed to submit message: {msg_id:?} to domain: {dst_domain:?}",
                );
            }
        }

        Ok(())
    }

    pub(crate) fn submit_messages_from_system_domain(
        relayer_id: RelayerId,
        system_domain_client: &Arc<Client>,
        confirmed_block_id: BlockId<Block>,
    ) -> Result<(), Error> {
        let best_block_id = BlockId::Hash(system_domain_client.info().best_hash);
        let api = system_domain_client.runtime_api();

        let assigned_messages: RelayerMessagesWithStorageKey = api
            .relayer_assigned_messages(&confirmed_block_id, relayer_id)
            .map_err(|_| Error::FetchAssignedMessages)?;

        // TODO(ved): check for already relayed messages before submitting
        // TODO(ved): would need a function on runtime to confirm the relay.

        Self::construct_cross_domain_message_and_submit(
            confirmed_block_id,
            assigned_messages.outbox,
            |block_id, key| {
                Self::construct_system_domain_storage_proof_for_key_at(
                    system_domain_client,
                    block_id,
                    key,
                )
            },
            |msg| api.submit_outbox_message_unsigned(&best_block_id, msg),
        )?;

        Self::construct_cross_domain_message_and_submit(
            confirmed_block_id,
            assigned_messages.inbox_responses,
            |block_id, key| {
                Self::construct_system_domain_storage_proof_for_key_at(
                    system_domain_client,
                    block_id,
                    key,
                )
            },
            |msg| api.submit_inbox_response_message_unsigned(&best_block_id, msg),
        )?;

        Ok(())
    }

    fn last_relayed_block_key(domain_id: DomainId) -> Vec<u8> {
        (b"message_relayer_last_processed_block_of_domain", domain_id).encode()
    }

    fn fetch_last_relayed_block(
        client: &Arc<Client>,
        domain_id: DomainId,
    ) -> Option<BlockId<Block>> {
        let encoded = client
            .get_aux(&Self::last_relayed_block_key(domain_id))
            .ok()??;

        BlockId::decode(&mut encoded.as_ref()).ok()
    }

    pub(crate) fn store_last_relayed_block(
        client: &Arc<Client>,
        domain_id: DomainId,
        block_id: BlockId<Block>,
    ) -> Result<(), Error> {
        client
            .insert_aux(
                &[(
                    Self::last_relayed_block_key(domain_id).as_ref(),
                    block_id.encode().as_ref(),
                )],
                &[],
            )
            .map_err(|_| Error::StoreRelayedBlockId)
    }
}
