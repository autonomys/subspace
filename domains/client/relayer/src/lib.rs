// TODO(ved): remove once the code is connected.
#![allow(dead_code)]
#![warn(rust_2018_idioms)]

pub mod worker;

use domain_runtime_primitives::RelayerId;
use parity_scale_codec::{Decode, Encode};
use sc_client_api::{AuxStore, HeaderBackend, ProofProvider, StorageProof};
use sp_api::ProvideRuntimeApi;
use sp_domain_tracker::DomainTrackerApi;
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
    /// Emits when failed to store the processed block number.
    StoreRelayedBlockNumber,
    /// Emits when unable to fetch domain_id.
    UnableToFetchDomainId,
    /// Emits when unable to fetch relay confirmation depth.
    UnableToFetchRelayConfirmationDepth,
    /// Blockchain related error.
    BlockchainError(Box<sp_blockchain::Error>),
    /// Arithmatic related error.
    ArithmaticError(ArithmeticError),
    /// Api related error.
    ApiError(sp_api::ApiError),
    /// Emits when the core domain block is not yet confirmed on the system domain.
    CoreDomainNonConfirmedOnSystemDomain,
    /// Unable to fetch block number against a block hash.
    UnableToFetchBlockNumber,
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

impl From<sp_api::ApiError> for Error {
    fn from(err: sp_api::ApiError) -> Self {
        Error::ApiError(err)
    }
}

impl<Client, Block> Relayer<Client, Block>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + AuxStore + ProofProvider<Block> + ProvideRuntimeApi<Block>,
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
        block_hash: Block::Hash,
        key: &[u8],
    ) -> Result<Proof<NumberFor<Block>, Block::Hash>, Error> {
        system_domain_client
            .header(BlockId::Hash(block_hash))?
            .map(|header| *header.state_root())
            .and_then(|state_root| {
                let proof = system_domain_client
                    .read_proof(block_hash, &mut [key].into_iter())
                    .ok()?;
                Some(Proof {
                    state_root,
                    core_domain_proof: None,
                    message_proof: proof,
                })
            })
            .ok_or(Error::ConstructStorageProof)
    }

    /// Constructs the proof for the given key using the core domain backend.
    fn construct_core_domain_storage_proof_for_key_at(
        core_domain_client: &Arc<Client>,
        block_hash: Block::Hash,
        key: &[u8],
        core_domain_proof: StorageProof,
    ) -> Result<Proof<NumberFor<Block>, Block::Hash>, Error> {
        core_domain_client
            .header(BlockId::Hash(block_hash))?
            .map(|header| (*header.number(), *header.state_root()))
            .and_then(|(number, state_root)| {
                let proof = core_domain_client
                    .read_proof(block_hash, &mut [key].into_iter())
                    .ok()?;
                Some(Proof {
                    state_root,
                    core_domain_proof: Some((number, core_domain_proof)),
                    message_proof: proof,
                })
            })
            .ok_or(Error::ConstructStorageProof)
    }

    fn construct_cross_domain_message_and_submit<
        Submitter: Fn(CrossDomainMessage<Block::Hash, NumberFor<Block>>) -> Result<(), sp_api::ApiError>,
        ProofConstructor: Fn(Block::Hash, &[u8]) -> Result<Proof<NumberFor<Block>, Block::Hash>, Error>,
    >(
        block_hash: Block::Hash,
        msgs: Vec<RelayerMessageWithStorageKey>,
        proof_constructor: ProofConstructor,
        submitter: Submitter,
    ) -> Result<(), Error> {
        for msg in msgs {
            let proof = match proof_constructor(block_hash, &msg.storage_key) {
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

    fn filter_assigned_messages(
        client: &Arc<Client>,
        mut msgs: RelayerMessagesWithStorageKey,
    ) -> Result<RelayerMessagesWithStorageKey, Error> {
        let api = client.runtime_api();
        let best_block_id = BlockId::Hash(client.info().best_hash);
        msgs.outbox.retain(|msg| {
            let id = (msg.channel_id, msg.nonce);
            match api.should_relay_outbox_message(&best_block_id, msg.dst_domain_id, id) {
                Ok(valid) => valid,
                Err(err) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?err,
                        "Failed to fetch validity of outbox message {id:?} for domain {0:?}",
                        msg.dst_domain_id
                    );
                    false
                }
            }
        });

        msgs.inbox_responses.retain(|msg| {
            let id = (msg.channel_id, msg.nonce);
            match api.should_relay_inbox_message_response(&best_block_id, msg.dst_domain_id, id) {
                Ok(valid) => valid,
                Err(err) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?err,
                        "Failed to fetch validity of inbox message response {id:?} for domain {0:?}",
                        msg.dst_domain_id
                    );
                    false
                }
            }
        });

        Ok(msgs)
    }

    pub(crate) fn submit_messages_from_system_domain(
        relayer_id: RelayerId,
        system_domain_client: &Arc<Client>,
        confirmed_block_hash: Block::Hash,
    ) -> Result<(), Error> {
        let api = system_domain_client.runtime_api();
        let confirmed_block_id = BlockId::Hash(confirmed_block_hash);
        let assigned_messages: RelayerMessagesWithStorageKey = api
            .relayer_assigned_messages(&confirmed_block_id, relayer_id)
            .map_err(|_| Error::FetchAssignedMessages)?;
        let filtered_messages =
            Self::filter_assigned_messages(system_domain_client, assigned_messages)?;

        // short circuit if the there are no messages to relay
        if filtered_messages.outbox.is_empty() && filtered_messages.inbox_responses.is_empty() {
            return Ok(());
        }

        let best_block_id = BlockId::Hash(system_domain_client.info().best_hash);
        Self::construct_cross_domain_message_and_submit(
            confirmed_block_hash,
            filtered_messages.outbox,
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
            confirmed_block_hash,
            filtered_messages.inbox_responses,
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

    pub(crate) fn submit_messages_from_core_domain<SDC>(
        relayer_id: RelayerId,
        core_domain_client: &Arc<Client>,
        system_domain_client: &Arc<SDC>,
        confirmed_block_hash: Block::Hash,
    ) -> Result<(), Error>
    where
        SDC: HeaderBackend<Block> + ProvideRuntimeApi<Block> + ProofProvider<Block>,
        SDC::Api: DomainTrackerApi<Block, NumberFor<Block>>,
    {
        // fetch messages to be relayed
        let core_domain_api = core_domain_client.runtime_api();
        let assigned_messages: RelayerMessagesWithStorageKey = core_domain_api
            .relayer_assigned_messages(&BlockId::Hash(confirmed_block_hash), relayer_id)
            .map_err(|_| Error::FetchAssignedMessages)?;

        let filtered_messages =
            Self::filter_assigned_messages(core_domain_client, assigned_messages)?;

        // short circuit if the there are no messages to relay
        if filtered_messages.outbox.is_empty() && filtered_messages.inbox_responses.is_empty() {
            return Ok(());
        }

        // check if this block state root is confirmed on system domain
        // and generate proof
        let core_domain_state_root_proof = {
            let system_domain_api = system_domain_client.runtime_api();
            let latest_system_domain_block_hash = system_domain_client.info().best_hash;
            let latest_system_domain_block_id = BlockId::Hash(latest_system_domain_block_hash);
            let core_domain_id = Self::domain_id(core_domain_client)?;
            let confirmed_block_number = *core_domain_client
                .header(BlockId::Hash(confirmed_block_hash))?
                .ok_or(Error::UnableToFetchBlockNumber)?
                .number();
            match system_domain_api.storage_key_for_core_domain_state_root(
                &latest_system_domain_block_id,
                core_domain_id,
                confirmed_block_number,
            )? {
                Some(storage_key) => {
                    // construct storage proof for the core domain state root using system domain backend.
                    system_domain_client.read_proof(
                        latest_system_domain_block_hash,
                        &mut [storage_key.as_ref()].into_iter(),
                    )?
                }
                None => return Err(Error::CoreDomainNonConfirmedOnSystemDomain),
            }
        };

        let best_block_id = BlockId::Hash(core_domain_client.info().best_hash);
        Self::construct_cross_domain_message_and_submit(
            confirmed_block_hash,
            filtered_messages.outbox,
            |block_id, key| {
                Self::construct_core_domain_storage_proof_for_key_at(
                    core_domain_client,
                    block_id,
                    key,
                    core_domain_state_root_proof.clone(),
                )
            },
            |msg| core_domain_api.submit_outbox_message_unsigned(&best_block_id, msg),
        )?;

        Self::construct_cross_domain_message_and_submit(
            confirmed_block_hash,
            filtered_messages.inbox_responses,
            |block_id, key| {
                Self::construct_core_domain_storage_proof_for_key_at(
                    core_domain_client,
                    block_id,
                    key,
                    core_domain_state_root_proof.clone(),
                )
            },
            |msg| core_domain_api.submit_inbox_response_message_unsigned(&best_block_id, msg),
        )?;

        Ok(())
    }

    fn last_relayed_block_key(domain_id: DomainId) -> Vec<u8> {
        (b"message_relayer_last_processed_block_of_domain", domain_id).encode()
    }

    fn fetch_last_relayed_block(
        client: &Arc<Client>,
        domain_id: DomainId,
    ) -> Option<NumberFor<Block>> {
        let encoded = client
            .get_aux(&Self::last_relayed_block_key(domain_id))
            .ok()??;

        NumberFor::<Block>::decode(&mut encoded.as_ref()).ok()
    }

    pub(crate) fn store_last_relayed_block(
        client: &Arc<Client>,
        domain_id: DomainId,
        block_number: NumberFor<Block>,
    ) -> Result<(), Error> {
        client
            .insert_aux(
                &[(
                    Self::last_relayed_block_key(domain_id).as_ref(),
                    block_number.encode().as_ref(),
                )],
                &[],
            )
            .map_err(|_| Error::StoreRelayedBlockNumber)
    }
}
