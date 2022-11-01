// TODO(ved): remove once the code is connected.
#![allow(dead_code)]

mod worker;

use parity_scale_codec::{Decode, Encode};
use sc_client_api::{AuxStore, HeaderBackend, ProofProvider, StorageKey};
use sp_api::{ProvideRuntimeApi, StateBackend};
use sp_messenger::messages::{
    CrossDomainMessage, Proof, RelayerMessageWithStorageKey, RelayerMessagesWithStorageKey,
};
use sp_messenger::RelayerApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use std::marker::PhantomData;
use std::sync::Arc;
use system_runtime_primitives::{DomainId, RelayerId};

/// The logging target.
const LOG_TARGET: &str = "message::relayer";

/// Relayer relays messages between core domains using system domain as trusted third party.
struct Relayer<Client, Block> {
    domain_client: Arc<Client>,
    relayer_id: RelayerId,
    _phantom_data: PhantomData<Block>,
}

/// Relayer error types.
enum Error {
    /// Emits when storage proof construction fails.
    ConstructStorageProof,
    /// Emits when failed to fetch assigned messages for a given relayer.
    FetchAssignedMessages,
    /// Emits when failed to submit an unsigned extrinsic.
    SubmitUnsignedExtrinsic,
    /// Emits when failed to store the processed block id.
    StoreProcessedBlockId,
    /// Emits when unable to fetch domain_id.
    UnableToFetchDomainId,
}

impl<Client, Block> Relayer<Client, Block>
where
    Block: BlockT,
    Client: HeaderBackend<Block>
        + AuxStore
        + StateBackend<<Block::Header as HeaderT>::Hashing>
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, RelayerId, DomainId>,
{
    /// Constructs the proof for the given key using the backend for the given key.
    fn construct_storage_proof_for_key_at(
        &self,
        block_id: &BlockId<Block>,
        key: &StorageKey,
    ) -> Result<Proof<Block::Hash>, Error> {
        let state_version = sp_runtime::StateVersion::default();
        let state_root = self
            .domain_client
            .storage_root(std::iter::empty(), state_version)
            .0;
        let proof = self
            .domain_client
            .read_proof(block_id, &mut [key.as_ref()].into_iter())
            .map_err(|_| Error::ConstructStorageProof)?;

        Ok(Proof {
            state_root,
            message_proof: proof,
        })
    }

    fn construct_cross_domain_message_and_submit<
        Submitter: Fn(CrossDomainMessage<DomainId, Block::Hash>) -> Result<(), sp_api::ApiError>,
    >(
        &self,
        k_deep_block_id: &BlockId<Block>,
        msgs: Vec<RelayerMessageWithStorageKey<DomainId>>,
        submitter: Submitter,
    ) -> Result<(), Error> {
        for msg in msgs {
            let proof =
                match self.construct_storage_proof_for_key_at(k_deep_block_id, &msg.storage_key) {
                    Ok(proof) => proof,
                    Err(_) => {
                        tracing::error!(
                        target: LOG_TARGET,
                        "Failed to construct storage proof for message: {:?} bound to domain: {:?}",
                        (msg.channel_id, msg.nonce),
                        msg.dst_domain_id,
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

    fn submit_unsigned_messages(&self, block_id: &BlockId<Block>) -> Result<(), Error> {
        let best_block_id = BlockId::Hash(self.domain_client.info().best_hash);
        let api = self.domain_client.runtime_api();
        let domain_id = api
            .domain_id(&best_block_id)
            .map_err(|_| Error::UnableToFetchDomainId)?;

        let assigned_messages: RelayerMessagesWithStorageKey<DomainId> = api
            .relayer_assigned_messages(block_id, self.relayer_id.clone())
            .map_err(|_| Error::FetchAssignedMessages)?;

        self.construct_cross_domain_message_and_submit(
            block_id,
            assigned_messages.outbox,
            |msg| api.submit_outbox_message_unsigned(&best_block_id, msg),
        )?;

        self.construct_cross_domain_message_and_submit(
            block_id,
            assigned_messages.inbox_responses,
            |msg| api.submit_inbox_response_message_unsigned(&best_block_id, msg),
        )?;

        // store processed block id for the domain_id
        self.store_last_processed_block(domain_id, block_id)?;
        Ok(())
    }

    fn last_processed_block_key(domain_id: DomainId) -> Vec<u8> {
        (b"message_relayer_last_processed_block", domain_id).encode()
    }

    fn fetch_last_processed_block(&self, domain_id: DomainId) -> Option<BlockId<Block>> {
        let encoded = self
            .domain_client
            .get_aux(&Self::last_processed_block_key(domain_id))
            .ok()??;

        BlockId::decode(&mut encoded.as_ref()).ok()
    }

    fn store_last_processed_block(
        &self,
        domain_id: DomainId,
        block_id: &BlockId<Block>,
    ) -> Result<(), Error> {
        self.domain_client
            .insert_aux(
                &[(
                    Self::last_processed_block_key(domain_id).as_ref(),
                    block_id.encode().as_ref(),
                )],
                &[],
            )
            .map_err(|_| Error::StoreProcessedBlockId)
    }
}
