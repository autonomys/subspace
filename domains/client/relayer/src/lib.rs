#![warn(rust_2018_idioms)]

pub mod worker;

use cross_domain_message_gossip::Message as GossipMessage;
use domain_runtime_primitives::RelayerId;
use futures::channel::mpsc::TrySendError;
use parity_scale_codec::{Decode, Encode};
use sc_client_api::{AuxStore, HeaderBackend, ProofProvider, StorageProof};
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::ProvideRuntimeApi;
use sp_domain_tracker::DomainTrackerApi;
use sp_domains::DomainId;
use sp_messenger::messages::{
    CrossDomainMessage, Proof, RelayerMessageWithStorageKey, RelayerMessagesWithStorageKey,
};
use sp_messenger::RelayerApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, CheckedAdd, CheckedSub, Header as HeaderT, NumberFor};
use sp_runtime::ArithmeticError;
use std::marker::PhantomData;
use std::sync::Arc;

/// The logging target.
const LOG_TARGET: &str = "message::relayer";

/// Relayer relays messages between core domains using system domain as trusted third party.
struct Relayer<Client, Block>(PhantomData<(Client, Block)>);

/// Sink used to submit all the gossip messages.
pub type GossipMessageSink = TracingUnboundedSender<GossipMessage>;

/// Relayer error types.
#[derive(Debug)]
pub enum Error {
    /// Emits when storage proof construction fails.
    ConstructStorageProof,
    /// Emits when unsigned extrinsic construction fails.
    FailedToConstructExtrinsic,
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
    /// Arithmetic related error.
    ArithmeticError(ArithmeticError),
    /// Api related error.
    ApiError(sp_api::ApiError),
    /// Emits when the core domain block is not yet confirmed on the system domain.
    CoreDomainNonConfirmedOnSystemDomain,
    /// Unable to fetch block number against a block hash.
    UnableToFetchBlockNumber,
    /// Failed to submit a cross domain message
    UnableToSubmitCrossDomainMessage(TrySendError<GossipMessage>),
}

impl From<sp_blockchain::Error> for Error {
    fn from(err: sp_blockchain::Error) -> Self {
        Error::BlockchainError(Box::new(err))
    }
}

impl From<ArithmeticError> for Error {
    fn from(err: ArithmeticError) -> Self {
        Error::ArithmeticError(err)
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
        let relay_confirmation_depth = api
            .relay_confirmation_depth(&best_block_id)
            .map_err(|_| Error::UnableToFetchRelayConfirmationDepth)?;
        relay_confirmation_depth
            .checked_add(&NumberFor::<Block>::from(1u32))
            .ok_or(Error::ArithmeticError(ArithmeticError::Overflow))
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
    fn construct_core_domain_storage_proof_for_key_at<SHash>(
        core_domain_client: &Arc<Client>,
        block_hash: Block::Hash,
        key: &[u8],
        system_domain_state_root: SHash,
        core_domain_proof: StorageProof,
    ) -> Result<Proof<NumberFor<Block>, Block::Hash>, Error>
    where
        SHash: Into<Block::Hash>,
    {
        core_domain_client
            .header(BlockId::Hash(block_hash))?
            .map(|header| *header.number())
            .and_then(|number| {
                let proof = core_domain_client
                    .read_proof(block_hash, &mut [key].into_iter())
                    .ok()?;
                Some(Proof {
                    state_root: system_domain_state_root.into(),
                    core_domain_proof: Some((number, core_domain_proof)),
                    message_proof: proof,
                })
            })
            .ok_or(Error::ConstructStorageProof)
    }

    fn construct_cross_domain_message_and_submit<
        Submitter: Fn(CrossDomainMessage<Block::Hash, NumberFor<Block>>) -> Result<(), Error>,
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

    fn confirmed_system_domain_block_id<SDC, SBlock>(
        system_domain_client: &Arc<SDC>,
    ) -> Result<SBlock::Header, Error>
    where
        SBlock: BlockT,
        SDC: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock>,
        SDC::Api: RelayerApi<SBlock, RelayerId, NumberFor<SBlock>>,
    {
        let best_block_id = BlockId::Hash(system_domain_client.info().best_hash);
        let best_block = system_domain_client.info().best_number;
        let api = system_domain_client.runtime_api();
        let confirmation_depth = api
            .relay_confirmation_depth(&best_block_id)
            .map_err(|_| Error::UnableToFetchRelayConfirmationDepth)?
            .checked_add(&NumberFor::<SBlock>::from(1u32))
            .ok_or(Error::ArithmeticError(ArithmeticError::Overflow))?;
        let confirmed_block = best_block
            .checked_sub(&confirmation_depth)
            .ok_or(Error::ArithmeticError(ArithmeticError::Underflow))?;

        system_domain_client
            .header(BlockId::Number(confirmed_block))?
            .ok_or(
                sp_blockchain::Error::MissingHeader(format!("number: {:?}", confirmed_block))
                    .into(),
            )
    }

    pub(crate) fn submit_messages_from_system_domain(
        relayer_id: RelayerId,
        system_domain_client: &Arc<Client>,
        confirmed_block_hash: Block::Hash,
        gossip_message_sink: &GossipMessageSink,
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
            |msg| Self::gossip_outbox_message(system_domain_client, msg, gossip_message_sink),
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
            |msg| {
                Self::gossip_inbox_response_message(system_domain_client, msg, gossip_message_sink)
            },
        )?;

        Ok(())
    }

    pub(crate) fn submit_messages_from_core_domain<SDC, SBlock>(
        relayer_id: RelayerId,
        core_domain_client: &Arc<Client>,
        system_domain_client: &Arc<SDC>,
        confirmed_block_hash: Block::Hash,
        gossip_message_sink: &GossipMessageSink,
    ) -> Result<(), Error>
    where
        SBlock: BlockT,
        NumberFor<SBlock>: From<NumberFor<Block>>,
        SBlock::Hash: Into<Block::Hash>,
        SDC: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock>,
        SDC::Api: DomainTrackerApi<SBlock, NumberFor<SBlock>>
            + RelayerApi<SBlock, RelayerId, NumberFor<SBlock>>,
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
        let (system_domain_state_root, core_domain_state_root_proof) = {
            let system_domain_api = system_domain_client.runtime_api();
            let confirmed_system_domain_block_header =
                Self::confirmed_system_domain_block_id(system_domain_client)?;
            let confirmed_system_domain_hash = confirmed_system_domain_block_header.hash();
            let core_domain_id = Self::domain_id(core_domain_client)?;
            let confirmed_block_number = *core_domain_client
                .header(BlockId::Hash(confirmed_block_hash))?
                .ok_or(Error::UnableToFetchBlockNumber)?
                .number();
            match system_domain_api.storage_key_for_core_domain_state_root(
                &BlockId::Hash(confirmed_system_domain_hash),
                core_domain_id,
                confirmed_block_number.into(),
            )? {
                Some(storage_key) => {
                    // construct storage proof for the core domain state root using system domain backend.
                    let proof = system_domain_client.read_proof(
                        confirmed_system_domain_hash,
                        &mut [storage_key.as_ref()].into_iter(),
                    )?;

                    tracing::debug!(
                        target: LOG_TARGET,
                        "Confirmed system domain block number: {:?}",
                        confirmed_system_domain_block_header.number()
                    );
                    (*confirmed_system_domain_block_header.state_root(), proof)
                }
                None => return Err(Error::CoreDomainNonConfirmedOnSystemDomain),
            }
        };

        Self::construct_cross_domain_message_and_submit(
            confirmed_block_hash,
            filtered_messages.outbox,
            |block_hash, key| {
                Self::construct_core_domain_storage_proof_for_key_at(
                    core_domain_client,
                    block_hash,
                    key,
                    system_domain_state_root,
                    core_domain_state_root_proof.clone(),
                )
            },
            |msg| Self::gossip_outbox_message(core_domain_client, msg, gossip_message_sink),
        )?;

        Self::construct_cross_domain_message_and_submit(
            confirmed_block_hash,
            filtered_messages.inbox_responses,
            |block_id, key| {
                Self::construct_core_domain_storage_proof_for_key_at(
                    core_domain_client,
                    block_id,
                    key,
                    system_domain_state_root,
                    core_domain_state_root_proof.clone(),
                )
            },
            |msg| Self::gossip_inbox_response_message(core_domain_client, msg, gossip_message_sink),
        )?;

        Ok(())
    }

    fn gossip_outbox_message(
        client: &Arc<Client>,
        msg: CrossDomainMessage<Block::Hash, NumberFor<Block>>,
        sink: &GossipMessageSink,
    ) -> Result<(), Error> {
        let best_block_id = BlockId::Hash(client.info().best_hash);
        let dst_domain_id = msg.dst_domain_id;
        let ext = client
            .runtime_api()
            .outbox_message_unsigned(&best_block_id, msg)?
            .ok_or(Error::FailedToConstructExtrinsic)?;

        sink.unbounded_send(GossipMessage {
            domain_id: dst_domain_id,
            encoded_data: ext.encode(),
        })
        .map_err(Error::UnableToSubmitCrossDomainMessage)
    }

    fn gossip_inbox_response_message(
        client: &Arc<Client>,
        msg: CrossDomainMessage<Block::Hash, NumberFor<Block>>,
        sink: &GossipMessageSink,
    ) -> Result<(), Error> {
        let best_block_id = BlockId::Hash(client.info().best_hash);
        let dst_domain_id = msg.dst_domain_id;
        let ext = client
            .runtime_api()
            .inbox_response_message_unsigned(&best_block_id, msg)?
            .ok_or(Error::FailedToConstructExtrinsic)?;

        sink.unbounded_send(GossipMessage {
            domain_id: dst_domain_id,
            encoded_data: ext.encode(),
        })
        .map_err(Error::UnableToSubmitCrossDomainMessage)
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
