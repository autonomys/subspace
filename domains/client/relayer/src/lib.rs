#![warn(rust_2018_idioms)]

pub mod worker;

use cross_domain_message_gossip::Message as GossipMessage;
use domain_runtime_primitives::RelayerId;
use futures::channel::mpsc::TrySendError;
use parity_scale_codec::{Decode, Encode, FullCodec};
use sc_client_api::{AuxStore, HeaderBackend, ProofProvider, StorageProof};
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::ProvideRuntimeApi;
use sp_domains::DomainId;
use sp_messenger::messages::{
    CoreDomainStateRootStorage, CrossDomainMessage, DomainBlockInfo, Proof,
    RelayerMessageWithStorageKey, RelayerMessagesWithStorageKey,
};
use sp_messenger::RelayerApi;
use sp_runtime::generic::BlockId;
use sp_runtime::scale_info::TypeInfo;
use sp_runtime::traits::{
    Block as BlockT, CheckedAdd, CheckedSub, Header as HeaderT, NumberFor, One, Zero,
};
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

type ProofOf<Block> = Proof<NumberFor<Block>, <Block as BlockT>::Hash, <Block as BlockT>::Hash>;
type UnProcessedBlocks<Block> = Vec<(NumberFor<Block>, <Block as BlockT>::Hash)>;

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
    ) -> Result<ProofOf<Block>, Error> {
        system_domain_client
            .header(block_hash)?
            .map(|header| (*header.number(), header.hash(), *header.state_root()))
            .and_then(|(block_number, block_hash, state_root)| {
                let proof = system_domain_client
                    .read_proof(block_hash, &mut [key].into_iter())
                    .ok()?;
                Some(Proof {
                    system_domain_block_info: DomainBlockInfo {
                        block_number,
                        block_hash,
                    },
                    system_domain_state_root: state_root,
                    core_domain_proof: None,
                    message_proof: proof,
                })
            })
            .ok_or(Error::ConstructStorageProof)
    }

    /// Constructs the proof for the given key using the core domain backend.
    fn construct_core_domain_storage_proof_for_key_at<SNumber, SHash>(
        system_domain_info: DomainBlockInfo<SNumber, SHash>,
        core_domain_client: &Arc<Client>,
        block_hash: Block::Hash,
        key: &[u8],
        system_domain_state_root: SHash,
        core_domain_proof: StorageProof,
    ) -> Result<ProofOf<Block>, Error>
    where
        SNumber: Into<NumberFor<Block>>,
        SHash: Into<Block::Hash>,
    {
        core_domain_client
            .header(block_hash)?
            .map(|header| (*header.number(), header.hash()))
            .and_then(|(number, hash)| {
                let proof = core_domain_client
                    .read_proof(block_hash, &mut [key].into_iter())
                    .ok()?;
                Some(Proof {
                    system_domain_block_info: DomainBlockInfo {
                        block_number: system_domain_info.block_number.into(),
                        block_hash: system_domain_info.block_hash.into(),
                    },
                    system_domain_state_root: system_domain_state_root.into(),
                    core_domain_proof: Some((
                        DomainBlockInfo {
                            block_number: number,
                            block_hash: hash,
                        },
                        core_domain_proof,
                    )),
                    message_proof: proof,
                })
            })
            .ok_or(Error::ConstructStorageProof)
    }

    fn construct_cross_domain_message_and_submit<
        Submitter: Fn(CrossDomainMessage<NumberFor<Block>, Block::Hash, Block::Hash>) -> Result<(), Error>,
        ProofConstructor: Fn(Block::Hash, &[u8]) -> Result<Proof<NumberFor<Block>, Block::Hash, Block::Hash>, Error>,
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

        Ok(system_domain_client
            .hash(confirmed_block)?
            .and_then(|block_hash| system_domain_client.header(block_hash).transpose())
            .ok_or_else(|| {
                sp_blockchain::Error::MissingHeader(format!("number: {confirmed_block:?}"))
            })??)
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
                Self::gossip_inbox_message_response(system_domain_client, msg, gossip_message_sink)
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
        Block::Hash: FullCodec,
        NumberFor<Block>: FullCodec + TypeInfo,
        NumberFor<SBlock>: From<NumberFor<Block>> + Into<NumberFor<Block>>,
        SBlock::Hash: Into<Block::Hash>,
        SDC: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock>,
        SDC::Api: RelayerApi<SBlock, RelayerId, NumberFor<SBlock>>,
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
        let (system_domain_info, system_domain_state_root, core_domain_state_root_proof) = {
            let confirmed_system_domain_block_header =
                Self::confirmed_system_domain_block_id(system_domain_client)?;
            let confirmed_system_domain_hash = confirmed_system_domain_block_header.hash();
            let core_domain_id = Self::domain_id(core_domain_client)?;
            let confirmed_block_header = core_domain_client
                .header(confirmed_block_hash)?
                .ok_or(Error::UnableToFetchBlockNumber)?;

            let storage_key = CoreDomainStateRootStorage::<
                NumberFor<Block>,
                Block::Hash,
                Block::Hash,
            >::storage_key(
                core_domain_id,
                *confirmed_block_header.number(),
                confirmed_block_header.hash(),
            );

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
            (
                DomainBlockInfo {
                    block_number: *confirmed_system_domain_block_header.number(),
                    block_hash: confirmed_system_domain_block_header.hash(),
                },
                *confirmed_system_domain_block_header.state_root(),
                proof,
            )
        };

        Self::construct_cross_domain_message_and_submit(
            confirmed_block_hash,
            filtered_messages.outbox,
            |block_hash, key| {
                Self::construct_core_domain_storage_proof_for_key_at(
                    system_domain_info.clone(),
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
                    system_domain_info.clone(),
                    core_domain_client,
                    block_id,
                    key,
                    system_domain_state_root,
                    core_domain_state_root_proof.clone(),
                )
            },
            |msg| Self::gossip_inbox_message_response(core_domain_client, msg, gossip_message_sink),
        )?;

        Ok(())
    }

    /// Sends an Outbox message from src_domain to dst_domain.
    fn gossip_outbox_message(
        client: &Arc<Client>,
        msg: CrossDomainMessage<NumberFor<Block>, Block::Hash, Block::Hash>,
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

    /// Sends an Inbox message response from src_domain to dst_domain
    /// Inbox message was earlier sent by dst_domain to src_domain and
    /// this message is the response of the Inbox message execution.
    fn gossip_inbox_message_response(
        client: &Arc<Client>,
        msg: CrossDomainMessage<NumberFor<Block>, Block::Hash, Block::Hash>,
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

    fn relayed_blocks_at_number_key(domain_id: DomainId, number: NumberFor<Block>) -> Vec<u8> {
        (
            b"message_relayer_processed_block_of_domain",
            domain_id,
            number,
        )
            .encode()
    }

    /// Takes number as tip and finds all the unprocessed blocks including the tip.
    fn fetch_unprocessed_blocks_until(
        client: &Arc<Client>,
        domain_id: DomainId,
        best_number: NumberFor<Block>,
        best_hash: Block::Hash,
    ) -> Result<UnProcessedBlocks<Block>, Error> {
        let mut blocks_to_process = vec![];
        let (mut number_to_check, mut hash_to_check) = (best_number, best_hash);
        while !Self::fetch_blocks_relayed_at(client, domain_id, number_to_check)
            .contains(&hash_to_check)
        {
            blocks_to_process.push((number_to_check, hash_to_check));
            if number_to_check == Zero::zero() {
                break;
            }

            hash_to_check = match client.header(hash_to_check).ok().flatten() {
                Some(header) => *header.parent_hash(),
                None => {
                    return Err(
                        sp_blockchain::Error::MissingHeader(hash_to_check.to_string()).into(),
                    );
                }
            };

            number_to_check = number_to_check
                .checked_sub(&One::one())
                .expect("block number is guaranteed to be >= 1 from the above check")
        }

        blocks_to_process.reverse();
        Ok(blocks_to_process)
    }

    fn fetch_blocks_relayed_at(
        client: &Arc<Client>,
        domain_id: DomainId,
        number: NumberFor<Block>,
    ) -> Vec<Block::Hash> {
        client
            .get_aux(&Self::relayed_blocks_at_number_key(domain_id, number))
            .ok()
            .flatten()
            .and_then(|enc_val| Vec::<Block::Hash>::decode(&mut enc_val.as_ref()).ok())
            .unwrap_or_default()
    }

    pub(crate) fn store_relayed_block(
        client: &Arc<Client>,
        domain_id: DomainId,
        block_number: NumberFor<Block>,
        block_hash: Block::Hash,
    ) -> Result<(), Error> {
        let mut processed_blocks = Self::fetch_blocks_relayed_at(client, domain_id, block_number);
        if processed_blocks.contains(&block_hash) {
            return Ok(());
        }

        processed_blocks.push(block_hash);
        client
            .insert_aux(
                &[(
                    Self::relayed_blocks_at_number_key(domain_id, block_number).as_ref(),
                    processed_blocks.encode().as_ref(),
                )],
                &[],
            )
            .map_err(|_| Error::StoreRelayedBlockNumber)
    }
}
