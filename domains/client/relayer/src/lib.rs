#![feature(let_chains)]
#![warn(rust_2018_idioms)]
// TODO: Restore once https://github.com/rust-lang/rust/issues/122105 is resolved
// #![deny(unused_crate_dependencies)]

pub mod worker;

use async_channel::TrySendError;
use cross_domain_message_gossip::{
    ChannelStorage, Message as GossipMessage, MessageData as GossipMessageData,
};
use parity_scale_codec::{Codec, Encode};
use sc_client_api::{AuxStore, HeaderBackend, ProofProvider, StorageProof};
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::ProvideRuntimeApi;
use sp_core::H256;
use sp_domains::{DomainId, DomainsApi};
use sp_messenger::messages::{
    BlockMessageWithStorageKey, BlockMessagesWithStorageKey, ChainId, CrossDomainMessage, Proof,
};
use sp_messenger::{MessengerApi, RelayerApi};
use sp_mmr_primitives::MmrApi;
use sp_runtime::traits::{Block as BlockT, CheckedSub, Header as HeaderT, NumberFor, One};
use sp_runtime::ArithmeticError;
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use std::marker::PhantomData;
use std::sync::Arc;
use tracing::log;

/// The logging target.
const LOG_TARGET: &str = "message::relayer";

/// Relayer relays messages between domains using consensus chain as trusted third party.
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
    /// Failed to submit a cross domain message
    UnableToSubmitCrossDomainMessage(TrySendError<GossipMessage>),
    /// Invalid ChainId
    InvalidChainId,
    /// Failed to generate MMR proof
    MmrProof(sp_mmr_primitives::Error),
    /// MMR Leaf missing
    MmrLeafMissing,
    /// Missing block header
    MissingBlockHeader,
    /// Missing block hash
    MissingBlockHash,
}

impl From<sp_blockchain::Error> for Error {
    #[inline]
    fn from(err: sp_blockchain::Error) -> Self {
        Error::BlockchainError(Box::new(err))
    }
}

impl From<ArithmeticError> for Error {
    #[inline]
    fn from(err: ArithmeticError) -> Self {
        Error::ArithmeticError(err)
    }
}

impl From<sp_api::ApiError> for Error {
    #[inline]
    fn from(err: sp_api::ApiError) -> Self {
        Error::ApiError(err)
    }
}

type ProofOf<Block> = Proof<NumberFor<Block>, <Block as BlockT>::Hash, H256>;

fn construct_consensus_mmr_proof<Client, Block>(
    consensus_chain_client: &Arc<Client>,
    dst_chain_id: ChainId,
    (block_number, block_hash): (NumberFor<Block>, Block::Hash),
) -> Result<ConsensusChainMmrLeafProof<NumberFor<Block>, Block::Hash, H256>, Error>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: MmrApi<Block, H256, NumberFor<Block>>,
{
    let api = consensus_chain_client.runtime_api();
    let best_hash = consensus_chain_client.info().best_hash;
    let best_number = consensus_chain_client.info().best_number;

    let (prove_at_number, prove_at_hash) = match dst_chain_id {
        // The consensus chain will verify the MMR proof statelessly with the MMR root
        // stored in the runtime, we need to generate the proof with the best block
        // with the latest MMR root in the runtime so the proof will be valid as long
        // as the MMR root is available when verifying the proof.
        ChainId::Consensus => (best_number, best_hash),
        // The domain chain will verify the MMR proof with the offchain MMR leaf data
        // in the consensus client, we need to generate the proof with the proving block
        // (i.e. finalized block) to avoid potential consensus fork and ensure the verification
        // result is deterministic.
        ChainId::Domain(_) => (block_number, block_hash),
    };

    let (mut leaves, proof) = api
        .generate_proof(best_hash, vec![block_number], Some(prove_at_number))
        .map_err(Error::ApiError)?
        .map_err(Error::MmrProof)?;
    debug_assert!(leaves.len() == 1, "should always be of length 1");
    let leaf = leaves.pop().ok_or(Error::MmrLeafMissing)?;

    Ok(ConsensusChainMmrLeafProof {
        consensus_block_number: prove_at_number,
        consensus_block_hash: prove_at_hash,
        opaque_mmr_leaf: leaf,
        proof,
    })
}

fn construct_cross_chain_message_and_submit<CNumber, CHash, Submitter, ProofConstructor>(
    msgs: Vec<BlockMessageWithStorageKey>,
    proof_constructor: ProofConstructor,
    submitter: Submitter,
) -> Result<(), Error>
where
    Submitter: Fn(CrossDomainMessage<CNumber, CHash, H256>) -> Result<(), Error>,
    ProofConstructor: Fn(&[u8], ChainId) -> Result<Proof<CNumber, CHash, H256>, Error>,
{
    for msg in msgs {
        let proof = match proof_constructor(&msg.storage_key, msg.dst_chain_id) {
            Ok(proof) => proof,
            Err(err) => {
                tracing::error!(
                    target: LOG_TARGET,
                    "Failed to construct storage proof for message: {:?} bound to chain: {:?} with error: {:?}",
                    (msg.channel_id, msg.nonce),
                    msg.dst_chain_id,
                    err
                );
                continue;
            }
        };
        let msg = CrossDomainMessage::from_relayer_msg_with_proof(msg, proof);
        let (dst_domain, msg_id) = (msg.dst_chain_id, (msg.channel_id, msg.nonce));
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

/// Sends an Outbox message from src_domain to dst_domain.
fn gossip_outbox_message<Block, Client, CNumber, CHash>(
    client: &Arc<Client>,
    msg: CrossDomainMessage<CNumber, CHash, H256>,
    sink: &GossipMessageSink,
) -> Result<(), Error>
where
    Block: BlockT,
    CNumber: Codec,
    CHash: Codec,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, CNumber, CHash>,
{
    let best_hash = client.info().best_hash;
    let dst_chain_id = msg.dst_chain_id;
    let ext = client
        .runtime_api()
        .outbox_message_unsigned(best_hash, msg)?
        .ok_or(Error::FailedToConstructExtrinsic)?;

    sink.unbounded_send(GossipMessage {
        chain_id: dst_chain_id,
        data: GossipMessageData::Xdm(ext.encode()),
    })
    .map_err(Error::UnableToSubmitCrossDomainMessage)
}

/// Sends an Inbox message response from src_domain to dst_domain
/// Inbox message was earlier sent by dst_domain to src_domain and
/// this message is the response of the Inbox message execution.
fn gossip_inbox_message_response<Block, Client, CNumber, CHash>(
    client: &Arc<Client>,
    msg: CrossDomainMessage<CNumber, CHash, H256>,
    sink: &GossipMessageSink,
) -> Result<(), Error>
where
    Block: BlockT,
    CNumber: Codec,
    CHash: Codec,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, CNumber, CHash>,
{
    let best_hash = client.info().best_hash;
    let dst_chain_id = msg.dst_chain_id;
    let ext = client
        .runtime_api()
        .inbox_response_message_unsigned(best_hash, msg)?
        .ok_or(Error::FailedToConstructExtrinsic)?;

    sink.unbounded_send(GossipMessage {
        chain_id: dst_chain_id,
        data: GossipMessageData::Xdm(ext.encode()),
    })
    .map_err(Error::UnableToSubmitCrossDomainMessage)
}

impl<Client, Block> Relayer<Client, Block>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + AuxStore + ProofProvider<Block> + ProvideRuntimeApi<Block>,
{
    /// Constructs the proof for the given key using the consensus chain backend.
    fn construct_consensus_chain_xdm_proof_for_key_at(
        consensus_chain_client: &Arc<Client>,
        finalized_block: (NumberFor<Block>, Block::Hash),
        block_hash_to_process: Block::Hash,
        key: &[u8],
        dst_chain_id: ChainId,
    ) -> Result<ProofOf<Block>, Error>
    where
        Client::Api: MmrApi<Block, H256, NumberFor<Block>>,
    {
        let proof = consensus_chain_client
            .read_proof(block_hash_to_process, &mut [key].into_iter())
            .map_err(|_| Error::ConstructStorageProof)?;

        let consensus_chain_mmr_proof =
            construct_consensus_mmr_proof(consensus_chain_client, dst_chain_id, finalized_block)?;

        Ok(Proof::Consensus {
            consensus_chain_mmr_proof,
            message_proof: proof,
        })
    }

    fn filter_messages<CClient, CNumber, CHash>(
        client: &Arc<Client>,
        consensus_client: &Arc<CClient>,
        mut msgs: BlockMessagesWithStorageKey,
    ) -> Result<BlockMessagesWithStorageKey, Error>
    where
        CHash: Codec,
        CNumber: Codec,
        CClient: AuxStore,
        Client::Api: RelayerApi<Block, NumberFor<Block>, CNumber, CHash>,
    {
        let api = client.runtime_api();
        let best_hash = client.info().best_hash;
        msgs.outbox.retain(|msg| {
            let id = (msg.channel_id, msg.nonce);
            let should_relay =
                match api.should_relay_outbox_message(best_hash, msg.dst_chain_id, id) {
                    Ok(valid) => valid,
                    Err(err) => {
                        tracing::error!(
                            target: LOG_TARGET,
                            ?err,
                            "Failed to fetch validity of outbox message {id:?} for domain {0:?}",
                            msg.dst_chain_id
                        );
                        false
                    }
                };

            let channel_storage = ChannelStorage::new(msg.dst_chain_id);
            if should_relay
                && let Some(dst_channel_state) = channel_storage
                    .get_channel_state_for(&**consensus_client, msg.src_chain_id, msg.channel_id)
                    .ok()
                    .flatten()
            {
                // if this message should relay,
                // check if the dst_chain inbox nonce is more than message nonce,
                // if so, skip relaying since message is already executed on dst_chain
                let relay_message = msg.nonce >= dst_channel_state.next_inbox_nonce;
                if !relay_message {
                    log::debug!(
                        "Skipping message relay from {:?} to {:?}",
                        msg.src_chain_id,
                        msg.dst_chain_id,
                    );
                }
                relay_message
            } else {
                should_relay
            }
        });

        msgs.inbox_responses.retain(|msg| {
            let id = (msg.channel_id, msg.nonce);
            let should_relay = match api.should_relay_inbox_message_response(best_hash, msg.dst_chain_id, id) {
                Ok(valid) => valid,
                Err(err) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?err,
                        "Failed to fetch validity of inbox message response {id:?} for domain {0:?}",
                        msg.dst_chain_id
                    );
                    false
                }
            };

            let channel_storage = ChannelStorage::new(msg.dst_chain_id);
            if should_relay && let Some(dst_channel_state) = channel_storage.get_channel_state_for(
                &**consensus_client,
                msg.src_chain_id,
                msg.channel_id,
            )
                .ok()
                .flatten() && let Some(dst_chain_outbox_response_nonce) = dst_channel_state.latest_response_received_message_nonce{
                // relay inbox response if the dst_chain did not execute is already
                let relay_message = msg.nonce > dst_chain_outbox_response_nonce;
                if !relay_message{
                    log::debug!(
                        "Skipping message relay from {:?} to {:?}",
                        msg.src_chain_id,
                        msg.dst_chain_id,
                    );
                }
                relay_message
            } else { should_relay }
        });

        Ok(msgs)
    }

    pub(crate) fn submit_messages_from_consensus_chain(
        consensus_chain_client: &Arc<Client>,
        finalized_block: (NumberFor<Block>, Block::Hash),
        gossip_message_sink: &GossipMessageSink,
    ) -> Result<(), Error>
    where
        Client::Api: MmrApi<Block, H256, NumberFor<Block>>
            + RelayerApi<Block, NumberFor<Block>, NumberFor<Block>, Block::Hash>,
    {
        // since the `finalized_block_number - 1` block MMR leaf is included in `finalized_block_number`,
        // we process that block instead while using the finalized block number to generate the MMR
        // proof `finalized_block_number -1`
        let block_number_to_process = match finalized_block.0.checked_sub(&One::one()) {
            None => return Ok(()),
            Some(number) => number,
        };
        let block_hash_to_process = consensus_chain_client
            .hash(block_number_to_process)?
            .ok_or(Error::MissingBlockHeader)?;

        let api = consensus_chain_client.runtime_api();
        let block_messages: BlockMessagesWithStorageKey = api
            .block_messages(block_hash_to_process)
            .map_err(|_| Error::FetchAssignedMessages)?;

        let filtered_messages = Self::filter_messages(
            consensus_chain_client,
            consensus_chain_client,
            block_messages,
        )?;

        // short circuit if the there are no messages to relay
        if filtered_messages.outbox.is_empty() && filtered_messages.inbox_responses.is_empty() {
            return Ok(());
        }

        construct_cross_chain_message_and_submit::<NumberFor<Block>, Block::Hash, _, _>(
            filtered_messages.outbox,
            |key, dst_chain_id| {
                Self::construct_consensus_chain_xdm_proof_for_key_at(
                    consensus_chain_client,
                    finalized_block,
                    block_hash_to_process,
                    key,
                    dst_chain_id,
                )
            },
            |msg| gossip_outbox_message(consensus_chain_client, msg, gossip_message_sink),
        )?;

        construct_cross_chain_message_and_submit::<NumberFor<Block>, Block::Hash, _, _>(
            filtered_messages.inbox_responses,
            |key, dst_chain_id| {
                Self::construct_consensus_chain_xdm_proof_for_key_at(
                    consensus_chain_client,
                    finalized_block,
                    block_hash_to_process,
                    key,
                    dst_chain_id,
                )
            },
            |msg| gossip_inbox_message_response(consensus_chain_client, msg, gossip_message_sink),
        )?;

        Ok(())
    }

    pub(crate) fn submit_messages_from_domain<CClient, CBlock>(
        domain_id: DomainId,
        domain_client: &Arc<Client>,
        consensus_chain_client: &Arc<CClient>,
        finalized_consensus_block: (NumberFor<CBlock>, CBlock::Hash),
        confirmed_domain_block_hash: Block::Hash,
        gossip_message_sink: &GossipMessageSink,
    ) -> Result<(), Error>
    where
        CBlock: BlockT,
        CClient:
            HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + ProofProvider<CBlock> + AuxStore,
        CClient::Api: DomainsApi<CBlock, Block::Header>
            + MessengerApi<CBlock, NumberFor<CBlock>, CBlock::Hash>
            + MmrApi<CBlock, H256, NumberFor<CBlock>>,
        Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
    {
        // fetch messages to be relayed
        let domain_api = domain_client.runtime_api();
        let block_messages: BlockMessagesWithStorageKey = domain_api
            .block_messages(confirmed_domain_block_hash)
            .map_err(|_| Error::FetchAssignedMessages)?;

        // filter out already relayed messages
        let filtered_messages =
            Self::filter_messages(domain_client, consensus_chain_client, block_messages)?;

        // short circuit if the there are no messages to relay
        if filtered_messages.outbox.is_empty() && filtered_messages.inbox_responses.is_empty() {
            return Ok(());
        }

        // Generate domain proof that points to the confirmed domain block.
        // Confirmed domain block is taken from the parent of the finalized consensus block
        let consensus_chain_number_to_process =
            match finalized_consensus_block.0.checked_sub(&One::one()) {
                None => return Ok(()),
                Some(number) => number,
            };

        let consensus_block_hash = consensus_chain_client
            .hash(consensus_chain_number_to_process)?
            .ok_or(Error::MissingBlockHash)?;

        let consensus_chain_api = consensus_chain_client.runtime_api();
        let storage_key = consensus_chain_api
            .confirmed_domain_block_storage_key(consensus_block_hash, domain_id)?;

        let domain_proof = consensus_chain_client.read_proof(
            consensus_block_hash,
            &mut [storage_key.as_ref()].into_iter(),
        )?;

        construct_cross_chain_message_and_submit::<NumberFor<CBlock>, CBlock::Hash, _, _>(
            filtered_messages.outbox,
            |key, dst_chain_id| {
                Self::construct_domain_chain_xdm_proof_for_key_at(
                    finalized_consensus_block,
                    consensus_chain_client,
                    domain_client,
                    confirmed_domain_block_hash,
                    key,
                    domain_proof.clone(),
                    dst_chain_id,
                )
            },
            |msg| gossip_outbox_message(domain_client, msg, gossip_message_sink),
        )?;

        construct_cross_chain_message_and_submit::<NumberFor<CBlock>, CBlock::Hash, _, _>(
            filtered_messages.inbox_responses,
            |key, dst_chain_id| {
                Self::construct_domain_chain_xdm_proof_for_key_at(
                    finalized_consensus_block,
                    consensus_chain_client,
                    domain_client,
                    confirmed_domain_block_hash,
                    key,
                    domain_proof.clone(),
                    dst_chain_id,
                )
            },
            |msg| gossip_inbox_message_response(domain_client, msg, gossip_message_sink),
        )?;

        Ok(())
    }

    /// Constructs the proof for the given key using the domain backend.
    fn construct_domain_chain_xdm_proof_for_key_at<CClient, CBlock>(
        consensus_chain_finalized_block: (NumberFor<CBlock>, CBlock::Hash),
        consensus_chain_client: &Arc<CClient>,
        domain_client: &Arc<Client>,
        block_hash: Block::Hash,
        key: &[u8],
        domain_proof: StorageProof,
        dst_chain_id: ChainId,
    ) -> Result<ProofOf<CBlock>, Error>
    where
        CBlock: BlockT,
        CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + ProofProvider<CBlock>,
        CClient::Api: DomainsApi<CBlock, Block::Header>
            + MessengerApi<CBlock, NumberFor<CBlock>, CBlock::Hash>
            + MmrApi<CBlock, H256, NumberFor<CBlock>>,
    {
        let consensus_chain_mmr_proof = construct_consensus_mmr_proof(
            consensus_chain_client,
            dst_chain_id,
            consensus_chain_finalized_block,
        )?;

        let proof = domain_client
            .read_proof(block_hash, &mut [key].into_iter())
            .map_err(|_| Error::ConstructStorageProof)?;

        Ok(Proof::Domain {
            consensus_chain_mmr_proof,
            domain_proof,
            message_proof: proof,
        })
    }
}
