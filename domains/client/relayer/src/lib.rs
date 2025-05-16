#![warn(rust_2018_idioms)]
// TODO: Restore once https://github.com/rust-lang/rust/issues/122105 is resolved
// #![deny(unused_crate_dependencies)]

mod aux_schema;
pub mod worker;

use crate::aux_schema::{
    ChannelProcessedState, get_last_processed_nonces, set_channel_inbox_response_processed_state,
    set_channel_outbox_processed_state,
};
use async_channel::TrySendError;
use cross_domain_message_gossip::{
    ChannelDetail, Message as GossipMessage, MessageData as GossipMessageData, get_channel_state,
};
use parity_scale_codec::{Codec, Encode};
use rand::seq::SliceRandom;
use sc_client_api::{AuxStore, HeaderBackend, ProofProvider, StorageProof};
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::{ApiExt, ApiRef, ProvideRuntimeApi};
use sp_core::H256;
use sp_domains::{ChannelId, DomainsApi};
use sp_messenger::messages::{
    BlockMessagesQuery, ChainId, ChannelState, ChannelStateWithNonce, CrossDomainMessage,
    MessageNonceWithStorageKey, MessagesWithStorageKey, Nonce, Proof,
};
use sp_messenger::{MessengerApi, RelayerApi};
use sp_mmr_primitives::MmrApi;
use sp_runtime::ArithmeticError;
use sp_runtime::traits::{Block as BlockT, CheckedSub, Header as HeaderT, NumberFor, One};
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use std::cmp::max;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_runtime_primitives::BlockHashFor;

const CHANNEL_PROCESSED_STATE_CACHE_LIMIT: u32 = 5;
const MAXIMUM_CHANNELS_TO_PROCESS_IN_BLOCK: usize = 15;

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

type ProofOf<Block> = Proof<NumberFor<Block>, BlockHashFor<Block>, H256>;

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
    msgs: (ChainId, ChainId, ChannelId, Vec<MessageNonceWithStorageKey>),
    proof_constructor: ProofConstructor,
    submitter: Submitter,
) -> Result<(), Error>
where
    Submitter: Fn(CrossDomainMessage<CNumber, CHash, H256>) -> Result<(), Error>,
    ProofConstructor: Fn(&[u8], ChainId) -> Result<Proof<CNumber, CHash, H256>, Error>,
{
    let (src_chain_id, dst_chain_id, channel_id, msgs) = msgs;
    for msg in msgs {
        let proof = match proof_constructor(&msg.storage_key, dst_chain_id) {
            Ok(proof) => proof,
            Err(err) => {
                tracing::error!(
                    "Failed to construct storage proof for message: {:?} bound to chain: {:?} with error: {:?}",
                    (channel_id, msg.nonce),
                    dst_chain_id,
                    err
                );
                continue;
            }
        };
        let msg = CrossDomainMessage::from_relayer_msg_with_proof(
            src_chain_id,
            dst_chain_id,
            channel_id,
            msg,
            proof,
        );
        let (dst_domain, msg_id) = (msg.dst_chain_id, (msg.channel_id, msg.nonce));
        if let Err(err) = submitter(msg) {
            tracing::error!(
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

// Fetch the XDM at the given block and filter any already relayed XDM according to the best block
fn fetch_and_filter_messages<Client, Block, CClient, CBlock>(
    client: &Arc<Client>,
    fetch_message_at: Block::Hash,
    consensus_client: &Arc<CClient>,
    self_chain_id: ChainId,
) -> Result<Vec<(ChainId, ChannelId, MessagesWithStorageKey)>, Error>
where
    CBlock: BlockT,
    CClient: AuxStore + HeaderBackend<CBlock>,
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
{
    // return no messages for previous relayer version
    if !is_relayer_api_version_available::<_, Block, CBlock>(client, 3, fetch_message_at) {
        return Ok(vec![]);
    }

    fetch_messages::<_, _, Block, CBlock>(
        &**consensus_client,
        client,
        fetch_message_at,
        self_chain_id,
    )
}

// A helper struct used when constructing XDM proof
#[derive(Clone)]
enum XDMProofData<CHash, DHash> {
    Consensus(CHash),
    Domain {
        domain_proof: StorageProof,
        confirmed_domain_block_hash: DHash,
    },
}

impl<Client, Block> Relayer<Client, Block>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + AuxStore + ProofProvider<Block> + ProvideRuntimeApi<Block>,
{
    pub(crate) fn construct_and_submit_xdm<CClient, CBlock>(
        chain_id: ChainId,
        domain_client: &Arc<Client>,
        consensus_chain_client: &Arc<CClient>,
        confirmed_block_number: NumberFor<CBlock>,
        gossip_message_sink: &GossipMessageSink,
    ) -> Result<(), Error>
    where
        CBlock: BlockT,
        CClient:
            HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + ProofProvider<CBlock> + AuxStore,
        CClient::Api: DomainsApi<CBlock, Block::Header>
            + MessengerApi<CBlock, NumberFor<CBlock>, CBlock::Hash>
            + MmrApi<CBlock, H256, NumberFor<CBlock>>
            + RelayerApi<CBlock, NumberFor<CBlock>, NumberFor<CBlock>, CBlock::Hash>,
        Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
    {
        // Since the block MMR leaf is included in the next block, we procees the XDM of block `confirmed_block_number - 1`
        // and use the block `confirmed_block_number` to generate the MMR proof of block `confirmed_block_number - 1`
        let mmr_consensus_block = (
            confirmed_block_number,
            consensus_chain_client
                .hash(confirmed_block_number)?
                .ok_or(Error::MissingBlockHash)?,
        );
        let (to_process_consensus_number, to_process_consensus_hash) =
            match confirmed_block_number.checked_sub(&One::one()) {
                None => return Ok(()),
                Some(n) => {
                    let h = consensus_chain_client
                        .hash(n)?
                        .ok_or(Error::MissingBlockHash)?;
                    (n, h)
                }
            };

        tracing::debug!(
            "Checking messages to be submitted from chain: {chain_id:?} at block: ({to_process_consensus_number:?}, {to_process_consensus_hash:?})",
        );

        let consensus_chain_api = consensus_chain_client.runtime_api();
        let (block_messages, maybe_domain_data) = match chain_id {
            ChainId::Consensus => (
                fetch_and_filter_messages::<_, _, _, CBlock>(
                    consensus_chain_client,
                    to_process_consensus_hash,
                    consensus_chain_client,
                    chain_id,
                )?,
                None,
            ),
            ChainId::Domain(domain_id) => {
                let confirmed_domain_block_hash = {
                    match consensus_chain_api
                        .latest_confirmed_domain_block(to_process_consensus_hash, domain_id)?
                    {
                        Some((_, confirmed_domain_block_hash)) => confirmed_domain_block_hash,
                        // No domain block confirmed yet so just return
                        None => return Ok(()),
                    }
                };
                (
                    fetch_and_filter_messages::<_, _, _, CBlock>(
                        domain_client,
                        confirmed_domain_block_hash,
                        consensus_chain_client,
                        chain_id,
                    )?,
                    Some((domain_id, confirmed_domain_block_hash)),
                )
            }
        };

        // short circuit if the there are no messages to relay
        if block_messages.is_empty() {
            return Ok(());
        }

        let xdm_proof_data = match maybe_domain_data {
            None => XDMProofData::Consensus(to_process_consensus_hash),
            Some((domain_id, confirmed_domain_block_hash)) => {
                let storage_key = consensus_chain_api
                    .confirmed_domain_block_storage_key(to_process_consensus_hash, domain_id)?;

                let domain_proof = consensus_chain_client.read_proof(
                    to_process_consensus_hash,
                    &mut [storage_key.as_ref()].into_iter(),
                )?;

                XDMProofData::Domain {
                    domain_proof,
                    confirmed_domain_block_hash,
                }
            }
        };

        for (dst_chain_id, channel_id, messages) in block_messages {
            construct_cross_chain_message_and_submit::<NumberFor<CBlock>, CBlock::Hash, _, _>(
                (chain_id, dst_chain_id, channel_id, messages.outbox),
                |key, dst_chain_id| {
                    Self::construct_xdm_proof(
                        consensus_chain_client,
                        domain_client,
                        dst_chain_id,
                        mmr_consensus_block,
                        key,
                        xdm_proof_data.clone(),
                    )
                },
                |msg| gossip_outbox_message(domain_client, msg, gossip_message_sink),
            )?;

            construct_cross_chain_message_and_submit::<NumberFor<CBlock>, CBlock::Hash, _, _>(
                (chain_id, dst_chain_id, channel_id, messages.inbox_responses),
                |key, dst_chain_id| {
                    Self::construct_xdm_proof(
                        consensus_chain_client,
                        domain_client,
                        dst_chain_id,
                        mmr_consensus_block,
                        key,
                        xdm_proof_data.clone(),
                    )
                },
                |msg| gossip_inbox_message_response(domain_client, msg, gossip_message_sink),
            )?;
        }

        Ok(())
    }

    /// Constructs the proof for the given key using the domain backend.
    fn construct_xdm_proof<CClient, CBlock>(
        consensus_chain_client: &Arc<CClient>,
        domain_client: &Arc<Client>,
        dst_chain_id: ChainId,
        mmr_consensus_block: (NumberFor<CBlock>, CBlock::Hash),
        message_storage_key: &[u8],
        xdm_proof_data: XDMProofData<CBlock::Hash, Block::Hash>,
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
            mmr_consensus_block,
        )?;

        let proof = match xdm_proof_data {
            XDMProofData::Consensus(at_consensus_hash) => {
                let message_proof = consensus_chain_client
                    .read_proof(at_consensus_hash, &mut [message_storage_key].into_iter())
                    .map_err(|_| Error::ConstructStorageProof)?;

                Proof::Consensus {
                    consensus_chain_mmr_proof,
                    message_proof,
                }
            }
            XDMProofData::Domain {
                domain_proof,
                confirmed_domain_block_hash,
            } => {
                let message_proof = domain_client
                    .read_proof(
                        confirmed_domain_block_hash,
                        &mut [message_storage_key].into_iter(),
                    )
                    .map_err(|_| Error::ConstructStorageProof)?;

                Proof::Domain {
                    consensus_chain_mmr_proof,
                    domain_proof,
                    message_proof,
                }
            }
        };
        Ok(proof)
    }
}

fn filter_block_messages<Client, Block, CBlock>(
    api: &ApiRef<'_, Client::Api>,
    best_hash: Block::Hash,
    query: BlockMessagesQuery,
    messages: &mut MessagesWithStorageKey,
) -> Result<(), Error>
where
    Block: BlockT,
    CBlock: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
{
    let BlockMessagesQuery {
        chain_id,
        channel_id,
        outbox_from,
        inbox_responses_from,
    } = query;
    let maybe_outbox_nonce =
        api.first_outbox_message_nonce_to_relay(best_hash, chain_id, channel_id, outbox_from)?;
    let maybe_inbox_response_nonce = api.first_inbox_message_response_nonce_to_relay(
        best_hash,
        chain_id,
        channel_id,
        inbox_responses_from,
    )?;

    if let Some(nonce) = maybe_outbox_nonce {
        messages.outbox.retain(|msg| msg.nonce >= nonce)
    } else {
        messages.outbox.clear()
    }

    if let Some(nonce) = maybe_inbox_response_nonce {
        messages.inbox_responses.retain(|msg| msg.nonce >= nonce)
    } else {
        messages.inbox_responses.clear();
    }

    Ok(())
}

// Fetch the unprocessed XDMs at a given block
fn fetch_messages<Backend, Client, Block, CBlock>(
    backend: &Backend,
    client: &Arc<Client>,
    fetch_message_at: Block::Hash,
    self_chain_id: ChainId,
) -> Result<Vec<(ChainId, ChannelId, MessagesWithStorageKey)>, Error>
where
    Block: BlockT,
    CBlock: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
    Backend: AuxStore,
{
    let runtime_api = client.runtime_api();
    let fetch_message_at_number = client
        .number(fetch_message_at)?
        .ok_or(Error::MissingBlockHeader)?;
    let mut queries = runtime_api
        .channels_and_state(fetch_message_at)?
        .into_iter()
        .filter_map(|(dst_chain_id, channel_id, channel_state)| {
            get_channel_state_query(
                backend,
                client,
                fetch_message_at,
                self_chain_id,
                dst_chain_id,
                channel_id,
                channel_state,
            )
            .ok()
            .flatten()
        })
        .collect::<Vec<_>>();

    // pick random 15 queries
    let queries = if queries.len() <= MAXIMUM_CHANNELS_TO_PROCESS_IN_BLOCK {
        queries
    } else {
        let mut rng = rand::thread_rng();
        queries.shuffle(&mut rng);
        queries.truncate(MAXIMUM_CHANNELS_TO_PROCESS_IN_BLOCK);
        queries
    };

    let best_hash = client.info().best_hash;
    let runtime_api_best = client.runtime_api();
    let total_messages = queries
        .into_iter()
        .filter_map(|query| {
            let BlockMessagesQuery {
                chain_id: dst_chain_id,
                channel_id,
                ..
            } = query;
            let mut messages = runtime_api
                .block_messages_with_query(fetch_message_at, query.clone())
                .ok()?;

            // filter messages with best hash
            filter_block_messages::<Client, _, CBlock>(
                &runtime_api_best,
                best_hash,
                query,
                &mut messages,
            )
            .ok()?;

            if !messages.outbox.is_empty()
                && let Some(max_nonce) = messages.outbox.iter().map(|key| key.nonce).max()
            {
                set_channel_outbox_processed_state(
                    backend,
                    self_chain_id,
                    dst_chain_id,
                    ChannelProcessedState::<Block> {
                        block_number: fetch_message_at_number,
                        block_hash: fetch_message_at,
                        channel_id,
                        nonce: Some(max_nonce),
                    },
                )
                .ok()?;
            }

            if !messages.inbox_responses.is_empty()
                && let Some(max_nonce) = messages.inbox_responses.iter().map(|key| key.nonce).max()
            {
                set_channel_inbox_response_processed_state(
                    backend,
                    self_chain_id,
                    dst_chain_id,
                    ChannelProcessedState::<Block> {
                        block_number: fetch_message_at_number,
                        block_hash: fetch_message_at,
                        channel_id,
                        nonce: Some(max_nonce),
                    },
                )
                .ok()?;
            }

            Some((dst_chain_id, channel_id, messages))
        })
        .collect();

    Ok(total_messages)
}

fn get_channel_state_query<Backend, Client, Block>(
    backend: &Backend,
    client: &Arc<Client>,
    fetch_message_at: Block::Hash,
    self_chain_id: ChainId,
    dst_chain_id: ChainId,
    channel_id: ChannelId,
    local_channel_state: ChannelStateWithNonce,
) -> Result<Option<BlockMessagesQuery>, Error>
where
    Backend: AuxStore,
    Block: BlockT,
    Client: HeaderBackend<Block>,
{
    let maybe_dst_channel_state =
        get_channel_state(backend, dst_chain_id, self_chain_id, channel_id)
            .ok()
            .flatten();

    let last_processed_nonces = get_last_processed_nonces(
        backend,
        client,
        fetch_message_at,
        self_chain_id,
        dst_chain_id,
        channel_id,
    )?;

    let query = match (
        maybe_dst_channel_state,
        last_processed_nonces.outbox_nonce,
        last_processed_nonces.inbox_response_nonce,
    ) {
        // don't have any info on channel, so assume from the beginning
        (None, None, None) => Some(BlockMessagesQuery {
            chain_id: dst_chain_id,
            channel_id,
            outbox_from: Nonce::zero(),
            inbox_responses_from: Nonce::zero(),
        }),
        // don't have channel processed state, so use the dst_channel state for query
        (Some(dst_channel_state), None, None) => {
            should_relay_messages_to_channel(dst_chain_id, &dst_channel_state, local_channel_state)
                .then_some(BlockMessagesQuery {
                    chain_id: dst_chain_id,
                    channel_id,
                    outbox_from: dst_channel_state.next_inbox_nonce,
                    inbox_responses_from: dst_channel_state
                        .latest_response_received_message_nonce
                        // pick the next inbox message response nonce or default to zero
                        .map(|nonce| nonce.saturating_add(One::one()))
                        .unwrap_or(Nonce::zero()),
                })
        }
        // don't have dst channel state, so use the last processed channel state
        (None, last_outbox_nonce, last_inbox_message_response_nonce) => Some(BlockMessagesQuery {
            chain_id: dst_chain_id,
            channel_id,
            outbox_from: last_outbox_nonce
                .map(|nonce| nonce.saturating_add(One::one()))
                .unwrap_or(Nonce::zero()),
            inbox_responses_from: last_inbox_message_response_nonce
                .map(|nonce| nonce.saturating_add(One::one()))
                .unwrap_or(Nonce::zero()),
        }),
        (Some(dst_channel_state), last_outbox_nonce, last_inbox_message_response_nonce) => {
            should_relay_messages_to_channel(dst_chain_id, &dst_channel_state, local_channel_state)
                .then(|| {
                    let next_outbox_nonce = max(
                        dst_channel_state.next_inbox_nonce,
                        last_outbox_nonce
                            .map(|nonce| nonce.saturating_add(One::one()))
                            .unwrap_or(Nonce::zero()),
                    );

                    let next_inbox_response_nonce = max(
                        dst_channel_state
                            .latest_response_received_message_nonce
                            .map(|nonce| nonce.saturating_add(One::one()))
                            .unwrap_or(Nonce::zero()),
                        last_inbox_message_response_nonce
                            .map(|nonce| nonce.saturating_add(One::one()))
                            .unwrap_or(Nonce::zero()),
                    );

                    BlockMessagesQuery {
                        chain_id: dst_chain_id,
                        channel_id,
                        outbox_from: next_outbox_nonce,
                        inbox_responses_from: next_inbox_response_nonce,
                    }
                })
        }
    };

    tracing::debug!(
        "From Chain[{:?}] to Chain[{:?}] and Channel[{:?}] Query: {:?}",
        self_chain_id,
        dst_chain_id,
        channel_id,
        query
    );

    Ok(query)
}

fn should_relay_messages_to_channel(
    dst_chain_id: ChainId,
    dst_channel_state: &ChannelDetail,
    local_channel_state: ChannelStateWithNonce,
) -> bool {
    let should_process = if dst_channel_state.state == ChannelState::Closed
        && let ChannelStateWithNonce::Closed {
            next_outbox_nonce,
            next_inbox_nonce,
        } = local_channel_state
    {
        // if the next outbox nonce of local channel is same as
        // next inbox nonce of dst_channel, then there are no further
        // outbox messages to be sent from the local channel
        let no_outbox_messages = next_outbox_nonce == dst_channel_state.next_inbox_nonce;

        // if next inbox nonce of local channel is +1 of
        // last received response nonce on dst_chain, then there are
        // no further messages responses to be sent from the local channel
        let no_inbox_responses_messages = dst_channel_state
            .latest_response_received_message_nonce
            .map(|nonce| nonce == next_inbox_nonce.saturating_sub(Nonce::one()))
            .unwrap_or(false);

        !(no_outbox_messages && no_inbox_responses_messages)
    } else {
        true
    };

    if !should_process {
        tracing::debug!(
            "Chain[{:?}] for Channel[{:?}] is closed and no messages to process",
            dst_chain_id,
            dst_channel_state.channel_id
        );
    }

    should_process
}

fn is_relayer_api_version_available<Client, Block, CBlock>(
    client: &Arc<Client>,
    version: u32,
    block_hash: Block::Hash,
) -> bool
where
    Block: BlockT,
    CBlock: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
{
    let relayer_api_version = client
        .runtime_api()
        .api_version::<dyn RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>>(
            block_hash,
        )
        .ok()
        .flatten()
        // It is safe to return a default version of 1, since there will always be version 1.
        .unwrap_or(1);

    relayer_api_version >= version
}
