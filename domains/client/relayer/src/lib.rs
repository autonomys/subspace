#![feature(let_chains)]
#![warn(rust_2018_idioms)]
// TODO: Restore once https://github.com/rust-lang/rust/issues/122105 is resolved
// #![deny(unused_crate_dependencies)]

pub mod worker;

use async_channel::TrySendError;
use cross_domain_message_gossip::{
    can_allow_xdm_submission, get_channel_state, get_xdm_processed_block_number,
    set_xdm_message_processed_at, BlockId, Message as GossipMessage,
    MessageData as GossipMessageData, RELAYER_PREFIX,
};
use parity_scale_codec::{Codec, Encode};
use sc_client_api::{AuxStore, HeaderBackend, ProofProvider, StorageProof};
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::{ApiRef, ProvideRuntimeApi};
use sp_core::{H256, U256};
use sp_domains::DomainsApi;
use sp_messenger::messages::{
    BlockMessageWithStorageKey, BlockMessagesWithStorageKey, ChainId, CrossDomainMessage, Proof,
};
use sp_messenger::{MessengerApi, RelayerApi, XdmId, MAX_FUTURE_ALLOWED_NONCES};
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

fn check_and_update_recent_xdm_submission<Backend, Client, Block>(
    backend: &Backend,
    client: &Arc<Client>,
    xdm_id: XdmId,
    msg: &BlockMessageWithStorageKey,
) -> bool
where
    Backend: AuxStore,
    Block: BlockT,
    Client: HeaderBackend<Block>,
{
    let prefix = (RELAYER_PREFIX, msg.dst_chain_id, msg.src_chain_id).encode();
    let current_block_id: BlockId<Block> = client.info().into();
    if let Ok(maybe_submitted_block_id) =
        get_xdm_processed_block_number::<_, Block>(backend, &prefix, xdm_id)
    {
        if !can_allow_xdm_submission(
            client,
            xdm_id,
            maybe_submitted_block_id,
            current_block_id.clone(),
            None,
        ) {
            log::debug!(
                target: LOG_TARGET,
                "Skipping already submitted message relay from {:?}: {:?}",
                msg.src_chain_id,
                xdm_id
            );
            return false;
        }
    }

    if let Err(err) = set_xdm_message_processed_at(backend, &prefix, xdm_id, current_block_id) {
        log::error!(
            target: LOG_TARGET,
            "Failed to store submitted message from {:?} to {:?}: {:?}",
            msg.src_chain_id,
            xdm_id,
            err
        );
    }

    true
}

fn should_relay_outbox_message<Backend, Client, Block, CBlock>(
    backend: &Backend,
    client: &Arc<Client>,
    api: &ApiRef<'_, Client::Api>,
    best_hash: Block::Hash,
    msg: &BlockMessageWithStorageKey,
) -> bool
where
    Backend: AuxStore,
    Block: BlockT,
    CBlock: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
{
    let id = msg.id();
    match api.should_relay_outbox_message(best_hash, msg.dst_chain_id, id) {
        Ok(true) => (),
        Ok(false) => return false,
        Err(err) => {
            tracing::error!(
                target: LOG_TARGET,
                ?err,
                "Failed to fetch validity of outbox message {id:?} for domain {0:?}",
                msg.dst_chain_id
            );
            return false;
        }
    };

    if let Some(dst_channel_state) =
        get_channel_state(backend, msg.dst_chain_id, msg.src_chain_id, msg.channel_id)
            .ok()
            .flatten()
    {
        // if this message should relay,
        // check if the dst_chain inbox nonce is more than message nonce,
        // if so, skip relaying since message is already executed on dst_chain
        let max_messages_nonce_allowed = dst_channel_state
            .next_inbox_nonce
            .saturating_add(MAX_FUTURE_ALLOWED_NONCES.into());
        let relay_message = msg.nonce >= dst_channel_state.next_inbox_nonce
            && msg.nonce <= max_messages_nonce_allowed;
        if !relay_message {
            log::debug!(
                target: LOG_TARGET,
                "Skipping Outbox message relay from {:?} to {:?} of XDM[{:?}, {:?}]. Max Nonce allowed: {:?}",
                msg.src_chain_id,
                msg.dst_chain_id,
                msg.channel_id,
                msg.nonce,
                max_messages_nonce_allowed
            );
            return false;
        }
    }

    let xdm_id = XdmId::RelayMessage((msg.dst_chain_id, msg.channel_id, msg.nonce));
    check_and_update_recent_xdm_submission(backend, client, xdm_id, msg)
}

fn should_relay_inbox_responses_message<Backend, Client, Block, CBlock>(
    backend: &Backend,
    client: &Arc<Client>,
    api: &ApiRef<'_, Client::Api>,
    best_hash: Block::Hash,
    msg: &BlockMessageWithStorageKey,
) -> bool
where
    Backend: AuxStore,
    Block: BlockT,
    CBlock: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
{
    let id = msg.id();
    match api.should_relay_inbox_message_response(best_hash, msg.dst_chain_id, id) {
        Ok(true) => (),
        Ok(false) => return false,
        Err(err) => {
            tracing::error!(
                target: LOG_TARGET,
                ?err,
                "Failed to fetch validity of inbox message response {id:?} for domain {0:?}",
                msg.dst_chain_id
            );
            return false;
        }
    };

    if let Some(dst_channel_state) =
        get_channel_state(backend, msg.dst_chain_id, msg.src_chain_id, msg.channel_id)
            .ok()
            .flatten()
    {
        let next_nonce = if let Some(dst_chain_outbox_response_nonce) =
            dst_channel_state.latest_response_received_message_nonce
        {
            // next nonce for outbox response will be +1 of current nonce for which
            // dst_chain has received response.
            dst_chain_outbox_response_nonce.saturating_add(U256::one())
        } else {
            // if dst_chain has not received the first outbox response,
            // then next nonce will be just 0
            U256::zero()
        };
        // relay inbox response if the dst_chain did not execute is already
        let max_msg_nonce_allowed = next_nonce.saturating_add(MAX_FUTURE_ALLOWED_NONCES.into());
        let relay_message = msg.nonce >= next_nonce && msg.nonce <= max_msg_nonce_allowed;
        if !relay_message {
            log::debug!(
                target: LOG_TARGET,
                "Skipping Inbox response message relay from {:?} to {:?} of XDM[{:?}, {:?}]. Max nonce allowed: {:?}",
                msg.src_chain_id,
                msg.dst_chain_id,
                msg.channel_id,
                msg.nonce,
                max_msg_nonce_allowed
            );
            return false;
        }
    }

    let xdm_id = XdmId::RelayResponseMessage((msg.dst_chain_id, msg.channel_id, msg.nonce));
    check_and_update_recent_xdm_submission(backend, client, xdm_id, msg)
}

// Fetch the XDM at the a given block and filter any already relayed XDM according to the best block
fn fetch_and_filter_messages<Client, Block, CClient, CBlock>(
    client: &Arc<Client>,
    fetch_message_at: Block::Hash,
    consensus_client: &Arc<CClient>,
) -> Result<BlockMessagesWithStorageKey, Error>
where
    CBlock: BlockT,
    CClient: AuxStore + HeaderBackend<CBlock>,
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
{
    let mut msgs = client
        .runtime_api()
        .block_messages(fetch_message_at)
        .map_err(|_| Error::FetchAssignedMessages)?;

    let api = client.runtime_api();
    let best_hash = client.info().best_hash;
    msgs.outbox.retain(|msg| {
        should_relay_outbox_message::<_, _, _, CBlock>(
            &**consensus_client,
            client,
            &api,
            best_hash,
            msg,
        )
    });

    msgs.inbox_responses.retain(|msg| {
        should_relay_inbox_responses_message::<_, _, _, CBlock>(
            &**consensus_client,
            client,
            &api,
            best_hash,
            msg,
        )
    });

    Ok(msgs)
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
            target: LOG_TARGET,
            "Checking messages to be submitted from chain: {chain_id:?} at block: ({to_process_consensus_number:?}, {to_process_consensus_hash:?})",
        );

        let consensus_chain_api = consensus_chain_client.runtime_api();
        let (block_messages, maybe_domain_data) = match chain_id {
            ChainId::Consensus => (
                fetch_and_filter_messages::<_, _, _, CBlock>(
                    consensus_chain_client,
                    to_process_consensus_hash,
                    consensus_chain_client,
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

        construct_cross_chain_message_and_submit::<NumberFor<CBlock>, CBlock::Hash, _, _>(
            block_messages.outbox,
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
            block_messages.inbox_responses,
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
