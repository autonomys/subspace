#![warn(rust_2018_idioms)]

pub mod worker;

use async_channel::TrySendError;
use cross_domain_message_gossip::Message as GossipMessage;
use parity_scale_codec::{Decode, Encode, FullCodec};
use sc_client_api::{AuxStore, HeaderBackend, ProofProvider, StorageProof};
use sc_utils::mpsc::TracingUnboundedSender;
use scale_info::TypeInfo;
use sp_api::ProvideRuntimeApi;
use sp_domains::{ChainId, DomainsApi};
use sp_messenger::messages::{
    BlockMessageWithStorageKey, BlockMessagesWithStorageKey, ConsensusChainMmrLeafProof,
    CrossDomainMessage, Proof,
};
use sp_messenger::{MessengerApi, RelayerApi};
use sp_mmr_primitives::{EncodableOpaqueLeaf, Proof as MmrProof};
use sp_runtime::traits::{Block as BlockT, CheckedSub, Header as HeaderT, NumberFor, One, Zero};
use sp_runtime::ArithmeticError;
use std::marker::PhantomData;
use std::sync::Arc;

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
    /// Emits when the core domain block is not yet confirmed on the system domain.
    DomainNonConfirmedOnConsensusChain,
    /// Failed to submit a cross domain message
    UnableToSubmitCrossDomainMessage(TrySendError<GossipMessage>),
    /// Invalid ChainId
    InvalidChainId,
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

type ProofOf<Block> = Proof<<Block as BlockT>::Hash, <Block as BlockT>::Hash>;
type UnProcessedBlocks<Block> = Vec<(NumberFor<Block>, <Block as BlockT>::Hash)>;

impl<Client, Block> Relayer<Client, Block>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + AuxStore + ProofProvider<Block> + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>>,
{
    pub(crate) fn chain_id(client: &Arc<Client>) -> Result<ChainId, Error> {
        client
            .runtime_api()
            .chain_id(client.info().best_hash)
            .map_err(|_| Error::UnableToFetchDomainId)
    }

    pub(crate) fn relay_confirmation_depth(
        client: &Arc<Client>,
    ) -> Result<NumberFor<Block>, Error> {
        let best_block_id = client.info().best_hash;
        let api = client.runtime_api();
        api.relay_confirmation_depth(best_block_id)
            .map_err(|_| Error::UnableToFetchRelayConfirmationDepth)
    }

    /// Constructs the proof for the given key using the consensus chain backend.
    fn construct_consensus_chain_storage_proof_for_key_at(
        consensus_chain_client: &Arc<Client>,
        block_hash: Block::Hash,
        key: &[u8],
    ) -> Result<ProofOf<Block>, Error> {
        consensus_chain_client
            .header(block_hash)?
            .map(|header| (header.hash(), *header.state_root()))
            .and_then(|(block_hash, _state_root)| {
                let proof = consensus_chain_client
                    .read_proof(block_hash, &mut [key].into_iter())
                    .ok()?;
                // TODO: derive the correct proof here
                Some(Proof {
                    consensus_chain_mmr_proof: ConsensusChainMmrLeafProof {
                        consensus_block_hash: block_hash,
                        opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                        proof: MmrProof {
                            leaf_indices: vec![],
                            leaf_count: 0,
                            items: vec![],
                        },
                    },
                    domain_proof: None,
                    message_proof: proof,
                })
            })
            .ok_or(Error::ConstructStorageProof)
    }

    fn construct_cross_chain_message_and_submit<
        Submitter: Fn(CrossDomainMessage<Block::Hash, Block::Hash>) -> Result<(), Error>,
        ProofConstructor: Fn(Block::Hash, &[u8]) -> Result<Proof<Block::Hash, Block::Hash>, Error>,
    >(
        block_hash: Block::Hash,
        msgs: Vec<BlockMessageWithStorageKey>,
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

    fn filter_messages(
        client: &Arc<Client>,
        mut msgs: BlockMessagesWithStorageKey,
    ) -> Result<BlockMessagesWithStorageKey, Error> {
        let api = client.runtime_api();
        let best_hash = client.info().best_hash;
        msgs.outbox.retain(|msg| {
            let id = (msg.channel_id, msg.nonce);
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
            }
        });

        msgs.inbox_responses.retain(|msg| {
            let id = (msg.channel_id, msg.nonce);
            match api.should_relay_inbox_message_response(best_hash, msg.dst_chain_id, id) {
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
            }
        });

        Ok(msgs)
    }

    pub(crate) fn submit_messages_from_consensus_chain(
        consensus_chain_client: &Arc<Client>,
        confirmed_block_hash: Block::Hash,
        gossip_message_sink: &GossipMessageSink,
    ) -> Result<(), Error> {
        let api = consensus_chain_client.runtime_api();
        let block_messages: BlockMessagesWithStorageKey = api
            .block_messages(confirmed_block_hash)
            .map_err(|_| Error::FetchAssignedMessages)?;
        let filtered_messages = Self::filter_messages(consensus_chain_client, block_messages)?;

        // short circuit if the there are no messages to relay
        if filtered_messages.outbox.is_empty() && filtered_messages.inbox_responses.is_empty() {
            return Ok(());
        }

        Self::construct_cross_chain_message_and_submit(
            confirmed_block_hash,
            filtered_messages.outbox,
            |block_id, key| {
                Self::construct_consensus_chain_storage_proof_for_key_at(
                    consensus_chain_client,
                    block_id,
                    key,
                )
            },
            |msg| Self::gossip_outbox_message(consensus_chain_client, msg, gossip_message_sink),
        )?;

        Self::construct_cross_chain_message_and_submit(
            confirmed_block_hash,
            filtered_messages.inbox_responses,
            |block_id, key| {
                Self::construct_consensus_chain_storage_proof_for_key_at(
                    consensus_chain_client,
                    block_id,
                    key,
                )
            },
            |msg| {
                Self::gossip_inbox_message_response(
                    consensus_chain_client,
                    msg,
                    gossip_message_sink,
                )
            },
        )?;

        Ok(())
    }

    pub(crate) fn submit_messages_from_domain<CCC, CCBlock>(
        domain_client: &Arc<Client>,
        consensus_chain_client: &Arc<CCC>,
        confirmed_block_hash: Block::Hash,
        gossip_message_sink: &GossipMessageSink,
        relay_confirmation_depth: NumberFor<Block>,
    ) -> Result<(), Error>
    where
        CCBlock: BlockT,
        Block::Hash: FullCodec,
        NumberFor<Block>: FullCodec + TypeInfo,
        NumberFor<CCBlock>: Into<NumberFor<Block>>,
        CCBlock::Hash: Into<Block::Hash>,
        CCC: HeaderBackend<CCBlock> + ProvideRuntimeApi<CCBlock> + ProofProvider<CCBlock>,
        CCC::Api: DomainsApi<CCBlock, Block::Header> + MessengerApi<CCBlock, NumberFor<CCBlock>>,
    {
        let chain_id = Self::chain_id(domain_client)?;
        let ChainId::Domain(domain_id) = chain_id else {
            return Err(Error::InvalidChainId);
        };

        let domain_block_header = domain_client.expect_header(confirmed_block_hash)?;
        let consensus_chain_api = consensus_chain_client.runtime_api();
        let best_consensus_chain_hash = consensus_chain_client.info().best_hash;
        let best_consensus_chain_block_header =
            consensus_chain_client.expect_header(best_consensus_chain_hash)?;

        // verify if the domain number is K-deep on Consensus chain
        if !consensus_chain_api
            .domain_best_number(best_consensus_chain_hash, domain_id)?
            .map(
                |best_number| match best_number.checked_sub(&relay_confirmation_depth) {
                    None => false,
                    Some(best_confirmed) => best_confirmed >= (*domain_block_header.number()),
                },
            )
            .unwrap_or(false)
        {
            return Err(Error::DomainNonConfirmedOnConsensusChain);
        }

        // fetch messages to be relayed
        let domain_api = domain_client.runtime_api();
        let block_messages: BlockMessagesWithStorageKey = domain_api
            .block_messages(confirmed_block_hash)
            .map_err(|_| Error::FetchAssignedMessages)?;

        let filtered_messages = Self::filter_messages(domain_client, block_messages)?;

        // short circuit if the there are no messages to relay
        if filtered_messages.outbox.is_empty() && filtered_messages.inbox_responses.is_empty() {
            return Ok(());
        }

        // generate domain proof that points to the confirmed domain block on consensus chain
        let storage_key = consensus_chain_api
            .confirmed_domain_block_storage_key(best_consensus_chain_hash, domain_id)?;

        let domain_proof = consensus_chain_client.read_proof(
            best_consensus_chain_hash,
            &mut [storage_key.as_ref()].into_iter(),
        )?;

        Self::construct_cross_chain_message_and_submit(
            confirmed_block_hash,
            filtered_messages.outbox,
            |block_hash, key| {
                Self::construct_domain_storage_proof_for_key_at(
                    best_consensus_chain_hash,
                    domain_client,
                    block_hash,
                    key,
                    *best_consensus_chain_block_header.state_root(),
                    domain_proof.clone(),
                )
            },
            |msg| Self::gossip_outbox_message(domain_client, msg, gossip_message_sink),
        )?;

        Self::construct_cross_chain_message_and_submit(
            confirmed_block_hash,
            filtered_messages.inbox_responses,
            |block_id, key| {
                Self::construct_domain_storage_proof_for_key_at(
                    best_consensus_chain_hash,
                    domain_client,
                    block_id,
                    key,
                    *best_consensus_chain_block_header.state_root(),
                    domain_proof.clone(),
                )
            },
            |msg| Self::gossip_inbox_message_response(domain_client, msg, gossip_message_sink),
        )?;

        Ok(())
    }

    /// Constructs the proof for the given key using the domain backend.
    fn construct_domain_storage_proof_for_key_at<CHash>(
        consensus_chain_block_hash: CHash,
        domain_client: &Arc<Client>,
        block_hash: Block::Hash,
        key: &[u8],
        _consensus_chain_state_root: CHash,
        domain_proof: StorageProof,
    ) -> Result<ProofOf<Block>, Error>
    where
        CHash: Into<Block::Hash>,
    {
        domain_client
            .header(block_hash)?
            .map(|header| (*header.number(), header.hash()))
            .and_then(|(_number, _hash)| {
                let proof = domain_client
                    .read_proof(block_hash, &mut [key].into_iter())
                    .ok()?;
                // TODO: Derive correct domain proof
                Some(Proof {
                    consensus_chain_mmr_proof: ConsensusChainMmrLeafProof {
                        consensus_block_hash: consensus_chain_block_hash.into(),
                        opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                        proof: MmrProof {
                            leaf_indices: vec![],
                            leaf_count: 0,
                            items: vec![],
                        },
                    },
                    domain_proof: Some(domain_proof),
                    message_proof: proof,
                })
            })
            .ok_or(Error::ConstructStorageProof)
    }

    /// Sends an Outbox message from src_domain to dst_domain.
    fn gossip_outbox_message(
        client: &Arc<Client>,
        msg: CrossDomainMessage<Block::Hash, Block::Hash>,
        sink: &GossipMessageSink,
    ) -> Result<(), Error> {
        let best_hash = client.info().best_hash;
        let dst_chain_id = msg.dst_chain_id;
        let ext = client
            .runtime_api()
            .outbox_message_unsigned(best_hash, msg)?
            .ok_or(Error::FailedToConstructExtrinsic)?;

        sink.unbounded_send(GossipMessage {
            chain_id: dst_chain_id,
            encoded_data: ext.encode(),
        })
        .map_err(Error::UnableToSubmitCrossDomainMessage)
    }

    /// Sends an Inbox message response from src_domain to dst_domain
    /// Inbox message was earlier sent by dst_domain to src_domain and
    /// this message is the response of the Inbox message execution.
    fn gossip_inbox_message_response(
        client: &Arc<Client>,
        msg: CrossDomainMessage<Block::Hash, Block::Hash>,
        sink: &GossipMessageSink,
    ) -> Result<(), Error> {
        let best_hash = client.info().best_hash;
        let dst_chain_id = msg.dst_chain_id;
        let ext = client
            .runtime_api()
            .inbox_response_message_unsigned(best_hash, msg)?
            .ok_or(Error::FailedToConstructExtrinsic)?;

        sink.unbounded_send(GossipMessage {
            chain_id: dst_chain_id,
            encoded_data: ext.encode(),
        })
        .map_err(Error::UnableToSubmitCrossDomainMessage)
    }

    fn relayed_blocks_at_number_key(chain_id: ChainId, number: NumberFor<Block>) -> Vec<u8> {
        (
            b"message_relayer_processed_block_of_domain",
            chain_id,
            number,
        )
            .encode()
    }

    /// Takes number as tip and finds all the unprocessed blocks including the tip.
    fn fetch_unprocessed_blocks_until(
        client: &Arc<Client>,
        chain_id: ChainId,
        best_number: NumberFor<Block>,
        best_hash: Block::Hash,
    ) -> Result<UnProcessedBlocks<Block>, Error> {
        let mut blocks_to_process = vec![];
        let (mut number_to_check, mut hash_to_check) = (best_number, best_hash);
        while !Self::fetch_blocks_relayed_at(client, chain_id, number_to_check)
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
        chain_id: ChainId,
        number: NumberFor<Block>,
    ) -> Vec<Block::Hash> {
        client
            .get_aux(&Self::relayed_blocks_at_number_key(chain_id, number))
            .ok()
            .flatten()
            .and_then(|enc_val| Vec::<Block::Hash>::decode(&mut enc_val.as_ref()).ok())
            .unwrap_or_default()
    }

    // TODO: at the moment the aux storage grows as the chain grows
    // We can prune the the storage by doing another round of check for any undelivered messages
    // and then prune the storage.
    // We can use Finalize event but its not triggered yet as we dont finalize.
    // Other option would be to use fraud proof period.
    pub(crate) fn store_relayed_block(
        client: &Arc<Client>,
        chain_id: ChainId,
        block_number: NumberFor<Block>,
        block_hash: Block::Hash,
    ) -> Result<(), Error> {
        let mut processed_blocks = Self::fetch_blocks_relayed_at(client, chain_id, block_number);
        if processed_blocks.contains(&block_hash) {
            return Ok(());
        }

        processed_blocks.push(block_hash);
        client
            .insert_aux(
                &[(
                    Self::relayed_blocks_at_number_key(chain_id, block_number).as_ref(),
                    processed_blocks.encode().as_ref(),
                )],
                &[],
            )
            .map_err(|_| Error::StoreRelayedBlockNumber)
    }
}
