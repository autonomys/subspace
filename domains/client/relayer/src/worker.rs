use crate::{BlockT, Error, GossipMessageSink, HeaderBackend, HeaderT, Relayer, LOG_TARGET};
use futures::StreamExt;
use parity_scale_codec::FullCodec;
use sc_client_api::{AuxStore, BlockchainEvents, ProofProvider};
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_consensus::SyncOracle;
use sp_domains::DomainsApi;
use sp_messenger::messages::ChainId;
use sp_messenger::RelayerApi;
use sp_runtime::scale_info::TypeInfo;
use sp_runtime::traits::{CheckedSub, NumberFor, Zero};
use std::sync::Arc;

/// Starts relaying consensus chain messages to other domains.
/// If the node is in major sync, worker waits waits until the sync is finished.
pub async fn relay_consensus_chain_messages<Client, Block, SO>(
    consensus_chain_client: Arc<Client>,
    sync_oracle: SO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    Client: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>>,
    SO: SyncOracle,
{
    // there is not confirmation depth for relayer on system domain
    // since all the relayers will haven embed client to known the canonical chain.
    let result = start_relaying_messages(
        NumberFor::<Block>::zero(),
        consensus_chain_client,
        |client, block_hash| {
            Relayer::submit_messages_from_consensus_chain(client, block_hash, &gossip_message_sink)
        },
        sync_oracle,
        |_, _| -> Result<bool, ApiError> {
            // since we just need to provide a storage proof with the state root of Consensus chain
            // proof can always be generated for any consensus chain block.
            // So we can always relay messages.
            Ok(true)
        },
    )
    .await;

    if let Err(err) = result {
        tracing::error!(
            target: LOG_TARGET,
            ?err,
            "Failed to start relayer for Consensus chain"
        )
    }
}

/// Starts relaying domain messages to other chains.
/// If the domain node is in major sync, worker waits waits until the sync is finished.
pub async fn relay_domain_messages<CCC, DC, CCBlock, Block, SO>(
    consensus_chain_client: Arc<CCC>,
    domain_client: Arc<DC>,
    sync_oracle: SO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    CCBlock: BlockT,
    Block::Hash: FullCodec,
    NumberFor<Block>: FullCodec + TypeInfo,
    NumberFor<CCBlock>: Into<NumberFor<Block>>,
    CCBlock::Hash: Into<Block::Hash>,
    DC: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    DC::Api: RelayerApi<Block, NumberFor<Block>>,
    CCC: HeaderBackend<CCBlock> + ProvideRuntimeApi<CCBlock> + ProofProvider<CCBlock>,
    CCC::Api: DomainsApi<CCBlock, Block::Header>,
    SO: SyncOracle + Send,
{
    let relay_confirmation_depth = match Relayer::relay_confirmation_depth(&domain_client) {
        Ok(depth) => depth,
        Err(err) => {
            tracing::error!(target: LOG_TARGET, ?err, "Failed to get confirmation depth");
            return;
        }
    };

    let result = start_relaying_messages(
        relay_confirmation_depth,
        domain_client,
        |client, block_hash| {
            Relayer::submit_messages_from_domain(
                client,
                &consensus_chain_client,
                block_hash,
                &gossip_message_sink,
                relay_confirmation_depth,
            )
        },
        sync_oracle,
        |chain_id, block_number| -> Result<bool, ApiError> {
            let ChainId::Domain(domain_id) = chain_id else {
                return Err(ApiError::Application(Box::from(
                    "Should always be running under a Domain".to_string(),
                )));
            };

            let api = consensus_chain_client.runtime_api();
            let at = consensus_chain_client.info().best_hash;
            let oldest_tracked_number = api.oldest_receipt_number(at, domain_id)?;
            // ensure block number is at least the oldest tracked number
            Ok(block_number >= oldest_tracked_number)
        },
    )
    .await;
    if let Err(err) = result {
        tracing::error!(
            target: LOG_TARGET,
            ?err,
            "Failed to start relayer for domain"
        )
    }
}

async fn start_relaying_messages<Client, Block, MP, SO, CRM>(
    relay_confirmation_depth: NumberFor<Block>,
    client: Arc<Client>,
    message_processor: MP,
    sync_oracle: SO,
    can_relay_message_from_block: CRM,
) -> Result<(), Error>
where
    Block: BlockT,
    Client: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>>,
    MP: Fn(&Arc<Client>, Block::Hash) -> Result<(), Error>,
    SO: SyncOracle,
    CRM: Fn(ChainId, NumberFor<Block>) -> Result<bool, ApiError>,
{
    let chain_id = Relayer::chain_id(&client)?;
    tracing::info!(
        target: LOG_TARGET,
        "Starting relayer for chain: {:?}",
        chain_id,
    );
    let mut chain_block_import = client.import_notification_stream();

    // from the start block, start processing all the messages assigned
    // wait for new block import of chain,
    // then fetch new messages in the block
    // construct proof of each message to be relayed
    // submit XDM as unsigned extrinsic.
    while let Some(block) = chain_block_import.next().await {
        // if the client is in major sync, wait until sync is complete
        if sync_oracle.is_major_syncing() {
            tracing::info!(target: LOG_TARGET, "Client is in major sync. Skipping...");
            continue;
        }

        let relay_block_until = match block.header.number().checked_sub(&relay_confirmation_depth) {
            None => {
                // not enough confirmed blocks.
                tracing::info!(
                    target: LOG_TARGET,
                    "Not enough confirmed blocks for domain: {:?}. Skipping...",
                    chain_id
                );
                continue;
            }
            Some(confirmed_block) => confirmed_block,
        };

        let (number, hash) = (*block.header.number(), block.header.hash());
        let blocks_to_process: Vec<(NumberFor<Block>, Block::Hash)> =
            Relayer::fetch_unprocessed_blocks_until(&client, chain_id, number, hash)?
                .into_iter()
                .filter(|(number, _)| *number <= relay_block_until)
                .collect();

        for (number, hash) in blocks_to_process {
            tracing::info!(
                target: LOG_TARGET,
                "Checking messages to be submitted from chain: {chain_id:?} at block: ({number:?}, {hash:?})",
            );

            // check if the message is ready to be relayed.
            // if not, the node is lagging behind and/or there is no way to generate a proof.
            // mark this block processed and continue to next one.
            if !can_relay_message_from_block(chain_id, number)? {
                Relayer::store_relayed_block(&client, chain_id, number, hash)?;
                tracing::info!(
                    target: LOG_TARGET,
                    "Chain({chain_id:?}) messages in the Block ({number:?}, {hash:?}) cannot be relayed. Skipping...",
                );
            } else {
                match message_processor(&client, hash) {
                    Ok(_) => {
                        Relayer::store_relayed_block(&client, chain_id, number, hash)?;
                        tracing::info!(
                            target: LOG_TARGET,
                            "Messages from {chain_id:?} at block({number:?}, {hash:?}) are processed."
                        )
                    }
                    Err(err) => {
                        match err {
                            Error::DomainNonConfirmedOnConsensusChain => {
                                tracing::info!(
                                    target: LOG_TARGET,
                                    "Waiting for Domain[{chain_id:?}] block({number:?}, {hash:?}) to be confirmed on Consensus chain."
                                )
                            }
                            _ => {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    ?err,
                                    "Failed to submit messages from the chain {chain_id:?} at the block ({number:?}, {hash:?})"
                                );
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
