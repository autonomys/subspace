use crate::{BlockT, Error, GossipMessageSink, HeaderBackend, HeaderT, Relayer, LOG_TARGET};
use cross_domain_message_gossip::{ChannelUpdate, Message as GossipMessage, MessageData};
use futures::StreamExt;
use sc_client_api::{AuxStore, BlockchainEvents, ProofProvider};
use sc_state_db::PruningMode;
use sp_api::{ApiError, ApiExt, ProvideRuntimeApi};
use sp_consensus::SyncOracle;
use sp_domains::{DomainId, DomainsApi};
use sp_messenger::messages::ChainId;
use sp_messenger::{MessengerApi, RelayerApi};
use sp_mmr_primitives::MmrApi;
use sp_runtime::traits::{CheckedSub, NumberFor, One};
use sp_runtime::SaturatedConversion;
use std::sync::Arc;

pub async fn gossip_channel_updates<Client, Block, CBlock, SO>(
    chain_id: ChainId,
    client: Arc<Client>,
    sync_oracle: SO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    CBlock: BlockT,
    Client: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
    SO: SyncOracle,
{
    tracing::info!(
        target: LOG_TARGET,
        "Starting Channel updates for chain: {:?}",
        chain_id,
    );
    let mut chain_block_imported = client.every_import_notification_stream();
    while let Some(imported_block) = chain_block_imported.next().await {
        // if the client is in major sync, wait until sync is complete
        if sync_oracle.is_major_syncing() {
            tracing::debug!(target: LOG_TARGET, "Client is in major sync. Skipping...");
            continue;
        }

        if !imported_block.is_new_best {
            tracing::debug!(target: LOG_TARGET, "Imported non-best block. Skipping...");
            continue;
        }

        let (block_hash, block_number) = match chain_id {
            ChainId::Consensus => (
                imported_block.header.hash(),
                *imported_block.header.number(),
            ),
            ChainId::Domain(_) => {
                // for domains, we gossip channel updates of imported block - 1
                // since the execution receipt of the imported block is not registered on consensus
                // without the execution receipt, we would not be able to verify the storage proof
                let number = match imported_block.header.number().checked_sub(&One::one()) {
                    None => continue,
                    Some(number) => number,
                };

                let hash = match client.hash(number).ok().flatten() {
                    Some(hash) => hash,
                    None => {
                        tracing::debug!(target: LOG_TARGET, "Missing block hash for number: {:?}", number);
                        continue;
                    }
                };

                (hash, number)
            }
        };

        if let Err(err) = do_gossip_channel_updates::<_, _, CBlock>(
            chain_id,
            &client,
            &gossip_message_sink,
            block_number,
            block_hash,
        ) {
            tracing::error!(target: LOG_TARGET, ?err, "failed to gossip channel update");
        }
    }
}

fn do_gossip_channel_updates<Client, Block, CBlock>(
    src_chain_id: ChainId,
    client: &Arc<Client>,
    gossip_message_sink: &GossipMessageSink,
    block_number: NumberFor<Block>,
    block_hash: Block::Hash,
) -> Result<(), Error>
where
    Block: BlockT,
    CBlock: BlockT,
    Client: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
{
    let api = client.runtime_api();
    let api_version = api
        .api_version::<dyn RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>>(
            block_hash,
        )?
        .ok_or(sp_api::ApiError::Application(
            "Failed to get relayer api version".into(),
        ))?;

    if api_version < 2 {
        return Ok(());
    }

    let updated_channels = api.updated_channels(block_hash)?;

    for (dst_chain_id, channel_id) in updated_channels {
        let storage_key = api.channel_storage_key(block_hash, dst_chain_id, channel_id)?;
        let proof = client
            .read_proof(block_hash, &mut [storage_key.as_ref()].into_iter())
            .map_err(|_| Error::ConstructStorageProof)?;

        let gossip_message = GossipMessage {
            chain_id: dst_chain_id,
            data: MessageData::ChannelUpdate(ChannelUpdate {
                src_chain_id,
                channel_id,
                block_number: block_number.saturated_into(),
                storage_proof: proof,
            }),
        };

        gossip_message_sink
            .unbounded_send(gossip_message)
            .map_err(Error::UnableToSubmitCrossDomainMessage)?;
    }

    Ok(())
}

/// Starts relaying consensus chain messages to other domains.
/// If the node is in major sync, worker waits until the sync is finished.
pub async fn relay_consensus_chain_messages<Client, Block, SO>(
    consensus_chain_client: Arc<Client>,
    confirmation_depth_k: NumberFor<Block>,
    state_pruning_mode: PruningMode,
    sync_oracle: SO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    Client: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<Block>, Block::Hash>
        + MmrApi<Block, sp_core::H256, NumberFor<Block>>,
    SO: SyncOracle,
{
    let result = start_relaying_messages(
        ChainId::Consensus,
        consensus_chain_client.clone(),
        confirmation_depth_k,
        |client, block_id, _| {
            Relayer::submit_messages_from_consensus_chain(client, block_id, &gossip_message_sink)
        },
        sync_oracle,
        |block_number| -> Result<Option<()>, ApiError> {
            // since a parent mmr leaf is included in its child,
            // we process the finalized block's parent instead since we know parent is implicitly finalized
            // so we ensure the state of the parent is available here
            Ok(block_number
                .checked_sub(&One::one())
                .and_then(|number_to_check| {
                    is_state_available(
                        &state_pruning_mode,
                        &consensus_chain_client,
                        number_to_check,
                    )
                    .then_some(())
                }))
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

type DomainExtraData<Block> = (NumberFor<Block>, <Block as BlockT>::Hash);

/// Starts relaying domain messages to other chains.
/// If the domain node is in major sync, worker waits until the sync is finished.
#[allow(clippy::too_many_arguments)]
pub async fn relay_domain_messages<CClient, Client, CBlock, Block, SO>(
    domain_id: DomainId,
    consensus_chain_client: Arc<CClient>,
    confirmation_depth_k: NumberFor<CBlock>,
    consensus_state_pruning: PruningMode,
    domain_client: Arc<Client>,
    domain_state_pruning: PruningMode,
    sync_oracle: SO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    CBlock: BlockT,
    Client: HeaderBackend<Block> + AuxStore + ProofProvider<Block> + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, NumberFor<CBlock>, CBlock::Hash>,
    CClient: BlockchainEvents<CBlock>
        + HeaderBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + ProofProvider<CBlock>
        + AuxStore,
    CClient::Api: DomainsApi<CBlock, Block::Header>
        + MessengerApi<CBlock, NumberFor<CBlock>, CBlock::Hash>
        + MmrApi<CBlock, sp_core::H256, NumberFor<CBlock>>,
    SO: SyncOracle + Send,
{
    let result = start_relaying_messages(
        ChainId::Domain(domain_id),
        consensus_chain_client.clone(),
        confirmation_depth_k,
        |consensus_chain_client, consensus_block, (_domain_block_number, domain_hash)| {
            Relayer::submit_messages_from_domain(
                domain_id,
                &domain_client,
                consensus_chain_client,
                consensus_block,
                domain_hash,
                &gossip_message_sink,
            )
        },
        sync_oracle,
        |consensus_block_number|
         -> Result<Option<DomainExtraData<Block>>, ApiError> {
            // since a parent mmr leaf is included in its child,
            // we process the finalized block's parent instead since we know parent is implicitly finalized
            // so we ensure the state of the parent is available here
            let consensus_block_number = match consensus_block_number.checked_sub(&One::one()) {
                None => return Ok(None),
                Some(number) => number
            };

            if !is_state_available(
                &consensus_state_pruning,
                &consensus_chain_client,
                consensus_block_number,
            ) {
                return Ok(None);
            }

            let consensus_hash_to_process = consensus_chain_client
                .hash(consensus_block_number)?
                .ok_or(ApiError::UnknownBlock(format!("Missing Hash for block number: {consensus_block_number:?}")))?;
            let api = consensus_chain_client.runtime_api();

            // TODO: This is used to keep compatible with gemini-3h, remove before next network
            let api_version = api
            .api_version::<dyn DomainsApi<CBlock, Block::Header>>(consensus_hash_to_process)
            .map_err(sp_blockchain::Error::RuntimeApiError)?
            .ok_or_else(|| {
                sp_blockchain::Error::RuntimeApiError(ApiError::Application(
                    format!("DomainsApi not found at: {:?}", consensus_hash_to_process).into(),
                ))
            })?;
            if api_version < 2 {
                return Ok(None)
            }

            let confirmed_domain_block =
                api.latest_confirmed_domain_block(consensus_hash_to_process, domain_id)?;

            if let Some((domain_block_number, domain_block_hash)) = confirmed_domain_block {
                // short circuit if the domain state is unavailable to relay messages.
                if !is_state_available(&domain_state_pruning, &domain_client, domain_block_number) {
                    return Ok(None);
                }

                tracing::debug!(
                    target: LOG_TARGET,
                    "Domain block: {domain_block_number:?} and {domain_block_hash:?} confirmed at Consensus block {consensus_block_number:?}"
                );

                Ok(confirmed_domain_block)
            } else {
                // if there is not confirmed domain block for this domain, skip
                Ok(None)
            }
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

fn is_state_available<Client, Block>(
    state_pruning_mode: &PruningMode,
    client: &Arc<Client>,
    relay_number: NumberFor<Block>,
) -> bool
where
    Block: BlockT,
    Client: HeaderBackend<Block>,
{
    match state_pruning_mode {
        // all the state is available for archive and archive canonical.
        // we can relay any message from any block
        PruningMode::ArchiveAll | PruningMode::ArchiveCanonical => true,
        // If the pruning mode is constrained, then check if the state is available for the `relay_number`
        PruningMode::Constrained(constraints) => {
            let max_blocks = NumberFor::<Block>::from(constraints.max_blocks.unwrap_or(0));
            let current_best_block = client.info().best_number;
            match current_best_block.checked_sub(&max_blocks) {
                // we still have the state available as there was no pruning yet.
                None => true,
                Some(available_block_state) => relay_number >= available_block_state,
            }
        }
    }
}

async fn start_relaying_messages<CClient, CBlock, MP, SO, CRM, ExtraData>(
    chain_id: ChainId,
    consensus_client: Arc<CClient>,
    confirmation_depth_k: NumberFor<CBlock>,
    message_processor: MP,
    sync_oracle: SO,
    can_relay_message_from_block: CRM,
) -> Result<(), Error>
where
    CBlock: BlockT,
    CClient: BlockchainEvents<CBlock>
        + HeaderBackend<CBlock>
        + AuxStore
        + ProofProvider<CBlock>
        + ProvideRuntimeApi<CBlock>,
    MP: Fn(&Arc<CClient>, (NumberFor<CBlock>, CBlock::Hash), ExtraData) -> Result<(), Error>,
    SO: SyncOracle,
    CRM: Fn(NumberFor<CBlock>) -> Result<Option<ExtraData>, ApiError>,
{
    tracing::info!(
        target: LOG_TARGET,
        "Starting relayer for chain: {:?}",
        chain_id,
    );
    let mut chain_block_imported = consensus_client.every_import_notification_stream();

    // from the start block, start processing all the messages assigned
    // wait for new block finalization of the chain,
    // then fetch new messages in the block
    // construct proof of each message to be relayed
    // submit XDM as unsigned extrinsic.
    while let Some(block) = chain_block_imported.next().await {
        // if the client is in major sync, wait until sync is complete
        if sync_oracle.is_major_syncing() {
            tracing::debug!(target: LOG_TARGET, "Client is in major sync. Skipping...");
            continue;
        }

        if !block.is_new_best {
            tracing::debug!(target: LOG_TARGET, "Imported non-best block. Skipping...");
            continue;
        }

        let (number, hash) = {
            let imported_block_number = *block.header.number();
            if let Some(block_to_relay) = imported_block_number.checked_sub(&confirmation_depth_k) {
                let block_to_relay_hash = consensus_client
                    .hash(block_to_relay)?
                    .ok_or(Error::MissingBlockHash)?;
                (block_to_relay, block_to_relay_hash)
            } else {
                tracing::debug!(target: LOG_TARGET, "Not enough confirmed blocks. Skipping...");
                continue;
            }
        };

        tracing::debug!(
            target: LOG_TARGET,
            "Checking messages to be submitted from chain: {chain_id:?} at block: ({number:?}, {hash:?})",
        );

        // check if the message is ready to be relayed.
        // if not, the node is lagging behind and/or there is no way to generate a proof.
        // mark this block processed and continue to next one.
        if let Some(extra_data) = can_relay_message_from_block(number)? {
            match message_processor(&consensus_client, (number, hash), extra_data) {
                Ok(_) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        "Messages from {chain_id:?} at block({number:?}, {hash:?}) are processed."
                    )
                }
                Err(err) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        ?err,
                        "Failed to submit messages from the chain {chain_id:?} at the block ({number:?}, {hash:?})"
                    );
                    break;
                }
            }
        } else {
            tracing::debug!(
                target: LOG_TARGET,
                "Chain({chain_id:?}) messages in the Block ({number:?}, {hash:?}) cannot be relayed. Skipping...",
            );
        }
    }

    Ok(())
}
