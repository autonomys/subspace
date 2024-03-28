use crate::{BlockT, Error, GossipMessageSink, HeaderBackend, HeaderT, Relayer, LOG_TARGET};
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
use std::sync::Arc;

/// Starts relaying consensus chain messages to other domains.
/// If the node is in major sync, worker waits until the sync is finished.
pub async fn relay_consensus_chain_messages<Client, Block, SO>(
    consensus_chain_client: Arc<Client>,
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
    Client::Api: RelayerApi<Block, NumberFor<Block>, Block::Hash>
        + MmrApi<Block, sp_core::H256, NumberFor<Block>>,
    SO: SyncOracle,
{
    let result = start_relaying_messages(
        ChainId::Consensus,
        consensus_chain_client.clone(),
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
pub async fn relay_domain_messages<CClient, Client, CBlock, Block, SO>(
    domain_id: DomainId,
    consensus_chain_client: Arc<CClient>,
    consensus_state_pruning: PruningMode,
    domain_client: Arc<Client>,
    domain_state_pruning: PruningMode,
    sync_oracle: SO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    CBlock: BlockT,
    Client: HeaderBackend<Block> + AuxStore + ProofProvider<Block> + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, NumberFor<Block>, CBlock::Hash>,
    CClient: BlockchainEvents<CBlock>
        + HeaderBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + ProofProvider<CBlock>
        + AuxStore,
    CClient::Api: DomainsApi<CBlock, Block::Header>
        + MessengerApi<CBlock>
        + MmrApi<CBlock, sp_core::H256, NumberFor<CBlock>>,
    SO: SyncOracle + Send,
{
    let result = start_relaying_messages(
        ChainId::Domain(domain_id),
        consensus_chain_client.clone(),
        |consensus_chain_client, consensus_block, (domain_block_number, domain_hash)| {
            let res = Relayer::submit_messages_from_domain(
                domain_id,
                &domain_client,
                consensus_chain_client,
                consensus_block,
                domain_hash,
                &gossip_message_sink,
            );

            if res.is_ok() {
                Relayer::store_relayed_domain_block(
                    &domain_client,
                    domain_id,
                    domain_block_number,
                    domain_hash,
                )?;
            }

            res
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

                // check if this domain block is already relayed
                if Relayer::fetch_domains_blocks_relayed_at(
                    &domain_client,
                    domain_id,
                    domain_block_number,
                )
                    .contains(&domain_block_hash)
                {
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
    let mut chain_block_finalization = consensus_client.finality_notification_stream();

    // from the start block, start processing all the messages assigned
    // wait for new block finalization of the chain,
    // then fetch new messages in the block
    // construct proof of each message to be relayed
    // submit XDM as unsigned extrinsic.
    while let Some(block) = chain_block_finalization.next().await {
        // if the client is in major sync, wait until sync is complete
        if sync_oracle.is_major_syncing() {
            tracing::debug!(target: LOG_TARGET, "Client is in major sync. Skipping...");
            continue;
        }

        let (number, hash) = (*block.header.number(), block.header.hash());
        let blocks_to_process: Vec<(NumberFor<CBlock>, CBlock::Hash)> =
            Relayer::fetch_unprocessed_consensus_blocks_until(
                &consensus_client,
                chain_id,
                number,
                hash,
            )?;

        for (number, hash) in blocks_to_process {
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
                        Relayer::store_relayed_consensus_block(
                            &consensus_client,
                            chain_id,
                            number,
                            hash,
                        )?;
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
                Relayer::store_relayed_consensus_block(&consensus_client, chain_id, number, hash)?;
                tracing::debug!(
                    target: LOG_TARGET,
                    "Chain({chain_id:?}) messages in the Block ({number:?}, {hash:?}) cannot be relayed. Skipping...",
                );
            }
        }
    }

    Ok(())
}
