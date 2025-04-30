use domain_runtime_primitives::{Balance, BlockNumber};
use futures::channel::mpsc;
use futures::{SinkExt, Stream, StreamExt};
use sc_client_api::{AuxStore, BlockchainEvents, ProofProvider};
use sc_consensus::{
    BlockImport, BlockImportParams, ForkChoiceStrategy, ImportedState, StateAction, StorageChanges,
};
use sc_network::PeerId;
use sc_network_common::sync::message::{
    BlockAttributes, BlockData, BlockRequest, Direction, FromBlock,
};
use sc_network_sync::block_relay_protocol::BlockDownloader;
use sc_network_sync::service::network::NetworkServiceHandle;
use sc_network_sync::SyncingService;
use sc_subspace_sync_common::snap_sync_engine::SnapSyncingEngine;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_domains::ExecutionReceiptFor;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, Header, NumberFor};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio::time::sleep;
use tracing::{debug, error, trace, Instrument};

pub(crate) const LOG_TARGET: &str = "domain_snap_sync";

/// Notification with number of the block that is about to be imported and acknowledgement sender
/// that pauses block production until the previous block is acknowledged.
#[derive(Debug, Clone)]
pub struct BlockImportingAcknowledgement<Block>
where
    Block: BlockT,
{
    /// Block number
    pub block_number: NumberFor<Block>,
    /// Sender for pausing the block import when operator is not fast enough to process
    /// the consensus block.
    pub acknowledgement_sender: mpsc::Sender<()>,
}

/// Provides parameters for domain snap sync synchronization with the consensus chain snap sync.
pub struct ConsensusChainSyncParams<Block, DomainHeader>
where
    Block: BlockT,
    DomainHeader: Header,
{
    /// Synchronizes consensus snap sync stages.
    pub snap_sync_orchestrator: Arc<SnapSyncOrchestrator>,
    /// Confirmed last Domain block ER
    pub last_domain_block_er: ExecutionReceiptFor<DomainHeader, Block, Balance>,
    /// Consensus chain block importing stream
    pub block_importing_notification_stream:
        Box<dyn Stream<Item = BlockImportingAcknowledgement<Block>> + Sync + Send + Unpin>,
}

/// Synchronizes consensus and domain chain snap sync.
pub struct SnapSyncOrchestrator {
    consensus_snap_sync_target_block_tx: broadcast::Sender<BlockNumber>,
    domain_snap_sync_finished: Arc<AtomicBool>,
}

impl Default for SnapSyncOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapSyncOrchestrator {
    /// Constructor
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1);
        Self {
            consensus_snap_sync_target_block_tx: tx,
            domain_snap_sync_finished: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Unblocks (allows) consensus chain snap sync with the given target block.
    pub fn unblock_consensus_snap_sync(&self, target_block_number: BlockNumber) {
        debug!(target: LOG_TARGET, %target_block_number, "Allowed starting consensus chain snap sync.");

        let target_block_send_result = self
            .consensus_snap_sync_target_block_tx
            .send(target_block_number);

        debug!(
            target: LOG_TARGET,
            ?target_block_send_result,
            "Target block sending result: {target_block_number}"
        );
    }

    /// Returns shared variable signaling domain snap sync finished.
    pub fn domain_snap_sync_finished(&self) -> Arc<AtomicBool> {
        self.domain_snap_sync_finished.clone()
    }

    /// Subscribes to a channel to receive target block numbers for consensus chain snap sync.
    pub fn consensus_snap_sync_target_block_receiver(&self) -> broadcast::Receiver<BlockNumber> {
        self.consensus_snap_sync_target_block_tx.subscribe()
    }

    /// Signal that domain snap sync finished.
    pub fn mark_domain_snap_sync_finished(&self) {
        debug!(target: LOG_TARGET, "Signal that domain snap sync finished.");
        self.domain_snap_sync_finished
            .store(true, Ordering::Release);
    }
}

pub struct SyncParams<DomainClient, Block, CBlock>
where
    Block: BlockT,
    CBlock: BlockT,
{
    pub domain_client: Arc<DomainClient>,
    pub sync_service: Arc<SyncingService<Block>>,
    pub domain_fork_id: Option<String>,
    pub domain_network_service_handle: NetworkServiceHandle,
    pub domain_block_downloader: Arc<dyn BlockDownloader<Block>>,
    pub consensus_chain_sync_params: ConsensusChainSyncParams<CBlock, Block::Header>,
    pub challenge_period: NumberFor<CBlock>,
}

async fn get_last_confirmed_block<Block: BlockT>(
    block_downloader: Arc<dyn BlockDownloader<Block>>,
    sync_service: &SyncingService<Block>,
    block_number: BlockNumber,
) -> Result<BlockData<Block>, sp_blockchain::Error> {
    const LAST_CONFIRMED_BLOCK_RETRIES: u32 = 5;
    const LOOP_PAUSE: Duration = Duration::from_secs(20);
    const MAX_GET_PEERS_ATTEMPT_NUMBER: usize = 30;

    for attempt in 1..=LAST_CONFIRMED_BLOCK_RETRIES {
        debug!(target: LOG_TARGET, %attempt, %block_number, "Starting last confirmed block request...");

        debug!(target: LOG_TARGET, %block_number, "Gathering peers for last confirmed block request.");
        let mut tried_peers = HashSet::<PeerId>::new();

        let current_peer_id = match get_currently_connected_peer(
            sync_service,
            &mut tried_peers,
            LOOP_PAUSE,
            MAX_GET_PEERS_ATTEMPT_NUMBER,
        )
        .instrument(tracing::info_span!("last confirmed block"))
        .await
        {
            Ok(peer_id) => peer_id,
            Err(err) => {
                debug!(target: LOG_TARGET, ?err, "Getting peers for the last confirmed block failed");
                continue;
            }
        };
        tried_peers.insert(current_peer_id);

        let id = {
            let now = SystemTime::now();
            let duration_since_epoch = now
                .duration_since(UNIX_EPOCH)
                .expect("Time usually goes forward");

            duration_since_epoch.as_nanos() as u64
        };

        let block_request = BlockRequest::<Block> {
            id,
            direction: Direction::Ascending,
            from: FromBlock::Number(block_number.into()),
            max: Some(1),
            fields: BlockAttributes::HEADER
                | BlockAttributes::JUSTIFICATION
                | BlockAttributes::BODY
                | BlockAttributes::RECEIPT
                | BlockAttributes::MESSAGE_QUEUE
                | BlockAttributes::INDEXED_BODY,
        };
        let block_response_result = block_downloader
            .download_blocks(current_peer_id, block_request.clone())
            .await;

        match block_response_result {
            Ok(block_response_inner_result) => {
                trace!(
                    target: LOG_TARGET,
                    %block_number,
                    "Sync worker handle result: {:?}",
                    block_response_inner_result
                );

                match block_response_inner_result {
                    Ok(data) => {
                        match block_downloader.block_response_into_blocks(&block_request, data.0) {
                            Ok(mut blocks) => {
                                trace!(target: LOG_TARGET, %block_number, "Domain block parsing result: {:?}", blocks);

                                if let Some(blocks) = blocks.pop() {
                                    return Ok(blocks);
                                } else {
                                    trace!(target: LOG_TARGET, %current_peer_id, "Got empty state blocks",);
                                    continue;
                                }
                            }
                            Err(error) => {
                                error!(target: LOG_TARGET, %block_number, ?error, "Domain block parsing error");
                                continue;
                            }
                        }
                    }
                    Err(error) => {
                        error!(target: LOG_TARGET, %block_number, ?error, "Domain block sync error (inner)");
                        continue;
                    }
                }
            }
            Err(error) => {
                error!(target: LOG_TARGET, %block_number, ?error, "Domain block sync error");
                continue;
            }
        }
    }

    Err(sp_blockchain::Error::Application(
        format!("Failed to get block {}", block_number).into(),
    ))
}

fn convert_block_number<Block: BlockT>(block_number: NumberFor<Block>) -> u32 {
    let block_number: u32 = match block_number.try_into() {
        Ok(block_number) => block_number,
        Err(_) => {
            panic!("Can't convert block number.")
        }
    };

    block_number
}

pub(crate) async fn snap_sync<Block, Client, CBlock>(
    sync_params: SyncParams<Client, Block, CBlock>,
) -> Result<(), sp_blockchain::Error>
where
    Block: BlockT,
    Client: HeaderBackend<Block>
        + BlockImport<Block>
        + AuxStore
        + ProofProvider<Block>
        + BlockchainEvents<Block>
        + Send
        + Sync
        + 'static,
    for<'a> &'a Client: BlockImport<Block>,
    CBlock: BlockT,
{
    let last_confirmed_block_receipt = sync_params.consensus_chain_sync_params.last_domain_block_er;

    // TODO: Handle the special case when we just added the domain
    if last_confirmed_block_receipt.domain_block_number == 0u32.into() {
        return Err(sp_blockchain::Error::Application(
            "Can't snap sync from genesis.".into(),
        ));
    }

    let consensus_block_hash = last_confirmed_block_receipt.consensus_block_hash;

    let mut block_importing_notification_stream = sync_params
        .consensus_chain_sync_params
        .block_importing_notification_stream;

    let mut consensus_target_block_acknowledgement_sender = None;
    while let Some(mut block_notification) = block_importing_notification_stream.next().await {
        if block_notification.block_number <= last_confirmed_block_receipt.consensus_block_number {
            if block_notification
                .acknowledgement_sender
                .send(())
                .await
                .is_err()
            {
                return Err(sp_blockchain::Error::Application(
                    format!(
                        "Can't acknowledge block import #{}",
                        block_notification.block_number
                    )
                    .into(),
                ));
            };
        } else {
            consensus_target_block_acknowledgement_sender
                .replace(block_notification.acknowledgement_sender);
            break;
        }
    }

    let domain_block_number =
        convert_block_number::<Block>(last_confirmed_block_receipt.domain_block_number);

    let domain_block_hash = last_confirmed_block_receipt.domain_block_hash;
    let domain_block = get_last_confirmed_block(
        sync_params.domain_block_downloader,
        &sync_params.sync_service,
        domain_block_number,
    )
    .await?;

    let Some(domain_block_header) = domain_block.header.clone() else {
        return Err(sp_blockchain::Error::MissingHeader(
            "Can't obtain domain block header for snap sync".to_string(),
        ));
    };

    let state_result = download_state(
        &domain_block_header,
        &sync_params.domain_client,
        sync_params.domain_fork_id,
        &sync_params.domain_network_service_handle,
        &sync_params.sync_service,
    )
    .await;

    trace!(target: LOG_TARGET, "State downloaded: {:?}", state_result);

    {
        let client = sync_params.domain_client.clone();
        // Import first block as finalized
        let mut block =
            BlockImportParams::new(BlockOrigin::NetworkInitialSync, domain_block_header);
        block.body = domain_block.body;
        block.justifications = domain_block.justifications;
        block.state_action = StateAction::ApplyChanges(StorageChanges::Import(state_result?));
        block.finalized = true;
        block.fork_choice = Some(ForkChoiceStrategy::Custom(true));
        client.as_ref().import_block(block).await.map_err(|error| {
            sp_blockchain::Error::Backend(format!("Failed to import state block: {error}"))
        })?;
    }

    trace!(
        target: LOG_TARGET,
        "Domain client info after waiting: {:?}",
        sync_params.domain_client.info()
    );

    // Verify domain state block creation.
    if let Ok(Some(created_domain_block_hash)) =
        sync_params.domain_client.hash(domain_block_number.into())
    {
        if created_domain_block_hash == domain_block_hash {
            trace!(
                target: LOG_TARGET,
                ?created_domain_block_hash,
                ?domain_block_hash,
                "Created hash matches after the domain block import with state",
            );
        } else {
            debug!(
                target: LOG_TARGET,
                ?created_domain_block_hash,
                ?domain_block_hash,
                "Created hash doesn't match after the domain block import with state",
            );

            return Err(sp_blockchain::Error::Backend(
                "Created hash doesn't match after the domain block import with state".to_string(),
            ));
        }
    } else {
        return Err(sp_blockchain::Error::Backend(
            "Can't obtain domain block hash after state importing for snap sync".to_string(),
        ));
    }

    crate::aux_schema::track_domain_hash_and_consensus_hash::<_, Block, CBlock>(
        &sync_params.domain_client,
        domain_block_hash,
        consensus_block_hash,
        // skip cleaning up finalized hash so that operator can pick after snap sync
        // and continue where snap sync left off
        false,
    )?;

    crate::aux_schema::write_execution_receipt::<_, Block, CBlock>(
        sync_params.domain_client.as_ref(),
        None,
        &last_confirmed_block_receipt,
        sync_params.challenge_period,
    )?;

    sync_params
        .consensus_chain_sync_params
        .snap_sync_orchestrator
        .mark_domain_snap_sync_finished();

    debug!(target: LOG_TARGET, info = ?sync_params.domain_client.info(), "Client info after successful domain snap sync.");

    // Unblock consensus block importing
    drop(consensus_target_block_acknowledgement_sender);
    drop(block_importing_notification_stream);

    Ok(())
}

/// Download and return state for specified block
async fn download_state<Block, Client>(
    header: &Block::Header,
    client: &Arc<Client>,
    fork_id: Option<String>,
    network_service_handle: &NetworkServiceHandle,
    sync_service: &SyncingService<Block>,
) -> Result<ImportedState<Block>, sp_blockchain::Error>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + ProofProvider<Block> + Send + Sync + 'static,
{
    let block_number = *header.number();

    const STATE_SYNC_RETRIES: u32 = 5;
    const LOOP_PAUSE: Duration = Duration::from_secs(20);
    const MAX_GET_PEERS_ATTEMPT_NUMBER: usize = 30;

    for attempt in 1..=STATE_SYNC_RETRIES {
        debug!(target: LOG_TARGET, %block_number, %attempt, "Starting state sync...");

        debug!(target: LOG_TARGET, %block_number, "Gathering peers for state sync.");
        let mut tried_peers = HashSet::<PeerId>::new();

        let current_peer_id = match get_currently_connected_peer(
            sync_service,
            &mut tried_peers,
            LOOP_PAUSE,
            MAX_GET_PEERS_ATTEMPT_NUMBER,
        )
        .instrument(tracing::info_span!("download state"))
        .await
        {
            Ok(peer_id) => peer_id,
            Err(err) => {
                debug!(?err, "Getting peers for state downloading failed");
                continue;
            }
        };
        tried_peers.insert(current_peer_id);

        let sync_engine = SnapSyncingEngine::<Block>::new(
            client.clone(),
            fork_id.as_deref(),
            header.clone(),
            false,
            (current_peer_id, block_number),
            network_service_handle,
        )?;

        let last_block_from_sync_result = sync_engine.download_state().await;

        match last_block_from_sync_result {
            Ok(block_to_import) => {
                debug!(target: LOG_TARGET, %block_number, "Sync worker handle result: {:?}", block_to_import);

                return block_to_import.state.ok_or_else(|| {
                    sp_blockchain::Error::Backend(
                        "Imported state was missing in synced block".into(),
                    )
                });
            }
            Err(error) => {
                error!(target: LOG_TARGET, %block_number, %error, "State sync error");
                continue;
            }
        }
    }

    Err(sp_blockchain::Error::Backend(
        "All snap sync retries failed".into(),
    ))
}

async fn get_currently_connected_peer<Block>(
    sync_service: &SyncingService<Block>,
    tried_peers: &mut HashSet<PeerId>,
    loop_pause: Duration,
    max_attempts: usize,
) -> Result<PeerId, sp_blockchain::Error>
where
    Block: BlockT,
{
    for current_attempt in 0..max_attempts {
        let all_connected_peers = sync_service
            .peers_info()
            .await
            .expect("Network service must be available.");

        debug!(
            target: LOG_TARGET,
            %current_attempt,
            ?all_connected_peers,
            "Connected peers"
        );

        let connected_full_peers = all_connected_peers
            .iter()
            .filter_map(|(peer_id, info)| (info.roles.is_full()).then_some(*peer_id))
            .collect::<Vec<_>>();

        debug!(
            target: LOG_TARGET,
            %current_attempt,
            ?tried_peers,
            "Sync peers: {:?}", connected_full_peers
        );

        let active_peers_set = HashSet::from_iter(connected_full_peers.into_iter());

        if let Some(peer_id) = active_peers_set.difference(tried_peers).next().cloned() {
            tried_peers.insert(peer_id);
            return Ok(peer_id);
        }

        sleep(loop_pause).await;
    }

    Err(sp_blockchain::Error::Backend("All retries failed".into()))
}
