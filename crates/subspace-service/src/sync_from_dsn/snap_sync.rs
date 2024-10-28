use crate::sync_from_dsn::import_blocks::download_and_reconstruct_blocks;
use crate::sync_from_dsn::segment_header_downloader::SegmentHeaderDownloader;
use crate::sync_from_dsn::snap_sync_engine::SnapSyncingEngine;
use crate::sync_from_dsn::DsnSyncPieceGetter;
use sc_client_api::{AuxStore, ProofProvider};
use sc_consensus::import_queue::ImportQueueService;
use sc_consensus::{
    BlockImport, BlockImportParams, ForkChoiceStrategy, ImportedState, IncomingBlock, StateAction,
    StorageChanges,
};
use sc_consensus_subspace::archiver::{decode_block, SegmentHeadersStore};
use sc_network::{NetworkBlock, PeerId};
use sc_network_sync::service::network::NetworkServiceHandle;
use sc_network_sync::SyncingService;
use sc_service::Error;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_consensus_subspace::SubspaceApi;
use sp_objects::ObjectsApi;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use subspace_archiving::reconstructor::Reconstructor;
use subspace_core_primitives::segments::SegmentIndex;
use subspace_core_primitives::{BlockNumber, PublicKey};
use subspace_erasure_coding::ErasureCoding;
use subspace_networking::Node;
use tokio::time::sleep;
use tracing::{debug, error};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn snap_sync<Block, AS, Client, PG>(
    segment_headers_store: SegmentHeadersStore<AS>,
    node: Node,
    fork_id: Option<String>,
    client: Arc<Client>,
    mut import_queue_service: Box<dyn ImportQueueService<Block>>,
    pause_sync: Arc<AtomicBool>,
    piece_getter: PG,
    sync_service: Arc<SyncingService<Block>>,
    network_service_handle: NetworkServiceHandle,
    erasure_coding: ErasureCoding,
) where
    Block: BlockT,
    AS: AuxStore,
    Client: HeaderBackend<Block>
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + BlockImport<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, PublicKey> + ObjectsApi<Block>,
    PG: DsnSyncPieceGetter,
{
    let info = client.info();
    // Only attempt snap sync with genesis state
    // TODO: Support snap sync from any state once
    //  https://github.com/paritytech/polkadot-sdk/issues/5366 is resolved
    if info.best_hash == info.genesis_hash {
        pause_sync.store(true, Ordering::Release);

        let snap_sync_fut = sync(
            &segment_headers_store,
            &node,
            &piece_getter,
            fork_id.as_deref(),
            &client,
            import_queue_service.as_mut(),
            &sync_service,
            &network_service_handle,
            None,
            &erasure_coding,
        );

        match snap_sync_fut.await {
            Ok(()) => {
                debug!("Snap sync finished successfully");
            }
            Err(error) => {
                error!(%error, "Snap sync failed");
            }
        }

        // This will notify Substrate's sync mechanism and allow regular Substrate sync to continue
        // gracefully
        {
            let info = client.info();
            sync_service.new_best_block_imported(info.best_hash, info.best_number);
        }
        pause_sync.store(false, Ordering::Release);
    } else {
        debug!("Snap sync can only work with genesis state, skipping");
    }
}

// Get blocks from the last segment or from the segment containing the target block.
// Returns encoded blocks collection and used segment index.
pub(crate) async fn get_blocks_from_target_segment<AS, PG>(
    segment_headers_store: &SegmentHeadersStore<AS>,
    node: &Node,
    piece_getter: &PG,
    target_block: Option<BlockNumber>,
    erasure_coding: &ErasureCoding,
) -> Result<Option<(SegmentIndex, VecDeque<(BlockNumber, Vec<u8>)>)>, Error>
where
    AS: AuxStore,
    PG: DsnSyncPieceGetter,
{
    sync_segment_headers(segment_headers_store, node)
        .await
        .map_err(|error| format!("Failed to sync segment headers: {}", error))?;

    let target_segment_index = {
        let last_segment_index = segment_headers_store
            .max_segment_index()
            .expect("Successfully synced above; qed");

        if let Some(target_block) = target_block {
            let mut segment_header = segment_headers_store
                .get_segment_header(last_segment_index)
                .ok_or(format!(
                    "Can't get segment header from the store: {last_segment_index}"
                ))?;

            if target_block > segment_header.last_archived_block().number {
                return Err(format!(
                    "Target block is greater than the last archived block. \
                    Last segment index = {last_segment_index}, target block = {target_block}, \
                    last block from the segment = {}
                    ",
                    segment_header.last_archived_block().number
                )
                .into());
            }

            let mut current_segment_index = last_segment_index;

            loop {
                if current_segment_index <= SegmentIndex::ONE {
                    break;
                }

                if target_block > segment_header.last_archived_block().number {
                    current_segment_index += SegmentIndex::ONE;
                    break;
                }

                current_segment_index -= SegmentIndex::ONE;

                segment_header = segment_headers_store
                    .get_segment_header(current_segment_index)
                    .ok_or(format!(
                        "Can't get segment header from the store: {last_segment_index}"
                    ))?;
            }

            current_segment_index
        } else {
            last_segment_index
        }
    };

    // We don't have the genesis state when we choose to snap sync.
    if target_segment_index <= SegmentIndex::ONE {
        error!(
            "Snap sync is impossible - not enough archived history: \
            wipe the DB folder and rerun with --sync=full"
        );
        return Err("Snap sync is impossible - not enough archived history".into());
    }

    // Identify all segment headers that would need to be reconstructed in order to get first
    // block of last segment header
    let mut segments_to_reconstruct = VecDeque::from([target_segment_index]);
    {
        let mut last_segment_first_block_number = None;

        loop {
            let oldest_segment_index = *segments_to_reconstruct.front().expect("Not empty; qed");
            let segment_index = oldest_segment_index
                .checked_sub(SegmentIndex::ONE)
                .ok_or_else(|| {
                    format!(
                        "Attempted to get segment index before {oldest_segment_index} during \
                            snap sync"
                    )
                })?;
            let segment_header = segment_headers_store
                .get_segment_header(segment_index)
                .ok_or_else(|| {
                    format!("Failed to get segment index {segment_index} during snap sync")
                })?;
            let last_archived_block = segment_header.last_archived_block();

            // If older segment header ends with fully archived block then no additional
            // information is necessary
            if last_archived_block.partial_archived().is_none() {
                break;
            }

            match last_segment_first_block_number {
                Some(block_number) => {
                    if block_number == last_archived_block.number {
                        // If older segment ends with the same block number as the first block
                        // in the last segment then add it to the list of segments that need to
                        // be reconstructed
                        segments_to_reconstruct.push_front(segment_index);
                    } else {
                        // Otherwise we're done here
                        break;
                    }
                }
                None => {
                    last_segment_first_block_number.replace(last_archived_block.number);
                    // This segment will definitely be needed to reconstruct first block of the
                    // last segment
                    segments_to_reconstruct.push_front(segment_index);
                }
            }
        }
    }

    // Reconstruct blocks of the last segment
    let mut blocks = VecDeque::new();
    {
        let reconstructor = Arc::new(Mutex::new(Reconstructor::new(erasure_coding.clone())));

        for segment_index in segments_to_reconstruct {
            let blocks_fut =
                download_and_reconstruct_blocks(segment_index, piece_getter, &reconstructor);

            blocks = VecDeque::from(blocks_fut.await?);
        }
    }

    Ok(Some((target_segment_index, blocks)))
}

#[allow(clippy::too_many_arguments)]
/// Synchronize the blockchain to the target_block (approximate value based on the containing
/// segment) or to the last archived block.
async fn sync<PG, AS, Block, Client, IQS>(
    segment_headers_store: &SegmentHeadersStore<AS>,
    node: &Node,
    piece_getter: &PG,
    fork_id: Option<&str>,
    client: &Arc<Client>,
    import_queue_service: &mut IQS,
    sync_service: &SyncingService<Block>,
    network_service_handle: &NetworkServiceHandle,
    target_block: Option<BlockNumber>,
    erasure_coding: &ErasureCoding,
) -> Result<(), Error>
where
    PG: DsnSyncPieceGetter,
    AS: AuxStore,
    Block: BlockT,
    Client: HeaderBackend<Block>
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + BlockImport<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, PublicKey> + ObjectsApi<Block>,
    IQS: ImportQueueService<Block> + ?Sized,
{
    debug!("Starting snap sync...");

    let Some((target_segment_index, mut blocks)) = get_blocks_from_target_segment(
        segment_headers_store,
        node,
        piece_getter,
        target_block,
        erasure_coding,
    )
    .await?
    else {
        // Snap-sync skipped
        return Ok(());
    };

    debug!(
        "Segments data received. Target segment index: {:?}",
        target_segment_index
    );

    let mut blocks_to_import = Vec::with_capacity(blocks.len().saturating_sub(1));
    let last_block_number;

    // First block is special because we need to download state for it
    {
        let (first_block_number, first_block_bytes) = blocks
            .pop_front()
            .expect("List of blocks is not empty according to logic above; qed");

        // Sometimes first block is the only block
        last_block_number = blocks
            .back()
            .map_or(first_block_number, |(block_number, _block_bytes)| {
                *block_number
            });

        debug!(
            %target_segment_index,
            %first_block_number,
            %last_block_number,
            "Blocks from target segment downloaded"
        );

        let signed_block = decode_block::<Block>(&first_block_bytes)
            .map_err(|error| format!("Failed to decode archived block: {error}"))?;
        drop(first_block_bytes);
        let (header, extrinsics) = signed_block.block.deconstruct();

        // Download state for the first block, so it can be imported even without doing execution
        let state = download_state(
            &header,
            client,
            fork_id,
            sync_service,
            network_service_handle,
        )
        .await
        .map_err(|error| {
            format!("Failed to download state for the first block of target segment: {error}")
        })?;

        debug!("Downloaded state of the first block of the target segment");

        // Import first block as finalized
        let mut block = BlockImportParams::new(BlockOrigin::NetworkInitialSync, header);
        block.body.replace(extrinsics);
        block.justifications = signed_block.justifications;
        block.state_action = StateAction::ApplyChanges(StorageChanges::Import(state));
        block.finalized = true;
        block.create_gap = false;
        block.fork_choice = Some(ForkChoiceStrategy::Custom(true));
        client
            .import_block(block)
            .await
            .map_err(|error| format!("Failed to import first block of target segment: {error}"))?;
    }

    debug!(
        blocks_count = %blocks.len(),
        "Queuing importing remaining blocks from target segment"
    );

    for (_block_number, block_bytes) in blocks {
        let signed_block = decode_block::<Block>(&block_bytes)
            .map_err(|error| format!("Failed to decode archived block: {error}"))?;
        let (header, extrinsics) = signed_block.block.deconstruct();

        blocks_to_import.push(IncomingBlock {
            hash: header.hash(),
            header: Some(header),
            body: Some(extrinsics),
            indexed_body: None,
            justifications: signed_block.justifications,
            origin: None,
            allow_missing_state: false,
            import_existing: false,
            skip_execution: false,
            state: None,
        });
    }

    if !blocks_to_import.is_empty() {
        import_queue_service.import_blocks(BlockOrigin::NetworkInitialSync, blocks_to_import);
    }

    // Wait for blocks to be imported
    // TODO: Replace this hack with actual watching of block import
    wait_for_block_import(client.as_ref(), last_block_number.into()).await;

    debug!(info = ?client.info(), "Snap sync finished successfully");

    Ok(())
}

async fn wait_for_block_import<Block, Client>(
    client: &Client,
    waiting_block_number: NumberFor<Block>,
) where
    Block: BlockT,
    Client: HeaderBackend<Block>,
{
    const WAIT_DURATION: Duration = Duration::from_secs(5);
    const MAX_NO_NEW_IMPORT_ITERATIONS: u32 = 10;
    let mut current_iteration = 0;
    let mut last_best_block_number = client.info().best_number;
    loop {
        let info = client.info();
        debug!(%current_iteration, %waiting_block_number, "Waiting client info: {:?}", info);

        tokio::time::sleep(WAIT_DURATION).await;

        if info.best_number >= waiting_block_number {
            break;
        }

        if last_best_block_number == info.best_number {
            current_iteration += 1;
        } else {
            current_iteration = 0;
        }

        if current_iteration >= MAX_NO_NEW_IMPORT_ITERATIONS {
            debug!(%current_iteration, %waiting_block_number, "Max idle period reached. {:?}", info);
            break;
        }

        last_best_block_number = info.best_number;
    }
}

async fn sync_segment_headers<AS>(
    segment_headers_store: &SegmentHeadersStore<AS>,
    node: &Node,
) -> Result<(), Error>
where
    AS: AuxStore,
{
    let last_segment_header = segment_headers_store.last_segment_header().ok_or_else(|| {
        Error::Other(
            "Archiver needs to be initialized before syncing from DSN to populate the very first \
            segment"
                .to_string(),
        )
    })?;
    let new_segment_headers = SegmentHeaderDownloader::new(node)
        .get_segment_headers(&last_segment_header)
        .await
        .map_err(|error| error.to_string())?;

    debug!("Found {} new segment headers", new_segment_headers.len());

    if !new_segment_headers.is_empty() {
        segment_headers_store.add_segment_headers(&new_segment_headers)?;
    }

    Ok(())
}

/// Download and return state for specified block
async fn download_state<Block, Client>(
    header: &Block::Header,
    client: &Arc<Client>,
    fork_id: Option<&str>,
    sync_service: &SyncingService<Block>,
    network_service_handle: &NetworkServiceHandle,
) -> Result<ImportedState<Block>, Error>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + ProofProvider<Block> + Send + Sync + 'static,
{
    let block_number = *header.number();

    const STATE_SYNC_RETRIES: u32 = 5;
    const LOOP_PAUSE: Duration = Duration::from_secs(20);

    for attempt in 1..=STATE_SYNC_RETRIES {
        debug!(%attempt, "Starting state sync...");

        debug!("Gathering peers for state sync.");
        let mut tried_peers = HashSet::<PeerId>::new();

        // TODO: add loop timeout
        let current_peer_id = loop {
            let connected_full_peers = sync_service
                .peers_info()
                .await
                .expect("Network service must be available.")
                .iter()
                .filter_map(|(peer_id, info)| {
                    (info.roles.is_full() && info.best_number > block_number).then_some(*peer_id)
                })
                .collect::<Vec<_>>();

            debug!(?tried_peers, "Sync peers: {}", connected_full_peers.len());

            let active_peers_set = HashSet::from_iter(connected_full_peers.into_iter());

            if let Some(peer_id) = active_peers_set.difference(&tried_peers).next().cloned() {
                break peer_id;
            }

            sleep(LOOP_PAUSE).await;
        };

        tried_peers.insert(current_peer_id);

        let sync_engine = SnapSyncingEngine::<Block>::new(
            client.clone(),
            fork_id,
            header.clone(),
            false,
            (current_peer_id, block_number),
            network_service_handle,
        )
        .map_err(Error::Client)?;

        let last_block_from_sync_result = sync_engine.download_state().await;

        match last_block_from_sync_result {
            Ok(block_to_import) => {
                debug!("Sync worker handle result: {:?}", block_to_import);

                return block_to_import.state.ok_or_else(|| {
                    Error::Other("Imported state was missing in synced block".into())
                });
            }
            Err(error) => {
                error!(%error, "State sync error");
                continue;
            }
        }
    }

    Err(Error::Other("All snap sync retries failed".into()))
}
