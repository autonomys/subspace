use crate::sync_from_dsn::fast_sync_engine::FastSyncingEngine;
use crate::sync_from_dsn::import_blocks::download_and_reconstruct_blocks;
use crate::sync_from_dsn::segment_header_downloader::SegmentHeaderDownloader;
use crate::sync_from_dsn::DsnSyncPieceGetter;
use sc_client_api::{AuxStore, BlockBackend, LockImportRun, ProofProvider};
use sc_consensus::import_queue::ImportQueueService;
use sc_consensus::{
    BlockImportParams, ForkChoiceStrategy, ImportedState, IncomingBlock, StateAction,
    StorageChanges,
};
use sc_consensus_subspace::archiver::{decode_block, SegmentHeadersStore};
use sc_network::{NetworkService, PeerId};
use sc_network_sync::service::syncing_service::SyncRestartArgs;
use sc_network_sync::SyncingService;
use sc_service::config::SyncMode;
use sc_service::{ClientExt, Error};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi};
use sp_objects::ObjectsApi;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use std::collections::{HashSet, VecDeque};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use subspace_archiving::reconstructor::Reconstructor;
use subspace_core_primitives::SegmentIndex;
use subspace_networking::Node;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, error};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn fast_sync<Backend, Block, AS, IQS, Client, PG>(
    segment_headers_store: SegmentHeadersStore<AS>,
    node: Node,
    client: Arc<Client>,
    import_queue_service: Box<IQS>,
    pause_sync: Arc<AtomicBool>,
    piece_getter: PG,
    network_service: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
    sync_service: Arc<SyncingService<Block>>,
) where
    Backend: sc_client_api::Backend<Block>,
    Block: BlockT,
    AS: AuxStore + Send + Sync + 'static,
    IQS: ImportQueueService<Block> + 'static + ?Sized,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + ClientExt<Block, Backend>
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + LockImportRun<Block, Backend>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey> + ObjectsApi<Block>,
    PG: DsnSyncPieceGetter,
{
    pause_sync.store(true, Ordering::Release);

    let finalized_hash_exists = client.info().finalized_hash != client.info().genesis_hash;
    if !finalized_hash_exists {
        let fast_syncer = FastSyncer::new(
            &segment_headers_store,
            &node,
            &piece_getter,
            client.clone(),
            import_queue_service,
            network_service.clone(),
            sync_service,
        );

        let fast_sync_result = fast_syncer.sync().await;

        match fast_sync_result {
            Ok(()) => {
                debug!("Fast sync finished successfully");
            }
            Err(err) => {
                error!("Fast sync failed: {err}");
            }
        }
    } else {
        debug!("Fast sync detected existing finalized hash.");
    }

    pause_sync.store(false, Ordering::Release);
}

struct FastSyncer<'a, PG, AS, Block, Client, IQS, B>
where
    Block: BlockT,
    IQS: ?Sized,
{
    segment_headers_store: &'a SegmentHeadersStore<AS>,
    node: &'a Node,
    piece_getter: &'a PG,
    client: Arc<Client>,
    import_queue_service: Arc<Mutex<Box<IQS>>>,
    network_service: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
    sync_service: Arc<SyncingService<Block>>,
    _marker: PhantomData<B>,
}

impl<'a, PG, AS, Block, Client, IQS, B> FastSyncer<'a, PG, AS, Block, Client, IQS, B>
where
    B: sc_client_api::Backend<Block>,
    PG: DsnSyncPieceGetter,
    AS: AuxStore + Send + Sync + 'static,
    Block: BlockT,
    Client: HeaderBackend<Block>
        + ClientExt<Block, B>
        + BlockBackend<Block>
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + LockImportRun<Block, B>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey> + ObjectsApi<Block>,
    IQS: ImportQueueService<Block> + 'static + ?Sized,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        segment_headers_store: &'a SegmentHeadersStore<AS>,
        node: &'a Node,
        piece_getter: &'a PG,
        client: Arc<Client>,
        import_queue_service: Box<IQS>,
        network_service: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
        sync_service: Arc<SyncingService<Block>>,
    ) -> Self {
        Self {
            segment_headers_store,
            node,
            piece_getter,
            client,
            import_queue_service: Arc::new(Mutex::new(import_queue_service)),
            network_service,
            sync_service,
            _marker: PhantomData,
        }
    }

    pub(crate) async fn sync(&self) -> Result<(), Error> {
        debug!("Starting fast sync...");

        self.sync_segment_headers()
            .await
            .map_err(|error| format!("Failed to sync segment headers: {}", error))?;

        let last_segment_index = self
            .segment_headers_store
            .max_segment_index()
            .expect("Successfully synced above; qed");

        // Skip the fast sync if there is just one segment header built on top of genesis, it is
        // more efficient to sync it regularly
        if last_segment_index <= SegmentIndex::ONE {
            debug!("Fast sync was skipped due to too early chain history");

            return Ok(());
        }

        // Identify all segment headers that would need to be reconstructed in order to get first
        // block of last segment header
        let mut segments_to_reconstruct = VecDeque::from([last_segment_index]);
        {
            let mut last_segment_first_block_number = None;

            loop {
                let oldest_segment_index =
                    *segments_to_reconstruct.front().expect("Not empty; qed");
                let segment_index = oldest_segment_index
                    .checked_sub(SegmentIndex::ONE)
                    .ok_or_else(|| {
                        format!(
                            "Attempted to get segment index before {oldest_segment_index} during \
                            fast sync"
                        )
                    })?;
                let segment_header = self
                    .segment_headers_store
                    .get_segment_header(segment_index)
                    .ok_or_else(|| {
                        format!("Failed to get segment index {segment_index} during fast sync")
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
            let mut reconstructor = Reconstructor::new().map_err(|error| error.to_string())?;

            for segment_index in segments_to_reconstruct {
                let blocks_fut = download_and_reconstruct_blocks(
                    segment_index,
                    self.piece_getter,
                    &mut reconstructor,
                );

                blocks = VecDeque::from(blocks_fut.await?);
            }
        }

        let (first_block_number, first_block_bytes) = blocks
            .pop_front()
            // TODO: Ensure this expectation actually holds, currently this is not guaranteed
            .expect("List of blocks is not empty according to logic above; qed");

        // Sometimes first block is the last block
        let last_block_number = blocks
            .back()
            .map_or(first_block_number, |(block_number, _block_bytes)| {
                *block_number
            });

        debug!(
            %last_segment_index,
            %first_block_number,
            %last_block_number,
            "Blocks from last segment downloaded"
        );

        let signed_block = decode_block::<Block>(&first_block_bytes)
            .map_err(|error| format!("Failed to decode archived block: {error}"))?;
        drop(first_block_bytes);
        let (header, extrinsics) = signed_block.block.deconstruct();

        // Download state for the first block, so it can be imported even without doing execution
        let first_block_state = self.download_state(&header).await.map_err(|error| {
            format!("Failed to download state for the first block of last segment: {error}")
        })?;

        debug!("Downloaded state of the first block of the last segment");

        let mut import_block = BlockImportParams::new(
            // In case there is just one block we need to notify Substrate sync about it
            if blocks.is_empty() {
                BlockOrigin::NetworkBroadcast
            } else {
                BlockOrigin::NetworkInitialSync
            },
            header,
        );
        import_block.justifications = signed_block.justifications;
        import_block.body = Some(extrinsics);
        import_block.state_action = StateAction::Skip;
        import_block.finalized = true;
        import_block.fork_choice = Some(ForkChoiceStrategy::LongestChain);

        // Raw import of the first block in the last segment
        let result = self
            .client
            .lock_import_and_run(|operation| {
                self.client.apply_block(
                    operation,
                    import_block,
                    Some(StorageChanges::Import(first_block_state)),
                )
            })
            .map_err(|e| {
                error!("Error during importing of the raw block: {}", e);
                sp_consensus::Error::ClientImport(e.to_string())
            })?;

        debug!(
            %first_block_number,
            ?result,
            "Raw block imported, clearing block gap"
        );

        // Clear the block gap that arises from above block import of the block with a much higher
        // number than previously
        self.client.clear_block_gap();

        debug!(
            blocks_count = %blocks.len(),
            "Started importing remaining blocks from last segment"
        );

        let mut blocks_to_import = blocks
            .into_iter()
            .map(|(_block_number, block_bytes)| {
                let signed_block = decode_block::<Block>(&block_bytes)
                    .map_err(|error| format!("Failed to decode archived block: {error}"))?;
                let (header, extrinsics) = signed_block.block.deconstruct();

                Ok(IncomingBlock {
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
                })
            })
            .collect::<Result<Vec<IncomingBlock<Block>>, Error>>()?;

        let maybe_last_block_to_import = blocks_to_import.pop();

        if !blocks_to_import.is_empty() {
            self.import_queue_service
                .lock()
                .await
                .import_blocks(BlockOrigin::NetworkInitialSync, blocks_to_import);
        }

        // Import last block (if there was more than one) and notify Substrate sync about it
        if let Some(last_block_to_import) = maybe_last_block_to_import {
            debug!(
                %last_block_number,
                %last_segment_index,
                "Importing the last block from the last segment"
            );

            self.import_queue_service
                .lock()
                .await
                .import_blocks(BlockOrigin::NetworkBroadcast, vec![last_block_to_import]);
        }

        // Wait for blocks to be imported
        // TODO: Replace this hack with actual watching of block import
        self.wait_for_block_import(last_block_number.into()).await;

        // Switch back to full sync mode
        self.sync_service
            .restart(SyncRestartArgs {
                sync_mode: SyncMode::Full,
                new_best_block: Some(last_block_number.into()),
            })
            .await;

        let info = self.client.info();
        debug!("Fast sync. Current client info: {:?}", info);

        Ok(())
    }

    async fn wait_for_block_import(&self, waiting_block_number: NumberFor<Block>) {
        const WAIT_DURATION: Duration = Duration::from_secs(5);
        const MAX_NO_NEW_IMPORT_ITERATIONS: u32 = 10;
        let mut current_iteration = 0;
        let mut last_best_block_number = self.client.info().best_number;
        loop {
            let info = self.client.info();
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

    async fn sync_segment_headers(&self) -> Result<(), Error>
    where
        AS: AuxStore + Send + Sync + 'static,
    {
        let max_segment_index =
            self.segment_headers_store
                .max_segment_index()
                .ok_or_else(|| {
                    Error::Other(
                        "Archiver needs to be initialized before syncing from DSN to populate the \
                        very first segment"
                            .to_string(),
                    )
                })?;
        let new_segment_headers = SegmentHeaderDownloader::new(self.node)
            .get_segment_headers(max_segment_index)
            .await
            .map_err(|error| error.to_string())?;

        debug!("Found {} new segment headers", new_segment_headers.len());

        if !new_segment_headers.is_empty() {
            self.segment_headers_store
                .add_segment_headers(&new_segment_headers)?;
        }

        Ok(())
    }

    /// Download and return state for specified block
    async fn download_state(&self, header: &Block::Header) -> Result<ImportedState<Block>, Error> {
        let block_number = *header.number();

        const STATE_SYNC_RETRIES: u32 = 5;
        const LOOP_PAUSE: Duration = Duration::from_secs(20);

        for attempt in 1..=STATE_SYNC_RETRIES {
            debug!(%attempt, "Starting state sync...");

            debug!("Gathering peers for state sync.");
            let network_service = self.network_service.clone();
            let mut tried_peers = HashSet::<PeerId>::new();

            // TODO: add loop timeout
            let current_peer_id = loop {
                let connected_full_peers = self
                    .sync_service
                    .peers_info()
                    .await
                    .expect("Network service must be available.")
                    .iter()
                    .filter_map(|(peer_id, info)| {
                        (info.roles.is_full() && info.best_number > block_number)
                            .then_some(*peer_id)
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

            let sync_engine = FastSyncingEngine::<Block, IQS>::new(
                self.client.clone(),
                self.import_queue_service.clone(),
                None,
                header.clone(),
                // We only care about the state, this value is just forwarded back into block to
                // import that is thrown away below
                None,
                // We only care about the state, this value is just forwarded back into block to
                // import that is thrown away below
                None,
                false,
                (current_peer_id, block_number),
                network_service,
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

        Err(Error::Other("All fast sync retries failed".into()))
    }
}
