use crate::sync_from_dsn::fast_sync_engine::FastSyncingEngine;
use crate::sync_from_dsn::import_blocks::download_and_reconstruct_blocks;
use crate::sync_from_dsn::raw_block_import::{import_raw_block, RawBlockData};
use crate::sync_from_dsn::segment_header_downloader::SegmentHeaderDownloader;
use crate::sync_from_dsn::DsnSyncPieceGetter;
use sc_client_api::{AuxStore, BlockBackend, LockImportRun, ProofProvider};
use sc_consensus::import_queue::ImportQueueService;
use sc_consensus::IncomingBlock;
use sc_consensus_subspace::archiver::{decode_block, SegmentHeadersStore};
use sc_network::{NetworkService, PeerId};
use sc_network_sync::service::network::NetworkServiceProvider;
use sc_network_sync::service::syncing_service::SyncRestartArgs;
use sc_network_sync::SyncingService;
use sc_service::config::SyncMode;
use sc_service::{ClientExt, Error};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi};
use sp_objects::ObjectsApi;
use sp_runtime::generic::SignedBlock;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use sp_runtime::Justifications;
use std::collections::HashSet;
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

// TODO: remove unused fields if DSN-sync is not related to fast-sync.
#[allow(dead_code)]
pub(crate) struct FastSyncResult<Block: BlockT> {
    pub(crate) last_imported_block_number: NumberFor<Block>,
    pub(crate) last_imported_segment_index: SegmentIndex,
    pub(crate) reconstructor: Reconstructor,
    /// Fast sync was skipped (possible reason - not enough archived segments).
    pub(crate) skipped: bool,
}

impl<Block: BlockT> FastSyncResult<Block> {
    fn skipped() -> Self {
        Self {
            skipped: true,
            reconstructor: Reconstructor::new().expect("Default initialization works."),
            last_imported_block_number: Default::default(),
            last_imported_segment_index: Default::default(),
        }
    }
}

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
            Ok(fast_sync_result) => {
                if fast_sync_result.skipped {
                    debug!("Fast sync was skipped.");
                }
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

    // TODO: Fix this implementation to actually follow the spec
    /// Sync algorithm:
    /// - 1. download two last segments,
    /// - 2. add the last block the second last segment (as raw - without checks and execution),
    /// - 3. download the state for the first block of the last segment,
    ///     - add the first block of the last segment as raw,
    ///     - download state for it,
    /// - 4. add blocks with execution from the last segment,
    ///     - notify Substrate sync by importing block with using BlockOrigin::NetworkBroadcast,
    ///     - clear the block gap to prevent Substrate sync to download blocks from the start.
    ///     - restart the Substrate sync with SyncMode::Full to enable it downloading full blocks.
    ///  Note: retry for fast sync will degrade reputation if we have already announced blocks.
    // TODO: fast-sync specification contains a special case for a segment that have the
    // complete last archived block, this will remove the necessity to download the second last
    // segment, we need to implement this case when the blockchain will contain at least one such
    // a segment to verify the solution.
    pub(crate) async fn sync(&self) -> Result<FastSyncResult<Block>, Error> {
        debug!("Starting fast sync...");

        // 1. Download the last two segments.
        let mut reconstructor = Reconstructor::new().map_err(|error| error.to_string())?;
        let segment_header_downloader = SegmentHeaderDownloader::new(self.node);

        if let Err(error) = self
            .download_segment_headers(&segment_header_downloader)
            .await
        {
            let error = format!("Failed to download segment headers: {}", error);
            return Err(Error::Other(error));
        };

        let Some(last_segment_index) = self.segment_headers_store.max_segment_index() else {
            return Err(Error::Other("Can't get last segment index.".into()));
        };

        // Skip the fast sync if we lack the minimum required segment number
        if last_segment_index <= SegmentIndex::ONE {
            return Ok(FastSyncResult::skipped());
        }

        let last_segment_header = self
            .segment_headers_store
            .get_segment_header(last_segment_index)
            .expect("Last segment index exists; qed");

        let second_last_segment_index = last_segment_header.segment_index() - SegmentIndex::ONE;

        let second_last_segment_blocks = download_and_reconstruct_blocks(
            second_last_segment_index,
            self.piece_getter,
            &mut reconstructor,
        )
        .await?;

        let blocks_in_second_last_segment = second_last_segment_blocks.len();
        debug!(
            "Second last segment blocks downloaded (SegmentId={}): {}-{}",
            second_last_segment_index,
            second_last_segment_blocks[0].0,
            second_last_segment_blocks[blocks_in_second_last_segment - 1].0
        );

        let blocks = download_and_reconstruct_blocks(
            last_segment_header.segment_index(),
            self.piece_getter,
            &mut reconstructor,
        )
        .await?;

        let blocks_in_last_segment = blocks.len();
        debug!(
            "Blocks downloaded (SegmentId={}): {}-{}",
            last_segment_index,
            blocks[0].0,
            blocks[blocks_in_last_segment - 1].0
        );

        // 2. Raw import the last block from the second last segment.

        // 3. Download state for the first block of the last segment.

        let (second_last_block_number, _) = blocks[blocks_in_last_segment - 2].clone();
        let last_block = blocks[blocks_in_last_segment - 1].clone();
        let last_block_number = last_block.0;

        // Raw import state block and download state.
        // Add the first block of the last segment as raw

        // The state block is first block from the last segment.
        let state_block_bytes = blocks[0].1.clone();
        let state_block_number = blocks[0].0;

        let (raw_block, _) =
            Self::create_raw_block(state_block_bytes.clone(), state_block_number.into())?;

        import_raw_block(self.client.as_ref(), raw_block.clone())?;

        debug!(
            hash = ?raw_block.hash,
            number = %state_block_number,
            "Raw state block imported"
        );

        // Download state for the target block.
        let download_state_result = self
            .download_state(state_block_bytes, state_block_number.into())
            .await;

        match download_state_result {
            Ok(Some(state_block)) => {
                if let Some(state_block_header) = state_block.header {
                    if *state_block_header.number() != NumberFor::<Block>::from(state_block_number)
                    {
                        error!(
                            expected = %state_block_number,
                            actual = %*state_block_header.number(),
                            "Download state operation returned invalid state block."
                        );
                        return Err(Error::Other(
                            "Download state operation returned invalid state block.".into(),
                        ));
                    }
                } else {
                    error!("Download state operation returned empty state block header.");
                    return Err(Error::Other(
                        "Download state operation returned empty state block header.".into(),
                    ));
                }
            }
            Ok(None) => {
                error!("Download state operation returned empty result.");
                return Err(Error::Other(
                    "Download state operation returned empty result.".into(),
                ));
            }
            Err(err) => {
                error!(?err, "Download state operation failed.");
                return Err(err);
            }
        };

        // 4. Import and execute blocks from the last segment

        debug!("Started importing blocks from last segment.");

        let mut blocks_to_import = blocks
            .into_iter()
            .map(|(_block_number, block_bytes)| {
                let (header, extrinsics, justifications) = Self::deconstruct_block(block_bytes)?;

                Ok(IncomingBlock {
                    hash: header.hash(),
                    header: Some(header),
                    body: Some(extrinsics),
                    indexed_body: None,
                    justifications,
                    origin: None,
                    allow_missing_state: false,
                    import_existing: false,
                    skip_execution: false,
                    state: None,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let block_to_import = blocks_to_import
            .pop()
            .expect("At least one block is present; qed");

        if !blocks_to_import.is_empty() {
            self.import_queue_service
                .lock()
                .await
                .import_blocks(BlockOrigin::NetworkInitialSync, blocks_to_import);
        }

        // Block import delay
        // We wait to import for all the blocks from the segment except the last one
        // TODO: Replace this hack with actual watching of block import
        self.wait_for_block_import(second_last_block_number.into())
            .await;

        // Notify Substrate sync by importing block with using BlockOrigin::NetworkBroadcast

        debug!(
            "Importing the last block #{} from the segment #{last_segment_index}",
            last_block_number
        );

        // Import and execute the last block from the segment and setup the substrate sync
        self.import_queue_service
            .lock()
            .await
            .import_blocks(BlockOrigin::NetworkBroadcast, vec![block_to_import]);

        // Block import delay
        // We wait to import for all the blocks from the segment except the last one
        // TODO: Replace this hack with actual watching of block import
        self.wait_for_block_import(last_block_number.into()).await;

        // Clear the block gap to prevent Substrate sync to download blocks from the start.
        debug!("Clearing block gap...");
        self.client.clear_block_gap();

        self.sync_service
            .restart(SyncRestartArgs {
                sync_mode: SyncMode::Full,
                new_best_block: Some(last_block_number.into()),
            })
            .await;

        let info = self.client.info();
        debug!("Fast sync. Current client info: {:?}", info);

        Ok(FastSyncResult::<Block> {
            skipped: false,
            last_imported_block_number: last_block_number.into(),
            last_imported_segment_index: last_segment_index,
            reconstructor,
        })
    }

    async fn wait_for_block_import(&self, waiting_block_number: NumberFor<Block>) {
        const WAIT_DURATION: Duration = Duration::from_secs(5);
        const MAX_NO_NEW_IMPORT_ITERATIONS: i32 = 10;
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

    async fn download_segment_headers(
        &self,
        segment_header_downloader: &SegmentHeaderDownloader<'_>,
    ) -> Result<(), Error>
    where
        AS: AuxStore + Send + Sync + 'static,
    {
        let max_segment_index =
            self.segment_headers_store
                .max_segment_index()
                .ok_or_else(|| {
                    Error::Other(
                "Archiver needs to be initialized before syncing from DSN to populate the very \
                    first segment"
                    .to_string(),
            )
                })?;
        let new_segment_headers = segment_header_downloader
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

    fn create_raw_block(
        block_bytes: Vec<u8>,
        block_number: NumberFor<Block>,
    ) -> Result<(RawBlockData<Block>, SignedBlock<Block>), Error> {
        let signed_block =
            decode_block::<Block>(&block_bytes).map_err(|error| error.to_string())?;

        let SignedBlock {
            block,
            justifications,
        } = signed_block.clone();
        let (header, extrinsics) = block.deconstruct();
        let hash = header.hash();

        debug!(
            ?hash,
            parent_hash=?header.parent_hash(),
            "Reconstructed block #{} for raw block import", block_number
        );

        Ok((
            RawBlockData {
                hash,
                header,
                block_body: Some(extrinsics),
                justifications,
            },
            signed_block,
        ))
    }

    #[allow(clippy::type_complexity)]
    fn deconstruct_block(
        block_data: Vec<u8>,
    ) -> Result<(Block::Header, Vec<Block::Extrinsic>, Option<Justifications>), Error> {
        let signed_block = decode_block::<Block>(&block_data).map_err(|error| error.to_string())?;

        let SignedBlock {
            block,
            justifications,
        } = signed_block;
        let (header, extrinsics) = block.deconstruct();

        Ok((header, extrinsics, justifications))
    }

    async fn download_state(
        &self,
        state_block_bytes: Vec<u8>,
        state_block_number: NumberFor<Block>,
    ) -> Result<Option<IncomingBlock<Block>>, sc_service::Error> {
        let (header, extrinsics, justifications) = Self::deconstruct_block(state_block_bytes)?;

        const STATE_SYNC_RETRIES: u32 = 5;
        const LOOP_PAUSE: Duration = Duration::from_secs(20);

        for attempt in 1..=STATE_SYNC_RETRIES {
            debug!(%attempt, "Starting state sync...");

            debug!("Gathering peers for state sync.");
            let network_service = self.network_service.clone();
            let mut tried_peers = HashSet::<PeerId>::new();

            // TODO: add loop timeout
            let peer_candidates = loop {
                let connected_full_peers = self
                    .sync_service
                    .peers_info()
                    .await
                    .expect("Network service must be available.")
                    .iter()
                    .filter_map(|(peer_id, info)| {
                        (info.roles.is_full() && info.best_number > state_block_number)
                            .then_some(*peer_id)
                    })
                    .collect::<Vec<_>>();

                debug!(?tried_peers, "Sync peers: {}", connected_full_peers.len());

                let active_peers_set = HashSet::from_iter(connected_full_peers.into_iter());

                let diff = active_peers_set
                    .difference(&tried_peers)
                    .cloned()
                    .collect::<HashSet<_>>();

                if !diff.is_empty() {
                    break diff;
                }

                sleep(LOOP_PAUSE).await;
            };

            let current_peer_id = peer_candidates
                .into_iter()
                .next()
                .expect("Length is checked within the loop.");
            tried_peers.insert(current_peer_id);

            let (network_service_worker, network_service_handle) = NetworkServiceProvider::new();

            let networking_fut = network_service_worker.run(network_service);

            let (sync_worker, sync_engine) = FastSyncingEngine::<Block, IQS>::new(
                self.client.clone(),
                self.import_queue_service.clone(),
                network_service_handle,
                None,
                header.clone(),
                Some(extrinsics.clone()),
                justifications.clone(),
                true,
                (current_peer_id, state_block_number),
            )
            .map_err(Error::Client)?;

            let sync_fut = sync_worker.run();

            let net_fut = tokio::spawn(networking_fut);
            let sync_worker_fut = tokio::spawn(sync_fut);

            // Start syncing..
            let _ = sync_engine.start().await;
            let last_block_from_sync_result = sync_worker_fut.await;

            net_fut.abort();

            match last_block_from_sync_result {
                Ok(Ok(last_block_from_sync)) => {
                    debug!("Sync worker handle result: {:?}", last_block_from_sync,);

                    // State block import delay
                    // TODO: Replace this hack with actual watching of block import
                    self.wait_for_block_import(state_block_number).await;

                    return Ok(last_block_from_sync);
                }
                Ok(Err(error)) => {
                    error!(?error, "State sync error.");
                    continue;
                }
                Err(error) => {
                    error!(?error, "State sync error.");
                    continue;
                }
            }
        }

        Err(Error::Other("All fast sync retries failed.".into()))
    }
}