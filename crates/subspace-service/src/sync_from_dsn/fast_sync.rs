use crate::sync_from_dsn::import_blocks::download_and_reconstruct_blocks;
use crate::sync_from_dsn::segment_header_downloader::SegmentHeaderDownloader;
use crate::sync_from_dsn::DsnSyncPieceGetter;
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sc_consensus::import_queue::ImportQueueService;
use sc_consensus::IncomingBlock;
use sc_consensus_subspace::archiver::{decode_block, SegmentHeadersStore};
use sc_consensus_subspace::block_import::ArchiverInitilizationData;
use sc_consensus_subspace::SubspaceLink;
use sc_network::{NetworkService, PeerId};
use sc_network_sync::fast_sync_engine::FastSyncingEngine;
use sc_network_sync::service::network::NetworkServiceProvider;
use sc_network_sync::SyncingService;
use sc_service::{ClientExt, Error, RawBlockData};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi};
use sp_objects::ObjectsApi;
use sp_runtime::generic::SignedBlock;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use sp_runtime::Justifications;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use subspace_archiving::reconstructor::Reconstructor;
use subspace_core_primitives::SegmentIndex;
use subspace_networking::Node;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, error};

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

pub(crate) struct FastSyncer<'a, PG, AS, Block, Client, IQS>
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
    subspace_link: SubspaceLink<Block>,
    fast_sync_state: Arc<parking_lot::Mutex<Option<NumberFor<Block>>>>,
    sync_service: Arc<SyncingService<Block>>,
}

impl<'a, PG, AS, Block, Client, IQS> FastSyncer<'a, PG, AS, Block, Client, IQS>
where
    PG: DsnSyncPieceGetter,
    AS: AuxStore + Send + Sync + 'static,
    Block: BlockT,
    Client: HeaderBackend<Block>
        + ClientExt<Block>
        + BlockBackend<Block>
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey> + ObjectsApi<Block>,
    IQS: ImportQueueService<Block> + ?Sized + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        segment_headers_store: &'a SegmentHeadersStore<AS>,
        node: &'a Node,
        piece_getter: &'a PG,
        client: Arc<Client>,
        import_queue_service: Arc<Mutex<Box<IQS>>>,
        network_service: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
        subspace_link: SubspaceLink<Block>,
        fast_sync_state: Arc<parking_lot::Mutex<Option<NumberFor<Block>>>>,
        sync_service: Arc<SyncingService<Block>>,
    ) -> Self {
        Self {
            segment_headers_store,
            node,
            piece_getter,
            client,
            import_queue_service,
            network_service,
            subspace_link,
            fast_sync_state,
            sync_service,
        }
    }

    /// Sync algorithm:
    /// - 1. download two last segments,
    /// - 2. add the last block the second last segment (as raw - without checks and execution),
    /// - 3. download the state for the first block of the last segment,
    ///     - a) add the first block of the last segment as raw,
    ///     - b) download state for it,
    /// - 4. add blocks with execution from the last segment (except the first block),
    ///     - a) init archiver using the second last segment header and the first block of the last segment,
    ///     - b) notify Substrate sync by importing block with using BlockOrigin::NetworkBroadcast,
    ///     - c) clear the block gap to prevent Substrate sync to download blocks from the start.
    ///     - d) update common blocks with connected peers.
    ///  Note: retry for fast sync will degrade reputation if we have already announced blocks
    pub(crate) async fn sync(&self) -> Result<FastSyncResult<Block>, Error> {
        // TODO: handle the edge case when the second last segment contains the whole last block
        debug!("Starting fast sync...");

        // 1. Download the last two segments.
        let mut reconstructor = Reconstructor::new().map_err(|error| error.to_string())?;
        let segment_header_downloader = SegmentHeaderDownloader::new(self.node);

        if let Err(error) = self
            .download_segment_headers(&segment_header_downloader)
            .await
        {
            error!(?error, "Failed to download segment headers.");
            return Err(error);
        };

        let Some(last_segment_index) = self.segment_headers_store.max_segment_index() else {
            return Err(Error::Other("Can't get last segment index.".into()));
        };

        // Skip the fast sync if we lack the minimum required segment number
        if last_segment_index == SegmentIndex::ZERO {
            return Ok(FastSyncResult::skipped());
        }

        let last_segment_header = self
            .segment_headers_store
            .get_segment_header(last_segment_index)
            .expect("We get segment index from the same storage. It should be present.");

        let second_last_segment_index = last_segment_header.segment_index() - 1.into();
        let second_last_segment_header = self
            .segment_headers_store
            .get_segment_header(second_last_segment_index)
            .expect("We get segment index from the same storage. It should be present.");

        let second_last_segment_blocks = download_and_reconstruct_blocks(
            second_last_segment_index,
            self.piece_getter,
            &mut reconstructor,
        )
        .await?;

        let blocks_in_second_last_segment = second_last_segment_blocks.len();

        if blocks_in_second_last_segment < 1 {
            return Err(Error::Other(
                "Unexpected block array length for the second last segment.".into(),
            ));
        }

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

        if blocks_in_last_segment < 2 {
            return Err(Error::Other(
                "Unexpected block array length for the last segment.".into(),
            ));
        }

        debug!(
            "Blocks downloaded (SegmentId={}): {}-{}",
            last_segment_index,
            blocks[0].0,
            blocks[blocks_in_last_segment - 1].0
        );

        // 2. Raw import the last block from the second last segment.

        let (last_block_number_from_second_segment, last_block_bytes_from_second_segment) =
            second_last_segment_blocks[blocks_in_second_last_segment - 1].clone();

        let (raw_block, _) = Self::create_raw_block(
            last_block_bytes_from_second_segment,
            last_block_number_from_second_segment.into(),
        )?;
        self.client.import_raw_block(raw_block.clone())?;

        debug!(
            hash = ?raw_block.hash,
            number = %last_block_number_from_second_segment,
            "Last raw block from the second last segment imported"
        );

        // 3. Download state for the first block of the last segment.

        let (second_last_block_number, _) = blocks[blocks_in_last_segment - 2].clone();
        let last_block = blocks[blocks_in_last_segment - 1].clone();
        let last_block_number = last_block.0;
        let last_block_bytes = last_block.1;

        // Raw import state block and download state.
        // 3.a)  add the first block of the last segment as raw

        // The state block is first block from the last segment.
        let state_block_bytes = blocks[0].1.clone();
        let state_block_number = blocks[0].0;

        let (raw_block, state_block) =
            Self::create_raw_block(state_block_bytes.clone(), state_block_number.into())?;

        self.client.import_raw_block(raw_block.clone())?;

        debug!(
            hash = ?raw_block.hash,
            number = %state_block_number,
            "Raw state block imported"
        );

        // 3.b) download state for it
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

        // Notify PoT verification about the last state block
        {
            self.fast_sync_state
                .lock()
                .replace(state_block_number.into());
        }

        // 4. Import and execute blocks from the last segment

        debug!("Started importing blocks from last segment.");

        for (block_number, block_bytes) in blocks.into_iter() {
            let current_block_number = NumberFor::<Block>::from(block_number);

            // 4.a) Initialize archiver and skip the first block.
            // We imported it previously as raw block.
            if current_block_number == state_block_number.into() {
                let notification_block = state_block.clone();
                self.subspace_link
                    .archiver_notification_sender()
                    .notify(move || ArchiverInitilizationData {
                        last_archived_block: (
                            second_last_segment_header,
                            notification_block.clone(),
                            Default::default(),
                        ),
                    });

                continue;
            }

            // Skip the last block import. We'll import it later with execution.
            if current_block_number == NumberFor::<Block>::from(last_block_number) {
                break;
            }

            self.import_deconstructed_block(
                block_bytes,
                current_block_number,
                BlockOrigin::NetworkInitialSync,
            )
            .await?;
        }

        // Block import delay
        // We wait to import for all the blocks from the segment except the last one
        self.wait_for_block_import(second_last_block_number.into())
            .await;

        // 4. Notify Substrate sync by importing block with using BlockOrigin::NetworkBroadcast

        debug!(
            "Importing the last block #{} from the segment #{last_segment_index}",
            last_block_number
        );

        // Update common blocks with connected peers.
        self.sync_service
            .new_best_number(second_last_block_number.into());

        // Import and execute the last block from the segment and setup the substrate sync
        self.import_deconstructed_block(
            last_block_bytes,
            last_block_number.into(),
            BlockOrigin::NetworkBroadcast,
        )
        .await?;

        // Clear the block gap to prevent Substrate sync to download blocks from the start.
        debug!("Clearing block gap...");
        self.client.clear_block_gap();

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

    async fn import_deconstructed_block(
        &self,
        block_bytes: Vec<u8>,
        block_number: NumberFor<Block>,
        block_origin: BlockOrigin,
    ) -> Result<(), Error> {
        let (header, extrinsics, justifications) = Self::deconstruct_block(block_bytes)?;
        let hash = header.hash();

        debug!(%block_number, ?block_origin, ?hash, "Importing block...");

        let incoming_block = IncomingBlock {
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
        };

        self.import_queue_service
            .lock()
            .await
            .import_blocks(block_origin, vec![incoming_block]);

        Ok(())
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

        for attempt in 1..=STATE_SYNC_RETRIES {
            debug!(%attempt, "Starting state sync...");

            debug!("Gathering peers for state sync.");
            let network_service = self.network_service.clone();
            let mut tried_peers = HashSet::<PeerId>::new();

            // TODO: add loop timeout
            let peer_candidates = loop {
                let open_peers = network_service
                    .open_peers()
                    .await
                    .expect("Network service must be available.");

                debug!(?tried_peers, "Sync peers: {}", open_peers.len());

                let active_peers_set = HashSet::from_iter(open_peers.into_iter());

                let diff = active_peers_set
                    .difference(&tried_peers)
                    .cloned()
                    .collect::<HashSet<_>>();

                if !diff.is_empty() {
                    break diff;
                }

                sleep(Duration::from_secs(20)).await; // TODO: customize period
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
                    self.wait_for_block_import(state_block_number).await;

                    debug!("Clearing block gap...");
                    self.client.clear_block_gap();

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
