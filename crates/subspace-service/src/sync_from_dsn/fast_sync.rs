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
use tracing::{error, info};

pub(crate) struct FastSyncResult<Block: BlockT> {
    pub(crate) last_imported_block_number: NumberFor<Block>,
    pub(crate) last_imported_segment_index: SegmentIndex,
    pub(crate) reconstructor: Reconstructor,
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
    pub(crate) fn new(
        segment_headers_store: &'a SegmentHeadersStore<AS>,
        node: &'a Node,
        piece_getter: &'a PG,
        client: Arc<Client>,
        import_queue_service: Arc<Mutex<Box<IQS>>>,
        network_service: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
        subspace_link: SubspaceLink<Block>,
    ) -> Self {
        Self {
            segment_headers_store,
            node,
            piece_getter,
            client,
            import_queue_service,
            network_service,
            subspace_link,
        }
    }

    /// Sync algorithm:
    /// - 1. download two last segments,
    /// - 2. add the last block the second last segment (as raw - without checks and execution),
    /// - 3. download the state for the first block of the last segment,
    ///     - a) add the first block of the last segment as raw,
    ///     - b) download state for it,
    /// - 4. add blocks with execution from the last segment (except the first and the last blocks),
    ///     - a) init archiver using the second last segment header and the first block of the last segment,
    ///     - b) notify Substrate sync by importing block with using BlockOrigin::NetworkBroadcast,
    ///     - c) clear the block gap to prevent Substrate sync to download blocks from the start.
    pub(crate) async fn sync(&self) -> Result<FastSyncResult<Block>, Error> {
        // TODO: skip fast sync if no segments
        // TODO: retry for fast sync will degrade reputation if we have already announced blocks
        // TODO: handle the edge case when the second last segment contains the whole last block
        info!("Starting fast sync...");

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
            return Err(sc_service::Error::Other(
                "Can't get last segment index.".into(),
            ));
        };

        // TODO: check for starting segment

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
            return Err(sc_service::Error::Other(
                "Unexpected block array length for the second last segment.".into(),
            ));
        }

        info!(
            "Second last segment blocks downloaded (SegmentId={}): {}-{}",
            second_last_segment_index,
            second_last_segment_blocks[0].0,
            second_last_segment_blocks[blocks_in_second_last_segment - 1].0
        ); // TODO: debug

        let blocks = download_and_reconstruct_blocks(
            last_segment_header.segment_index(),
            self.piece_getter,
            &mut reconstructor,
        )
        .await?;

        let blocks_in_last_segment = blocks.len();

        if blocks_in_last_segment < 2 {
            return Err(sc_service::Error::Other(
                "Unexpected block array length for the last segment.".into(),
            ));
        }

        info!(
            "Blocks downloaded (SegmentId={}): {}-{}",
            last_segment_index,
            blocks[0].0,
            blocks[blocks_in_last_segment - 1].0
        ); // TODO: debug

        // 2. Raw import the last block from the second last segment.

        let (last_block_number_from_second_segment, last_block_bytes_from_second_segment) =
            second_last_segment_blocks[blocks_in_second_last_segment - 1].clone();

        let (raw_block, _) = Self::create_raw_block(
            last_block_bytes_from_second_segment,
            last_block_number_from_second_segment.into(),
        )?;
        self.client.import_raw_block(raw_block.clone())?;

        info!(
            hash = ?raw_block.hash,
            number = %last_block_number_from_second_segment,
            "Last raw block from the second last segment imported"
        ); // TODO: debug

        // 3. Download state for the first block of the last segment.
        // TODO: check edge case (full segment)

        let (second_last_block_number, _) = blocks[blocks_in_last_segment - 1].clone();
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

        info!(
            hash = ?raw_block.hash,
            number = %state_block_number,
            "Raw state block imported"
        ); // TODO: debug

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

        // 4. Import and execute blocks from the last segment

        info!("Started importing blocks from last segment.");

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
        //TODO: timeout
        self.wait_for_block_import(second_last_block_number.into())
            .await;

        // 4.b) notify Substrate sync by importing block with using BlockOrigin::NetworkBroadcast

        info!(
            "Importing the last block #{} from the segment #{last_segment_index}",
            last_block_number
        ); // TODO: debug


        // Import and execute the last block from the segment and setup the substrate sync
        self.import_deconstructed_block(
            last_block_bytes,
            last_block_number.into(),
            BlockOrigin::NetworkBroadcast,
        )
        .await?;

        // Final import delay
        //TODO: timeout
        self.wait_for_block_import(last_block_number.into()).await;

        // 4.c) Clear the block gap to prevent Substrate sync to download blocks from the start.
        info!("Clearing block gap..."); //TODO: debug
        self.client.clear_block_gap();

        let info = self.client.info();
        info!("Current client info: {:?}", info); //TODO: debug

        Ok(FastSyncResult::<Block> {
            last_imported_block_number: last_block_number.into(),
            last_imported_segment_index: last_segment_index,
            reconstructor,
        })
    }

    //TODO: add timeout
    async fn wait_for_block_import(&self, last_imported_block_number: NumberFor<Block>) {
        loop {
            let info = self.client.info();
            info!(%last_imported_block_number, "Waiting client info: {:?}", info); // TODO: debug
            tokio::time::sleep(Duration::from_secs(5)).await;

            if last_imported_block_number >= info.best_number {
                break;
            }
        }
    }

    async fn download_segment_headers(
        &self,
        segment_header_downloader: &SegmentHeaderDownloader<'_>,
    ) -> Result<(), sc_service::Error>
    where
        AS: AuxStore + Send + Sync + 'static,
    {
        let max_segment_index =
            self.segment_headers_store
                .max_segment_index()
                .ok_or_else(|| {
                    sc_service::Error::Other(
                "Archiver needs to be initialized before syncing from DSN to populate the very \
                    first segment"
                    .to_string(),
            )
                })?;
        let new_segment_headers = segment_header_downloader
            .get_segment_headers(max_segment_index)
            .await
            .map_err(|error| error.to_string())?;

        info!("Found {} new segment headers", new_segment_headers.len()); // TODO: debug

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

        info!(
            ?hash,
            parent_hash=?header.parent_hash(),
            "Reconstructed block #{} for raw block import", block_number
        ); // TODO: debug

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

        info!(%block_number, ?block_origin, ?hash, "Importing block..."); // TODO: debug

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
    ) -> Result<(Block::Header, Vec<Block::Extrinsic>, Option<Justifications>), sc_service::Error>
    {
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
            info!(%attempt, "Starting state sync...");

            info!("Gathering peers for state sync.");
            let network_service = self.network_service.clone();
            let mut tried_peers = HashSet::<PeerId>::new();

            // TODO: add loop timeout
            let peer_candidates = loop {
                let open_peers = network_service
                    .open_peers()
                    .await
                    .expect("Network service must be available.");

                info!(?tried_peers, "Sync peers: {}", open_peers.len()); // TODO: debug comment

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
            .map_err(sc_service::Error::Client)?;

            let sync_fut = sync_worker.run();

            let net_fut = tokio::spawn(networking_fut);
            let sync_worker_handle = tokio::spawn(sync_fut); // TODO: join until finish

            // Start syncing..
            let _ = sync_engine.start().await;
            let last_block_from_sync_result = sync_worker_handle.await;

            net_fut.abort();

            // .map_err(|e| sc_service::Error::Other("Fast sync task error.".into()))?
            // .map_err(sc_service::Error::Client)?;

            match last_block_from_sync_result {
                Ok(Ok(last_block_from_sync)) => {
                    info!("Sync worker handle result: {:?}", last_block_from_sync,);

                    // Block import delay
                    sleep(Duration::from_secs(5)).await; // TODO

                    info!("Clearing block gap...");
                    self.client.clear_block_gap();

                    return Ok(last_block_from_sync);
                }
                Ok(Err(error)) => {
                    error!(?error, "State sync future error.");
                    continue;
                }
                Err(error) => {
                    error!(?error, "State sync future error.");
                    continue;
                }
            }
        }

        Err(sc_service::Error::Other(
            "All fast sync retries failed.".into(),
        ))
    }
}
