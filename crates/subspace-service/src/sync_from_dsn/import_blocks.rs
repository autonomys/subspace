use crate::sync_from_dsn::segment_header_downloader::SegmentHeaderDownloader;
use crate::sync_from_dsn::{PieceGetter, LOG_TARGET};
use sc_client_api::{AuxStore, BlockBackend, HeaderBackend};
use sc_consensus::import_queue::ImportQueueService;
use sc_consensus::IncomingBlock;
use sc_consensus_subspace::archiver::{decode_block, encode_block, SegmentHeadersStore};
use sc_service::Error;
use sc_tracing::tracing::{debug, trace};
use sp_consensus::BlockOrigin;
use sp_runtime::generic::SignedBlock;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor, One};
use sp_runtime::Saturating;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use subspace_archiving::reconstructor::Reconstructor;
use subspace_core_primitives::segments::SegmentIndex;
use subspace_core_primitives::BlockNumber;
use subspace_data_retrieval::segment_downloading::download_segment_pieces;
use subspace_erasure_coding::ErasureCoding;
use tokio::task;

/// How many blocks to queue before pausing and waiting for blocks to be imported, this is
/// essentially used to ensure we use a bounded amount of RAM during sync process.
const QUEUED_BLOCKS_LIMIT: BlockNumber = 500;
/// Time to wait for blocks to import if import is too slow
const WAIT_FOR_BLOCKS_TO_IMPORT: Duration = Duration::from_secs(1);

/// Starts the process of importing blocks.
///
/// Returns number of downloaded blocks.
#[allow(clippy::too_many_arguments)]
pub(super) async fn import_blocks_from_dsn<Block, AS, Client, PG, IQS>(
    segment_headers_store: &SegmentHeadersStore<AS>,
    segment_header_downloader: &SegmentHeaderDownloader<'_>,
    client: &Client,
    piece_getter: &PG,
    import_queue_service: &mut IQS,
    last_processed_segment_index: &mut SegmentIndex,
    last_processed_block_number: &mut <Block::Header as Header>::Number,
    erasure_coding: &ErasureCoding,
) -> Result<u64, Error>
where
    Block: BlockT,
    AS: AuxStore + Send + Sync + 'static,
    Client: HeaderBackend<Block> + BlockBackend<Block> + Send + Sync + 'static,
    PG: PieceGetter,
    IQS: ImportQueueService<Block> + ?Sized,
{
    {
        let last_segment_header = segment_headers_store.last_segment_header().ok_or_else(|| {
            Error::Other(
                "Archiver needs to be initialized before syncing from DSN to populate the very \
                first segment"
                    .to_string(),
            )
        })?;

        let new_segment_headers = segment_header_downloader
            .get_segment_headers(&last_segment_header)
            .await
            .map_err(|error| error.to_string())?;

        debug!(target: LOG_TARGET, "Found {} new segment headers", new_segment_headers.len());

        if !new_segment_headers.is_empty() {
            segment_headers_store.add_segment_headers(&new_segment_headers)?;
        }
    }

    let mut imported_blocks = 0;
    let mut reconstructor = Arc::new(Mutex::new(Reconstructor::new(erasure_coding.clone())));
    // Start from the first unprocessed segment and process all segments known so far
    let segment_indices_iter = (*last_processed_segment_index + SegmentIndex::ONE)
        ..=segment_headers_store
            .max_segment_index()
            .expect("Exists, we have inserted segment headers above; qed");
    let mut segment_indices_iter = segment_indices_iter.peekable();

    while let Some(segment_index) = segment_indices_iter.next() {
        debug!(target: LOG_TARGET, %segment_index, "Processing segment");

        let segment_header = segment_headers_store
            .get_segment_header(segment_index)
            .expect("Statically guaranteed to exist, see checks above; qed");

        let last_archived_maybe_partial_block_number = segment_header.last_archived_block().number;
        let last_archived_block_partial = segment_header
            .last_archived_block()
            .archived_progress
            .partial()
            .is_some();

        trace!(
            target: LOG_TARGET,
            %segment_index,
            last_archived_maybe_partial_block_number,
            last_archived_block_partial,
            "Checking segment header"
        );

        let last_full_archived_block_number = if last_archived_block_partial {
            // The genesis block is always fully reconstructed, so we can saturating_sub here
            NumberFor::<Block>::from(last_archived_maybe_partial_block_number)
                .saturating_sub(1u32.into())
        } else {
            NumberFor::<Block>::from(last_archived_maybe_partial_block_number)
        };

        let info = client.info();
        // We have already processed the last block that's completely in this segment, or one
        // higher than it, so it can't change. Resetting the reconstructor loses any partial
        // blocks, so we only reset based on fully reconstructed blocks.
        if *last_processed_block_number >= last_full_archived_block_number {
            *last_processed_segment_index = segment_index;
            // Reset reconstructor instance
            reconstructor = Arc::new(Mutex::new(Reconstructor::new(erasure_coding.clone())));
            continue;
        }
        // Just one partial unprocessed block and this was the last segment available, so nothing to
        // import
        let last_archived_maybe_partial_block_number =
            NumberFor::<Block>::from(last_archived_maybe_partial_block_number);
        if last_archived_maybe_partial_block_number == *last_processed_block_number + One::one()
            && last_archived_block_partial
            && segment_indices_iter.peek().is_none()
        {
            // Reset reconstructor instance
            reconstructor = Arc::new(Mutex::new(Reconstructor::new(erasure_coding.clone())));
            continue;
        }

        let segment_pieces = download_segment_pieces(segment_index, piece_getter)
            .await
            .map_err(|error| format!("Failed to download segment pieces: {error}"))?;
        // CPU-intensive piece and segment reconstruction code can block the async executor.
        let segment_contents_fut = task::spawn_blocking({
            let reconstructor = reconstructor.clone();

            move || {
                reconstructor
                    .lock()
                    .expect("Panic if previous thread panicked when holding the mutex")
                    .add_segment(segment_pieces.as_ref())
            }
        });
        let blocks = segment_contents_fut
            .await
            .expect("Panic if blocking task panicked")
            .map_err(|error| error.to_string())?
            .blocks;
        trace!(target: LOG_TARGET, %segment_index, "Segment reconstructed successfully");

        let mut blocks_to_import = Vec::with_capacity(QUEUED_BLOCKS_LIMIT as usize);

        let mut best_block_number = info.best_number;
        for (block_number, block_bytes) in blocks {
            let block_number = block_number.into();
            if block_number == 0u32.into() {
                let signed_block = client
                    .block(
                        client
                            .hash(block_number)?
                            .expect("Genesis block hash must always be found; qed"),
                    )?
                    .expect("Genesis block data must always be found; qed");

                if encode_block(signed_block) != block_bytes {
                    return Err(Error::Other(
                        "Wrong genesis block, block import failed".to_string(),
                    ));
                }
            }

            // Limit number of queued blocks for import
            // NOTE: Since best block number might be non-canonical, we might actually have more
            // than `QUEUED_BLOCKS_LIMIT` elements in the queue, but it should be rare and
            // insignificant. Feel free to address this in case you have a good strategy, but it
            // seems like complexity is not worth it.
            while block_number.saturating_sub(best_block_number) >= QUEUED_BLOCKS_LIMIT.into() {
                let just_queued_blocks_count = blocks_to_import.len();
                if !blocks_to_import.is_empty() {
                    // This vector is quite large (~150kB), so replacing it with an uninitialized
                    // vector with the correct capacity is faster than cloning and clearing it.
                    // (Cloning requires a memcpy, which pages in and sets all the memory, which is
                    // a waste just before clearing it.)
                    let importing_blocks = std::mem::replace(
                        &mut blocks_to_import,
                        Vec::with_capacity(QUEUED_BLOCKS_LIMIT as usize),
                    );
                    // Import queue handles verification and importing it into the client
                    import_queue_service
                        .import_blocks(BlockOrigin::NetworkInitialSync, importing_blocks);
                }
                trace!(
                    target: LOG_TARGET,
                    %block_number,
                    %best_block_number,
                    %just_queued_blocks_count,
                    %QUEUED_BLOCKS_LIMIT,
                    "Number of importing blocks reached queue limit, waiting before retrying"
                );
                tokio::time::sleep(WAIT_FOR_BLOCKS_TO_IMPORT).await;
                best_block_number = client.info().best_number;
            }

            let signed_block =
                decode_block::<Block>(&block_bytes).map_err(|error| error.to_string())?;

            *last_processed_block_number = block_number;

            // No need to import blocks that are already present, if block is not present it might
            // correspond to a short fork, so we need to import it even if we already have another
            // block at this height
            if client.expect_header(signed_block.block.hash()).is_ok() {
                continue;
            }

            let SignedBlock {
                block,
                justifications,
            } = signed_block;
            let (header, extrinsics) = block.deconstruct();
            let hash = header.hash();

            blocks_to_import.push(IncomingBlock {
                hash,
                header: Some(header),
                body: Some(extrinsics),
                indexed_body: None,
                justifications,
                origin: None,
                allow_missing_state: false,
                import_existing: false,
                state: None,
                skip_execution: false,
            });

            imported_blocks += 1;

            if imported_blocks % 1000 == 0 {
                debug!(target: LOG_TARGET, "Adding block {} from DSN to the import queue", block_number);
            }
        }

        if !blocks_to_import.is_empty() {
            // Import queue handles verification and importing it into the client
            import_queue_service.import_blocks(BlockOrigin::NetworkInitialSync, blocks_to_import);
        }

        *last_processed_segment_index = segment_index;
    }

    Ok(imported_blocks)
}
