use crate::farm::MaybePieceStoredResult;
use crate::single_disk_farm::direct_io_file::{DirectIoFile, DISK_SECTOR_SIZE};
use crate::single_disk_farm::plot_cache::DiskPlotCache;
use rand::prelude::*;
use std::assert_matches::assert_matches;
use std::num::NonZeroU64;
use std::sync::Arc;
use subspace_core_primitives::pieces::{Piece, PieceIndex, Record};
use subspace_core_primitives::sectors::SectorIndex;
use subspace_core_primitives::segments::HistorySize;
use subspace_farmer_components::file_ext::FileExt;
use subspace_farmer_components::sector::{SectorMetadata, SectorMetadataChecksummed};
use subspace_networking::libp2p::kad::RecordKey;
use subspace_networking::utils::multihash::ToMultihash;
use tempfile::tempdir;

const FAKE_SECTOR_SIZE: usize = 2 * 1024 * 1024;
const TARGET_SECTOR_COUNT: SectorIndex = 5;

#[tokio::test(flavor = "multi_thread")]
async fn basic() {
    let dummy_sector_metadata = SectorMetadataChecksummed::from(SectorMetadata {
        sector_index: 0,
        pieces_in_sector: 0,
        s_bucket_sizes: Box::new([0u16; Record::NUM_S_BUCKETS]),
        history_size: HistorySize::new(NonZeroU64::MIN),
    });

    let tempdir = tempdir().unwrap();
    let file = DirectIoFile::open(&tempdir.path().join("plot.bin")).unwrap();

    // Align plot file size for disk sector size
    file.preallocate(
        (FAKE_SECTOR_SIZE as u64 * u64::from(TARGET_SECTOR_COUNT))
            .div_ceil(DISK_SECTOR_SIZE as u64)
            * DISK_SECTOR_SIZE as u64,
    )
    .unwrap();

    let file = Arc::new(file);

    let piece_index_0 = PieceIndex::from(0);
    let piece_index_1 = PieceIndex::from(1);
    let piece_index_2 = PieceIndex::from(2);
    let piece_0 = {
        let mut piece = Piece::default();
        thread_rng().fill(piece.as_mut());
        piece
    };
    let piece_1 = {
        let mut piece = Piece::default();
        thread_rng().fill(piece.as_mut());
        piece
    };
    let piece_2 = {
        let mut piece = Piece::default();
        thread_rng().fill(piece.as_mut());
        piece
    };
    let record_key_0 = RecordKey::from(piece_index_0.to_multihash());
    let record_key_1 = RecordKey::from(piece_index_1.to_multihash());
    let record_key_2 = RecordKey::from(piece_index_2.to_multihash());

    let sectors_metadata = Arc::default();

    let disk_plot_cache = DiskPlotCache::new(
        &file,
        &sectors_metadata,
        TARGET_SECTOR_COUNT,
        FAKE_SECTOR_SIZE as u64,
    );

    // Initially empty
    assert_matches!(disk_plot_cache.read_piece(&record_key_0).await, None);
    assert_matches!(
        disk_plot_cache.is_piece_maybe_stored(&record_key_0),
        MaybePieceStoredResult::Vacant
    );

    // Can't store pieces when all sectors are plotted
    sectors_metadata.write_blocking().resize(
        usize::from(TARGET_SECTOR_COUNT),
        dummy_sector_metadata.clone(),
    );
    assert!(!disk_plot_cache
        .try_store_piece(piece_index_0, &piece_0)
        .await
        .unwrap());
    assert_matches!(
        disk_plot_cache.is_piece_maybe_stored(&record_key_0),
        MaybePieceStoredResult::No
    );

    // Clear plotted sectors and reopen
    sectors_metadata.write_blocking().clear();
    let disk_plot_cache = DiskPlotCache::new(
        &file,
        &sectors_metadata,
        TARGET_SECTOR_COUNT,
        FAKE_SECTOR_SIZE as u64,
    );

    // Successfully stores piece if not all sectors are plotted
    assert!(disk_plot_cache
        .try_store_piece(piece_index_0, &piece_0)
        .await
        .unwrap());
    assert_matches!(
        disk_plot_cache.is_piece_maybe_stored(&record_key_0),
        MaybePieceStoredResult::Yes
    );
    assert!(disk_plot_cache.read_piece(&record_key_0).await.unwrap() == piece_0);

    // Store two more pieces and make sure they can be read
    assert_matches!(
        disk_plot_cache.is_piece_maybe_stored(&record_key_1),
        MaybePieceStoredResult::Vacant
    );
    assert!(disk_plot_cache
        .try_store_piece(piece_index_1, &piece_1)
        .await
        .unwrap());
    assert_matches!(
        disk_plot_cache.is_piece_maybe_stored(&record_key_1),
        MaybePieceStoredResult::Yes
    );
    assert!(disk_plot_cache.read_piece(&record_key_1).await.unwrap() == piece_1);

    assert_matches!(
        disk_plot_cache.is_piece_maybe_stored(&record_key_2),
        MaybePieceStoredResult::Vacant
    );
    assert!(disk_plot_cache
        .try_store_piece(piece_index_2, &piece_2)
        .await
        .unwrap());
    assert_matches!(
        disk_plot_cache.is_piece_maybe_stored(&record_key_2),
        MaybePieceStoredResult::Yes
    );
    assert!(disk_plot_cache.read_piece(&record_key_2).await.unwrap() == piece_2);

    // Write almost all sectors even without updating metadata, this will result in internal piece
    // read error due to checksum mismatch and eviction of the piece from cache
    file.write_all_at(
        &vec![0; usize::from(TARGET_SECTOR_COUNT - 1) * FAKE_SECTOR_SIZE],
        0,
    )
    .unwrap();
    assert_matches!(
        disk_plot_cache.is_piece_maybe_stored(&record_key_2),
        MaybePieceStoredResult::Yes
    );
    assert_matches!(disk_plot_cache.read_piece(&record_key_2).await, None);
    assert_matches!(
        disk_plot_cache.is_piece_maybe_stored(&record_key_2),
        MaybePieceStoredResult::Vacant
    );

    // Updating metadata will immediately evict piece
    assert_matches!(
        disk_plot_cache.is_piece_maybe_stored(&record_key_1),
        MaybePieceStoredResult::Yes
    );
    sectors_metadata
        .write_blocking()
        .resize(usize::from(TARGET_SECTOR_COUNT - 1), dummy_sector_metadata);
    assert_matches!(
        disk_plot_cache.is_piece_maybe_stored(&record_key_1),
        MaybePieceStoredResult::No
    );

    // Closing file will render cache unusable
    assert!(disk_plot_cache.read_piece(&record_key_0).await.unwrap() == piece_0);
    drop(file);
    assert_matches!(disk_plot_cache.read_piece(&record_key_0).await, None);
}
