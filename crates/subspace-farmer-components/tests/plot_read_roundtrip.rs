//! Plot sectors with the old and abundance-backed tables and read pieces back, including under
//! the farmer's per-sector cutover dispatch.

use futures::executor::block_on;
use rand::prelude::*;
use std::num::{NonZeroU8, NonZeroU64, NonZeroUsize};
use std::slice;
use std::sync::atomic::AtomicBool;
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::PublicKey;
use subspace_core_primitives::pieces::{PieceOffset, Record};
use subspace_core_primitives::sectors::SectorId;
use subspace_core_primitives::segments::{HistorySize, RecordedHistorySegment};
use subspace_data_retrieval::piece_getter::PieceGetter;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::plotting::{
    CpuRecordsEncoder, PlotSectorOptions, RecordsEncoder, plot_sector,
};
use subspace_farmer_components::reading::{ReadSectorRecordChunksMode, read_piece};
use subspace_farmer_components::sector::SectorContentsMap;
use subspace_farmer_components::{FarmerProtocolInfo, ReadAt};
use subspace_kzg::Kzg;
use subspace_proof_of_space::chia::ChiaTable;
use subspace_proof_of_space::chia_v2::ChiaV2Table;
use subspace_proof_of_space::{PosTable, Table};
use subspace_proof_of_space_wgpu::{Device, WgpuDevice};

#[test]
fn abundance_plot_read_roundtrip() {
    let pieces_in_sector = 10;
    let sector_index = 0;
    let public_key = PublicKey::default();

    let mut input = RecordedHistorySegment::new_boxed();
    StdRng::seed_from_u64(42).fill(AsMut::<[u8]>::as_mut(input.as_mut()));
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg.clone(), erasure_coding.clone());
    let archived_history_segment = archiver
        .add_block(
            AsRef::<[u8]>::as_ref(input.as_ref()).to_vec(),
            Default::default(),
            true,
        )
        .archived_segments
        .into_iter()
        .next()
        .unwrap();

    let farmer_protocol_info = FarmerProtocolInfo {
        history_size: HistorySize::from(NonZeroU64::new(1).unwrap()),
        max_pieces_in_sector: pieces_in_sector,
        recent_segments: HistorySize::from(NonZeroU64::new(5).unwrap()),
        recent_history_fraction: (
            HistorySize::from(NonZeroU64::new(1).unwrap()),
            HistorySize::from(NonZeroU64::new(10).unwrap()),
        ),
        min_sector_lifetime: HistorySize::from(NonZeroU64::new(4).unwrap()),
    };

    let mut table_generator = ChiaV2Table::generator();
    let mut sector = Vec::new();
    let plotted_sector = block_on(plot_sector(PlotSectorOptions {
        public_key: &public_key,
        sector_index,
        piece_getter: &archived_history_segment,
        farmer_protocol_info,
        kzg: &kzg,
        erasure_coding: &erasure_coding,
        pieces_in_sector,
        sector_output: &mut sector,
        downloading_semaphore: None,
        encoding_semaphore: None,
        records_encoder: &mut CpuRecordsEncoder::<ChiaV2Table>::new(
            slice::from_mut(&mut table_generator),
            &erasure_coding,
            &Default::default(),
        ),
        abort_early: &Default::default(),
    }))
    .unwrap();

    let piece_offset = PieceOffset::ZERO;
    let piece_index = plotted_sector.piece_indexes[usize::from(piece_offset)];
    let expected = block_on(archived_history_segment.get_piece(piece_index))
        .unwrap()
        .unwrap();

    let read = block_on(read_piece::<ChiaV2Table, _, _>(
        piece_offset,
        &plotted_sector.sector_id,
        &plotted_sector.sector_metadata,
        &ReadAt::from_sync(sector.as_slice()),
        &erasure_coding,
        ReadSectorRecordChunksMode::ConcurrentChunks,
        &mut table_generator,
    ))
    .unwrap();

    assert_eq!(
        read.record(),
        expected.record(),
        "record read back from an abundance-plotted sector must match the original"
    );
}

/// Plot one sector with the old `ChiaTable` and one with the abundance `ChiaV2Table`, then read
/// both back selecting the table per sector via the farmer's cutover dispatch
/// (`PosTable::generator_for(is_post_cutover)`), exactly as an upgraded farm does.
#[test]
fn mixed_old_new_sectors_read_under_cutover_dispatch() {
    let pieces_in_sector = 10;
    let public_key = PublicKey::default();

    let mut input = RecordedHistorySegment::new_boxed();
    StdRng::seed_from_u64(42).fill(AsMut::<[u8]>::as_mut(input.as_mut()));
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg.clone(), erasure_coding.clone());
    let archived_history_segment = archiver
        .add_block(
            AsRef::<[u8]>::as_ref(input.as_ref()).to_vec(),
            Default::default(),
            true,
        )
        .archived_segments
        .into_iter()
        .next()
        .unwrap();

    let farmer_protocol_info = FarmerProtocolInfo {
        history_size: HistorySize::from(NonZeroU64::new(1).unwrap()),
        max_pieces_in_sector: pieces_in_sector,
        recent_segments: HistorySize::from(NonZeroU64::new(5).unwrap()),
        recent_history_fraction: (
            HistorySize::from(NonZeroU64::new(1).unwrap()),
            HistorySize::from(NonZeroU64::new(10).unwrap()),
        ),
        min_sector_lifetime: HistorySize::from(NonZeroU64::new(4).unwrap()),
    };

    // "Old" sector plotted with the old table, "new" sector with the abundance table.
    let mut old_sector = Vec::new();
    let mut old_generator = ChiaTable::generator();
    let old_plotted = block_on(plot_sector(PlotSectorOptions {
        public_key: &public_key,
        sector_index: 0,
        piece_getter: &archived_history_segment,
        farmer_protocol_info,
        kzg: &kzg,
        erasure_coding: &erasure_coding,
        pieces_in_sector,
        sector_output: &mut old_sector,
        downloading_semaphore: None,
        encoding_semaphore: None,
        records_encoder: &mut CpuRecordsEncoder::<ChiaTable>::new(
            slice::from_mut(&mut old_generator),
            &erasure_coding,
            &Default::default(),
        ),
        abort_early: &Default::default(),
    }))
    .unwrap();

    let mut new_sector = Vec::new();
    let mut new_generator = ChiaV2Table::generator();
    let new_plotted = block_on(plot_sector(PlotSectorOptions {
        public_key: &public_key,
        sector_index: 1,
        piece_getter: &archived_history_segment,
        farmer_protocol_info,
        kzg: &kzg,
        erasure_coding: &erasure_coding,
        pieces_in_sector,
        sector_output: &mut new_sector,
        downloading_semaphore: None,
        encoding_semaphore: None,
        records_encoder: &mut CpuRecordsEncoder::<ChiaV2Table>::new(
            slice::from_mut(&mut new_generator),
            &erasure_coding,
            &Default::default(),
        ),
        abort_early: &Default::default(),
    }))
    .unwrap();

    // Cutover sits between the two sectors: old_history <= cutover < new_history. The farmer's rule
    // is `is_post_cutover = history_size > cutover`.
    let cutover = 5u64;
    let old_is_post_cutover = 3u64 > cutover; // false -> old table
    let new_is_post_cutover = 7u64 > cutover; // true -> abundance table

    let piece_offset = PieceOffset::ZERO;

    // Pre-cutover sector must read back via the old table.
    let old_expected = block_on(
        archived_history_segment.get_piece(old_plotted.piece_indexes[usize::from(piece_offset)]),
    )
    .unwrap()
    .unwrap();
    let mut old_dispatch = PosTable::generator_for(old_is_post_cutover);
    let old_read = block_on(read_piece::<PosTable, _, _>(
        piece_offset,
        &old_plotted.sector_id,
        &old_plotted.sector_metadata,
        &ReadAt::from_sync(old_sector.as_slice()),
        &erasure_coding,
        ReadSectorRecordChunksMode::ConcurrentChunks,
        &mut old_dispatch,
    ))
    .unwrap();
    assert_eq!(
        old_read.record(),
        old_expected.record(),
        "pre-cutover sector must read back via the old table under dispatch"
    );

    // Post-cutover sector must read back via the abundance table.
    let new_expected = block_on(
        archived_history_segment.get_piece(new_plotted.piece_indexes[usize::from(piece_offset)]),
    )
    .unwrap()
    .unwrap();
    let mut new_dispatch = PosTable::generator_for(new_is_post_cutover);
    let new_read = block_on(read_piece::<PosTable, _, _>(
        piece_offset,
        &new_plotted.sector_id,
        &new_plotted.sector_metadata,
        &ReadAt::from_sync(new_sector.as_slice()),
        &erasure_coding,
        ReadSectorRecordChunksMode::ConcurrentChunks,
        &mut new_dispatch,
    ))
    .unwrap();
    assert_eq!(
        new_read.record(),
        new_expected.record(),
        "post-cutover sector must read back via the abundance table under dispatch"
    );

    // Misdispatch guard: reading the old sector with the abundance table must not reproduce it, so
    // the per-sector dispatch is genuinely load-bearing (not both tables reading everything alike).
    let mut wrong_generator = PosTable::generator_for(true);
    let old_misread = block_on(read_piece::<PosTable, _, _>(
        piece_offset,
        &old_plotted.sector_id,
        &old_plotted.sector_metadata,
        &ReadAt::from_sync(old_sector.as_slice()),
        &erasure_coding,
        ReadSectorRecordChunksMode::ConcurrentChunks,
        &mut wrong_generator,
    ));
    assert!(
        old_misread
            .map(|read| read.record() != old_expected.record())
            .unwrap_or(true),
        "old sector read with the abundance table must not reproduce the original"
    );
}

/// Minimal single-threaded [`RecordsEncoder`] over the production [`WgpuDevice`], used only to drive
/// `plot_sector` in the byte-identity test (the threaded `WgpuRecordsEncoder` lives in
/// `subspace-farmer`, which this crate cannot depend on).
struct WgpuTestEncoder {
    device: WgpuDevice,
}

impl RecordsEncoder for WgpuTestEncoder {
    fn encode_records(
        &mut self,
        sector_id: &SectorId,
        records: &mut [Record],
        _abort_early: &AtomicBool,
    ) -> anyhow::Result<SectorContentsMap> {
        let pieces_in_sector = records
            .len()
            .try_into()
            .map_err(|error| anyhow::anyhow!("Failed to convert pieces in sector: {error}"))?;
        let mut sector_contents_map = SectorContentsMap::new(pieces_in_sector);
        for ((piece_offset, record), mut encoded_chunks_used) in (PieceOffset::ZERO..)
            .zip(records.iter_mut())
            .zip(sector_contents_map.iter_record_bitfields_mut())
        {
            let pos_seed = sector_id.derive_evaluation_seed(piece_offset);
            self.device
                .generate_and_encode_pospace(&pos_seed, record, encoded_chunks_used.iter_mut())
                .map_err(|error| anyhow::anyhow!(error))?;
        }
        Ok(sector_contents_map)
    }
}

/// Byte-identity gate: a sector plotted with wgpu (GPU) must be byte-for-byte identical to one
/// plotted with the abundance CPU `ChiaV2Table`, so new GPU-plotted farms read and verify under the
/// same CPU path. Skips when no GPU is available (e.g. CI runners without a GPU).
#[test]
fn wgpu_plotted_sector_matches_cpu() {
    let pieces_in_sector = 10;
    let sector_index = 0;
    let public_key = PublicKey::default();

    let mut input = RecordedHistorySegment::new_boxed();
    StdRng::seed_from_u64(42).fill(AsMut::<[u8]>::as_mut(input.as_mut()));
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg.clone(), erasure_coding.clone());
    let archived_history_segment = archiver
        .add_block(
            AsRef::<[u8]>::as_ref(input.as_ref()).to_vec(),
            Default::default(),
            true,
        )
        .archived_segments
        .into_iter()
        .next()
        .unwrap();

    let farmer_protocol_info = FarmerProtocolInfo {
        history_size: HistorySize::from(NonZeroU64::new(1).unwrap()),
        max_pieces_in_sector: pieces_in_sector,
        recent_segments: HistorySize::from(NonZeroU64::new(5).unwrap()),
        recent_history_fraction: (
            HistorySize::from(NonZeroU64::new(1).unwrap()),
            HistorySize::from(NonZeroU64::new(10).unwrap()),
        ),
        min_sector_lifetime: HistorySize::from(NonZeroU64::new(4).unwrap()),
    };

    // One queue is enough for the test; skip entirely when no GPU is present.
    let Some(wgpu_device) = block_on(Device::enumerate(|_device_type| {
        NonZeroU8::new(1).expect("Not zero; qed")
    }))
    .into_iter()
    .next() else {
        eprintln!("No wgpu GPU available; skipping wgpu byte-identity gate");
        return;
    };
    let instance = wgpu_device
        .create_proofs_encoder_instances()
        .into_iter()
        .next()
        .expect("At least one queue per device; qed");
    let mut wgpu_encoder = WgpuTestEncoder {
        device: WgpuDevice::new(instance, erasure_coding.clone()),
    };

    let mut cpu_sector = Vec::new();
    let mut cpu_generator = ChiaV2Table::generator();
    block_on(plot_sector(PlotSectorOptions {
        public_key: &public_key,
        sector_index,
        piece_getter: &archived_history_segment,
        farmer_protocol_info,
        kzg: &kzg,
        erasure_coding: &erasure_coding,
        pieces_in_sector,
        sector_output: &mut cpu_sector,
        downloading_semaphore: None,
        encoding_semaphore: None,
        records_encoder: &mut CpuRecordsEncoder::<ChiaV2Table>::new(
            slice::from_mut(&mut cpu_generator),
            &erasure_coding,
            &Default::default(),
        ),
        abort_early: &Default::default(),
    }))
    .unwrap();

    let mut wgpu_sector = Vec::new();
    block_on(plot_sector(PlotSectorOptions {
        public_key: &public_key,
        sector_index,
        piece_getter: &archived_history_segment,
        farmer_protocol_info,
        kzg: &kzg,
        erasure_coding: &erasure_coding,
        pieces_in_sector,
        sector_output: &mut wgpu_sector,
        downloading_semaphore: None,
        encoding_semaphore: None,
        records_encoder: &mut wgpu_encoder,
        abort_early: &Default::default(),
    }))
    .unwrap();

    assert_eq!(
        cpu_sector, wgpu_sector,
        "wgpu-plotted sector must be byte-identical to the abundance CPU ChiaV2Table plot"
    );
}
