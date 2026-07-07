//! Plot a sector with the abundance-backed table and read a piece back unchanged.

use futures::executor::block_on;
use rand::prelude::*;
use std::num::{NonZeroU64, NonZeroUsize};
use std::slice;
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::PublicKey;
use subspace_core_primitives::pieces::{PieceOffset, Record};
use subspace_core_primitives::segments::{HistorySize, RecordedHistorySegment};
use subspace_data_retrieval::piece_getter::PieceGetter;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::plotting::{CpuRecordsEncoder, PlotSectorOptions, plot_sector};
use subspace_farmer_components::reading::{ReadSectorRecordChunksMode, read_piece};
use subspace_farmer_components::{FarmerProtocolInfo, ReadAt};
use subspace_kzg::Kzg;
use subspace_proof_of_space::Table;
use subspace_proof_of_space::chia_v2::ChiaV2Table;

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
