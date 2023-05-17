use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use futures::executor::block_on;
use rand::prelude::*;
use std::env;
use std::num::{NonZeroU64, NonZeroUsize};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    HistorySize, PublicKey, Record, RecordedHistorySegment, SegmentIndex,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::plotting::{plot_sector, PieceGetterRetryPolicy};
use subspace_farmer_components::sector::{sector_size, SectorMetadata};
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_proof_of_space::chia::ChiaTable;

type PosTable = ChiaTable;

const MAX_PIECES_IN_SECTOR: u16 = 1300;

fn criterion_benchmark(c: &mut Criterion) {
    println!("Initializing...");
    let pieces_in_sector = env::var("PIECES_IN_SECTOR")
        .map(|base_path| base_path.parse().unwrap())
        .unwrap_or_else(|_error| MAX_PIECES_IN_SECTOR);

    let public_key = PublicKey::default();
    let sector_offset = 0;
    let sector_index = 0;
    let mut input = RecordedHistorySegment::new_boxed();
    StdRng::seed_from_u64(42).fill(AsMut::<[u8]>::as_mut(input.as_mut()));
    let kzg = Kzg::new(kzg::embedded_kzg_settings());
    let mut archiver = Archiver::new(kzg.clone()).unwrap();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize).unwrap(),
    )
    .unwrap();
    let archived_history_segment = archiver
        .add_block(
            AsRef::<[u8]>::as_ref(input.as_ref()).to_vec(),
            Default::default(),
        )
        .into_iter()
        .next()
        .unwrap()
        .pieces;

    let farmer_protocol_info = FarmerProtocolInfo {
        history_size: HistorySize::from(NonZeroU64::new(1).unwrap()),
        max_pieces_in_sector: pieces_in_sector,
        sector_expiration: SegmentIndex::ONE,
    };

    let sector_size = sector_size(pieces_in_sector);
    let mut sector_bytes = vec![0; sector_size];
    let mut sector_metadata_bytes = vec![0; SectorMetadata::encoded_size()];

    let mut group = c.benchmark_group("plotting");
    group.throughput(Throughput::Bytes(sector_size as u64));
    group.bench_function("in-memory", |b| {
        b.iter(|| {
            block_on(plot_sector::<_, PosTable>(
                black_box(&public_key),
                black_box(sector_offset),
                black_box(sector_index),
                black_box(&archived_history_segment),
                black_box(PieceGetterRetryPolicy::default()),
                black_box(&farmer_protocol_info),
                black_box(&kzg),
                black_box(&erasure_coding),
                black_box(pieces_in_sector),
                black_box(&mut sector_bytes),
                black_box(&mut sector_metadata_bytes),
                Default::default(),
            ))
            .unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
