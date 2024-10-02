use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use futures::executor::block_on;
use rand::prelude::*;
use std::env;
use std::num::{NonZeroU64, NonZeroUsize};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::pieces::Record;
use subspace_core_primitives::segments::{HistorySize, RecordedHistorySegment};
use subspace_core_primitives::PublicKey;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::plotting::{plot_sector, CpuRecordsEncoder, PlotSectorOptions};
use subspace_farmer_components::sector::sector_size;
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_kzg::Kzg;
use subspace_proof_of_space::chia::ChiaTable;
use subspace_proof_of_space::Table;

type PosTable = ChiaTable;

const MAX_PIECES_IN_SECTOR: u16 = 1000;

fn criterion_benchmark(c: &mut Criterion) {
    println!("Initializing...");
    let pieces_in_sector = env::var("PIECES_IN_SECTOR")
        .map(|base_path| base_path.parse().unwrap())
        .unwrap_or_else(|_error| MAX_PIECES_IN_SECTOR);

    let public_key = PublicKey::default();
    let sector_index = 0;
    let mut input = RecordedHistorySegment::new_boxed();
    StdRng::seed_from_u64(42).fill(AsMut::<[u8]>::as_mut(input.as_mut()));
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg.clone(), erasure_coding.clone());
    let mut table_generators = [
        PosTable::generator(),
        PosTable::generator(),
        PosTable::generator(),
        PosTable::generator(),
        PosTable::generator(),
        PosTable::generator(),
        PosTable::generator(),
        PosTable::generator(),
    ];
    let archived_history_segment = archiver
        .add_block(
            AsRef::<[u8]>::as_ref(input.as_ref()).to_vec(),
            Default::default(),
            true,
        )
        .into_iter()
        .next()
        .unwrap()
        .pieces;

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

    let sector_size = sector_size(pieces_in_sector);
    let mut sector_bytes = Vec::new();

    let mut group = c.benchmark_group("plotting");
    group.throughput(Throughput::Bytes(sector_size as u64));
    group.bench_function("in-memory", |b| {
        b.iter(|| {
            block_on(plot_sector(PlotSectorOptions {
                public_key: black_box(&public_key),
                sector_index: black_box(sector_index),
                piece_getter: black_box(&archived_history_segment),
                farmer_protocol_info: black_box(farmer_protocol_info),
                kzg: black_box(&kzg),
                erasure_coding: black_box(&erasure_coding),
                pieces_in_sector: black_box(pieces_in_sector),
                sector_output: black_box(&mut sector_bytes),
                downloading_semaphore: black_box(None),
                encoding_semaphore: black_box(None),
                records_encoder: black_box(&mut CpuRecordsEncoder::<PosTable>::new(
                    &mut table_generators,
                    &erasure_coding,
                    &Default::default(),
                )),
                abort_early: &Default::default(),
            }))
            .unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
