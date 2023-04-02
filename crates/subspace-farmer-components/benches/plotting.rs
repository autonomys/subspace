use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use futures::executor::block_on;
use rand::{thread_rng, Rng};
use rayon::current_num_threads;
use rayon::prelude::*;
use std::io;
use std::num::NonZeroU64;
use std::time::Instant;
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::sector_codec::SectorCodec;
use subspace_core_primitives::{PublicKey, RecordedHistorySegment, SegmentIndex, PLOT_SECTOR_SIZE};
use subspace_farmer_components::plotting::{plot_sector, PieceGetterRetryPolicy};
use subspace_farmer_components::FarmerProtocolInfo;
use utils::BenchPieceGetter;

mod utils;

fn criterion_benchmark(c: &mut Criterion) {
    let public_key = PublicKey::default();
    let sector_index = 0;
    let mut input = RecordedHistorySegment::new_boxed();
    thread_rng().fill(AsMut::<[u8]>::as_mut(input.as_mut()));
    let kzg = Kzg::new(kzg::embedded_kzg_settings());
    let mut archiver = Archiver::new(kzg.clone()).unwrap();
    let sector_codec = SectorCodec::new(PLOT_SECTOR_SIZE as usize).unwrap();
    let piece = archiver
        .add_block(
            AsRef::<[u8]>::as_ref(input.as_ref()).to_vec(),
            Default::default(),
        )
        .into_iter()
        .next()
        .unwrap()
        .pieces[0]
        .into();

    let farmer_protocol_info = FarmerProtocolInfo {
        total_pieces: NonZeroU64::new(1).unwrap(),
        sector_expiration: SegmentIndex::ONE,
    };
    let piece_getter = BenchPieceGetter::new(piece);

    let mut group = c.benchmark_group("sector-plotting");
    group.throughput(Throughput::Bytes(PLOT_SECTOR_SIZE));
    group.bench_function("no-writes-single-thread", |b| {
        b.iter(|| {
            block_on(plot_sector(
                black_box(&public_key),
                black_box(sector_index),
                black_box(&piece_getter),
                black_box(PieceGetterRetryPolicy::default()),
                black_box(&farmer_protocol_info),
                black_box(&kzg),
                black_box(&sector_codec),
                black_box(io::sink()),
                black_box(io::sink()),
                Default::default(),
            ))
            .unwrap();
        })
    });

    let thread_count = current_num_threads() as u64;
    group.throughput(Throughput::Bytes(PLOT_SECTOR_SIZE * thread_count));
    group.bench_function("no-writes-multi-thread", |b| {
        b.iter_custom(|iters| {
            let sectors = (0..thread_count).collect::<Vec<_>>();
            let start = Instant::now();
            for _i in 0..iters {
                sectors.par_iter().for_each(|&sector_index| {
                    block_on(plot_sector(
                        black_box(&public_key),
                        black_box(sector_index),
                        black_box(&piece_getter),
                        black_box(PieceGetterRetryPolicy::default()),
                        black_box(&farmer_protocol_info),
                        black_box(&kzg),
                        black_box(&sector_codec),
                        black_box(io::sink()),
                        black_box(io::sink()),
                        Default::default(),
                    ))
                    .unwrap();
                });
            }
            start.elapsed()
        })
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
