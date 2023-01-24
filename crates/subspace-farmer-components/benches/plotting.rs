use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use futures::executor::block_on;
use rand::{thread_rng, Rng};
use rayon::current_num_threads;
use rayon::prelude::*;
use std::io;
use std::num::{NonZeroU32, NonZeroU64};
use std::time::Instant;
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::sector_codec::SectorCodec;
use subspace_core_primitives::{
    Piece, PublicKey, PIECES_IN_SEGMENT, PLOT_SECTOR_SIZE, RECORD_SIZE,
};
use subspace_farmer_components::plotting::plot_sector;
use subspace_farmer_components::FarmerProtocolInfo;
use utils::BenchPieceGetter;

mod utils;

// This is helpful for overriding locally for benching different parameters
const RECORDED_HISTORY_SEGMENT_SIZE: u32 = RECORD_SIZE * PIECES_IN_SEGMENT / 2;

fn criterion_benchmark(c: &mut Criterion) {
    let public_key = PublicKey::default();
    let sector_index = 0;
    let mut input = vec![0u8; RECORDED_HISTORY_SEGMENT_SIZE as usize];
    thread_rng().fill(input.as_mut_slice());
    let kzg = Kzg::new(kzg::test_public_parameters());
    let mut archiver =
        Archiver::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg.clone()).unwrap();
    let sector_codec = SectorCodec::new(PLOT_SECTOR_SIZE as usize).unwrap();
    let piece = Piece::try_from(
        archiver
            .add_block(input, Default::default())
            .into_iter()
            .next()
            .unwrap()
            .pieces
            .as_pieces()
            .next()
            .unwrap(),
    )
    .unwrap();

    let farmer_protocol_info = FarmerProtocolInfo {
        record_size: NonZeroU32::new(RECORD_SIZE).unwrap(),
        recorded_history_segment_size: RECORDED_HISTORY_SEGMENT_SIZE,
        total_pieces: NonZeroU64::new(1).unwrap(),
        sector_expiration: 1,
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
                black_box(&farmer_protocol_info),
                black_box(&kzg),
                black_box(&sector_codec),
                black_box(io::sink()),
                black_box(io::sink()),
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
                        black_box(&farmer_protocol_info),
                        black_box(&kzg),
                        black_box(&sector_codec),
                        black_box(io::sink()),
                        black_box(io::sink()),
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
