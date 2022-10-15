use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use futures::executor::block_on;
use rand::{thread_rng, Rng};
use rayon::current_num_threads;
use rayon::prelude::*;
use std::io;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::sync::atomic::AtomicBool;
use std::time::Instant;
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    plot_sector_size, Piece, PublicKey, PIECES_IN_SEGMENT, RECORD_SIZE,
};
use subspace_farmer::single_disk_plot::plotting::plot_sector;
use subspace_rpc_primitives::FarmerProtocolInfo;

// This is helpful for overriding locally for benching different parameters
pub const RECORDED_HISTORY_SEGMENT_SIZE: u32 = RECORD_SIZE * PIECES_IN_SEGMENT / 2;

pub fn criterion_benchmark(c: &mut Criterion) {
    let public_key = PublicKey::default();
    let sector_index = 0;
    let mut input = vec![0u8; RECORDED_HISTORY_SEGMENT_SIZE as usize];
    thread_rng().fill(input.as_mut_slice());
    let kzg = Kzg::new(kzg::test_public_parameters());
    let mut archiver = Archiver::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg).unwrap();
    let piece = Piece::try_from(
        archiver
            .add_block(input.clone(), Default::default())
            .into_iter()
            .next()
            .unwrap()
            .pieces
            .as_pieces()
            .next()
            .unwrap(),
    )
    .unwrap();

    let get_piece = |_piece_index| async { Ok(Some(piece.clone())) };
    let cancelled = AtomicBool::new(false);
    let farmer_protocol_info = FarmerProtocolInfo {
        genesis_hash: Default::default(),
        record_size: NonZeroU32::new(RECORD_SIZE).unwrap(),
        recorded_history_segment_size: RECORDED_HISTORY_SEGMENT_SIZE,
        total_pieces: NonZeroU64::new(1).unwrap(),
        space_l: NonZeroU16::new(20).unwrap(),
        sector_expiration: 1,
    };

    let mut group = c.benchmark_group("sector-plotting");
    group.throughput(Throughput::Bytes(plot_sector_size(
        farmer_protocol_info.space_l,
    )));
    group.bench_function("no-writes-single-thread", |b| {
        b.iter(|| {
            black_box(
                block_on(plot_sector(
                    &public_key,
                    sector_index,
                    &get_piece,
                    &cancelled,
                    &farmer_protocol_info,
                    io::sink(),
                    io::sink(),
                ))
                .unwrap(),
            )
        })
    });

    let thread_count = current_num_threads() as u64;
    group.throughput(Throughput::Bytes(
        plot_sector_size(farmer_protocol_info.space_l) * thread_count,
    ));
    group.bench_function("no-writes-multi-thread", |b| {
        b.iter_custom(|iters| {
            let sectors = (0..thread_count).collect::<Vec<_>>();
            let start = Instant::now();
            for _i in 0..iters {
                sectors.par_iter().for_each(|&sector_index| {
                    black_box(
                        block_on(plot_sector(
                            &public_key,
                            sector_index,
                            &get_piece,
                            &cancelled,
                            &farmer_protocol_info,
                            io::sink(),
                            io::sink(),
                        ))
                        .unwrap(),
                    );
                });
            }
            start.elapsed()
        })
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
