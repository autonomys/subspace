use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use futures::executor::block_on;
use memmap2::Mmap;
use std::fs::OpenOptions;
use std::io::Write;
use std::num::{NonZeroU32, NonZeroU64};
use std::time::Instant;
use std::{env, fs, io};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::sector_codec::SectorCodec;
use subspace_core_primitives::{
    Blake2b256Hash, Piece, PublicKey, SolutionRange, PIECES_IN_SEGMENT, PLOT_SECTOR_SIZE,
    RECORD_SIZE,
};
use subspace_farmer_components::farming::audit_sector;
use subspace_farmer_components::file_ext::FileExt;
use subspace_farmer_components::plotting::{plot_sector, PieceGetterRetryPolicy};
use subspace_farmer_components::FarmerProtocolInfo;
use utils::BenchPieceGetter;

mod utils;

// This is helpful for overriding locally for benching different parameters
pub const RECORDED_HISTORY_SEGMENT_SIZE: u32 = RECORD_SIZE * PIECES_IN_SEGMENT / 2;

pub fn criterion_benchmark(c: &mut Criterion) {
    let base_path = env::var("BASE_PATH")
        .map(|base_path| base_path.parse().unwrap())
        .unwrap_or_else(|_error| env::temp_dir());
    let sectors_count = env::var("SECTORS_COUNT")
        .map(|sectors_count| sectors_count.parse().unwrap())
        .unwrap_or(10);

    let public_key = PublicKey::default();
    let sector_index = 0;
    let input = vec![1u8; RECORDED_HISTORY_SEGMENT_SIZE as usize];
    let kzg = Kzg::new(kzg::test_public_parameters());
    let mut archiver =
        Archiver::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg.clone()).unwrap();
    let sector_codec = SectorCodec::new(PLOT_SECTOR_SIZE as usize).unwrap();
    let piece = Piece::from(
        archiver
            .add_block(input, Default::default())
            .into_iter()
            .next()
            .unwrap()
            .pieces
            .as_pieces()
            .next()
            .unwrap(),
    );

    let farmer_protocol_info = FarmerProtocolInfo {
        record_size: NonZeroU32::new(RECORD_SIZE).unwrap(),
        recorded_history_segment_size: RECORDED_HISTORY_SEGMENT_SIZE,
        total_pieces: NonZeroU64::new(1).unwrap(),
        sector_expiration: 1,
    };
    let global_challenge = Blake2b256Hash::default();
    let solution_range = SolutionRange::MAX;

    let plotted_sector = {
        let mut plotted_sector = vec![0u8; PLOT_SECTOR_SIZE as usize];

        block_on(plot_sector(
            &public_key,
            sector_index,
            &BenchPieceGetter::new(piece),
            PieceGetterRetryPolicy::default(),
            &farmer_protocol_info,
            &kzg,
            &sector_codec,
            plotted_sector.as_mut_slice(),
            io::sink(),
            Default::default(),
        ))
        .unwrap();

        plotted_sector
    };

    let mut group = c.benchmark_group("audit");
    group.throughput(Throughput::Elements(1));
    group.bench_function("memory", |b| {
        b.iter(|| {
            audit_sector(
                black_box(&public_key),
                black_box(sector_index),
                black_box(&global_challenge),
                black_box(solution_range),
                black_box(io::Cursor::new(&plotted_sector)),
            )
            .unwrap();
        })
    });

    group.throughput(Throughput::Elements(sectors_count));
    group.bench_function("disk", |b| {
        let plot_file_path = base_path.join("subspace_bench_sector.bin");
        let mut plot_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&plot_file_path)
            .unwrap();

        plot_file
            .preallocate(PLOT_SECTOR_SIZE * sectors_count)
            .unwrap();
        plot_file.advise_random_access().unwrap();

        for _i in 0..sectors_count {
            plot_file.write_all(plotted_sector.as_slice()).unwrap();
        }

        let plot_mmap = unsafe { Mmap::map(&plot_file).unwrap() };

        #[cfg(unix)]
        {
            plot_mmap.advise(memmap2::Advice::Random).unwrap();
        }

        b.iter_custom(|iters| {
            let start = Instant::now();
            for _i in 0..iters {
                for (sector_index, sector) in plot_mmap
                    .chunks_exact(PLOT_SECTOR_SIZE as usize)
                    .enumerate()
                    .map(|(sector_index, sector)| (sector_index as u64, sector))
                {
                    audit_sector(
                        black_box(&public_key),
                        black_box(sector_index),
                        black_box(&global_challenge),
                        black_box(solution_range),
                        black_box(io::Cursor::new(sector)),
                    )
                    .unwrap();
                }
            }
            start.elapsed()
        });

        drop(plot_file);
        fs::remove_file(plot_file_path).unwrap();
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
