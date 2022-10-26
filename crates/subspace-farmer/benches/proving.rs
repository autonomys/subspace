use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use futures::executor::block_on;
use memmap2::Mmap;
use schnorrkel::Keypair;
use std::fs::OpenOptions;
use std::io::Write;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::sync::atomic::AtomicBool;
use std::time::Instant;
use std::{env, fs, io};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    plot_sector_size, Blake2b256Hash, Piece, PublicKey, SolutionRange, PIECES_IN_SEGMENT,
    RECORD_SIZE,
};
use subspace_farmer::file_ext::FileExt;
use subspace_farmer::single_disk_plot::farming::audit_sector;
use subspace_farmer::single_disk_plot::piece_receiver::BenchPieceReceiver;
use subspace_farmer::single_disk_plot::plotting::plot_sector;
use subspace_farmer::single_disk_plot::SectorMetadata;
use subspace_rpc_primitives::FarmerProtocolInfo;

// This is helpful for overriding locally for benching different parameters
pub const RECORDED_HISTORY_SEGMENT_SIZE: u32 = RECORD_SIZE * PIECES_IN_SEGMENT / 2;

pub fn criterion_benchmark(c: &mut Criterion) {
    let base_path = env::var("BASE_PATH")
        .map(|base_path| base_path.parse().unwrap())
        .unwrap_or_else(|_error| env::temp_dir());
    let sectors_count = env::var("SECTORS_COUNT")
        .map(|sectors_count| sectors_count.parse().unwrap())
        .unwrap_or(10);

    let keypair = Keypair::from_bytes(&[0; 96]).unwrap();
    let public_key = PublicKey::from(keypair.public.to_bytes());
    let sector_index = 0;
    let input = vec![1u8; RECORDED_HISTORY_SEGMENT_SIZE as usize];
    let kzg = Kzg::new(kzg::test_public_parameters());
    let mut archiver = Archiver::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg).unwrap();
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

    let cancelled = AtomicBool::new(false);
    let farmer_protocol_info = FarmerProtocolInfo {
        genesis_hash: Default::default(),
        record_size: NonZeroU32::new(RECORD_SIZE).unwrap(),
        recorded_history_segment_size: RECORDED_HISTORY_SEGMENT_SIZE,
        total_pieces: NonZeroU64::new(1).unwrap(),
        space_l: NonZeroU16::new(20).unwrap(),
        sector_expiration: 1,
    };
    let global_challenge = Blake2b256Hash::default();
    let solution_range = SolutionRange::MAX;
    let reward_address = PublicKey::default();

    let plot_sector_size = plot_sector_size(farmer_protocol_info.space_l);

    let (plotted_sector, sector_metadata) = {
        let mut plotted_sector = vec![0u8; plot_sector_size as usize];
        let mut sector_metadata = vec![0u8; SectorMetadata::encoded_size()];

        block_on(plot_sector(
            &public_key,
            sector_index,
            &mut BenchPieceReceiver::new(piece),
            &cancelled,
            &farmer_protocol_info,
            plotted_sector.as_mut_slice(),
            sector_metadata.as_mut_slice(),
        ))
        .unwrap();

        (plotted_sector, sector_metadata)
    };

    let eligible_sector = audit_sector(
        &public_key,
        sector_index,
        &farmer_protocol_info,
        &global_challenge,
        solution_range,
        io::Cursor::new(plotted_sector),
    )
    .unwrap()
    .unwrap();

    let mut group = c.benchmark_group("proving");
    group.throughput(Throughput::Elements(1));
    group.bench_function("memory", |b| {
        b.iter(|| {
            eligible_sector
                .clone()
                .try_into_solution(
                    black_box(&keypair),
                    black_box(reward_address),
                    black_box(&farmer_protocol_info),
                    black_box(sector_metadata.as_slice()),
                )
                .unwrap();
        })
    });

    group.throughput(Throughput::Elements(sectors_count));
    group.bench_function("disk", |b| {
        let plot_file_path = base_path.join("subspace_bench_sector.bin");
        let mut metadata_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&plot_file_path)
            .unwrap();

        metadata_file
            .preallocate(SectorMetadata::encoded_size() as u64 * sectors_count)
            .unwrap();
        metadata_file.advise_random_access().unwrap();

        for _i in 0..sectors_count {
            metadata_file.write_all(sector_metadata.as_slice()).unwrap();
        }

        let sector_metadata_mmap = unsafe { Mmap::map(&metadata_file).unwrap() };

        #[cfg(unix)]
        {
            sector_metadata_mmap
                .advise(memmap2::Advice::Random)
                .unwrap();
        }

        b.iter_custom(|iters| {
            let start = Instant::now();
            for _i in 0..iters {
                for metadata in sector_metadata_mmap.chunks_exact(SectorMetadata::encoded_size()) {
                    eligible_sector
                        .clone()
                        .try_into_solution(
                            black_box(&keypair),
                            black_box(reward_address),
                            black_box(&farmer_protocol_info),
                            black_box(metadata),
                        )
                        .unwrap();
                }
            }
            start.elapsed()
        });

        drop(metadata_file);
        fs::remove_file(plot_file_path).unwrap();
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
