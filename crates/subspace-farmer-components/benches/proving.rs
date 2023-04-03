use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use futures::executor::block_on;
use memmap2::Mmap;
use rand::{thread_rng, Rng};
use schnorrkel::Keypair;
use std::fs::OpenOptions;
use std::io::Write;
use std::num::NonZeroU64;
use std::time::Instant;
use std::{env, fs, io};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::sector_codec::SectorCodec;
use subspace_core_primitives::{
    Blake2b256Hash, Piece, PublicKey, RecordedHistorySegment, SegmentIndex, SolutionRange,
    PLOT_SECTOR_SIZE,
};
use subspace_farmer_components::farming::audit_sector;
use subspace_farmer_components::file_ext::FileExt;
use subspace_farmer_components::plotting::{plot_sector, PieceGetterRetryPolicy};
use subspace_farmer_components::{FarmerProtocolInfo, SectorMetadata};
use utils::BenchPieceGetter;

mod utils;

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
    let mut input = RecordedHistorySegment::new_boxed();
    thread_rng().fill(AsMut::<[u8]>::as_mut(input.as_mut()));
    let kzg = Kzg::new(kzg::embedded_kzg_settings());
    let mut archiver = Archiver::new(kzg.clone()).unwrap();
    let sector_codec = SectorCodec::new(PLOT_SECTOR_SIZE as usize).unwrap();
    let piece = Piece::from(
        &archiver
            .add_block(
                AsRef::<[u8]>::as_ref(input.as_ref()).to_vec(),
                Default::default(),
            )
            .into_iter()
            .next()
            .unwrap()
            .pieces[0],
    );

    let farmer_protocol_info = FarmerProtocolInfo {
        total_pieces: NonZeroU64::new(1).unwrap(),
        sector_expiration: SegmentIndex::ONE,
    };
    let global_challenge = Blake2b256Hash::default();
    let solution_range = SolutionRange::MAX;
    let reward_address = PublicKey::default();

    let (plotted_sector, sector_metadata) = {
        let mut plotted_sector = vec![0u8; PLOT_SECTOR_SIZE as usize];
        let mut sector_metadata = vec![0u8; SectorMetadata::encoded_size()];

        block_on(plot_sector(
            &public_key,
            sector_index,
            &BenchPieceGetter::new(piece),
            PieceGetterRetryPolicy::default(),
            &farmer_protocol_info,
            &kzg,
            &sector_codec,
            plotted_sector.as_mut_slice(),
            sector_metadata.as_mut_slice(),
            Default::default(),
        ))
        .unwrap();

        (plotted_sector, sector_metadata)
    };

    let eligible_sector = audit_sector(
        &public_key,
        sector_index,
        &global_challenge,
        solution_range,
        io::Cursor::new(plotted_sector.as_slice()),
    )
    .unwrap()
    .unwrap();

    let mut group = c.benchmark_group("proving");
    group.throughput(Throughput::Elements(1));
    group.bench_function("memory", |b| {
        b.iter(|| {
            eligible_sector
                .clone()
                .try_into_solutions(
                    black_box(&keypair),
                    black_box(reward_address),
                    black_box(&sector_codec),
                    black_box(plotted_sector.as_slice()),
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
                        .try_into_solutions(
                            black_box(&keypair),
                            black_box(reward_address),
                            black_box(&sector_codec),
                            black_box(plotted_sector.as_slice()),
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
