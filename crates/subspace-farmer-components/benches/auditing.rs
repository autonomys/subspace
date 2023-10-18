use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use futures::executor::block_on;
use rand::prelude::*;
use std::fs::OpenOptions;
use std::io::Write;
use std::num::{NonZeroU64, NonZeroUsize};
use std::time::Instant;
use std::{env, fs};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    Blake3Hash, HistorySize, PublicKey, Record, RecordedHistorySegment, SectorId, SectorIndex,
    SolutionRange,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::auditing::audit_sector;
use subspace_farmer_components::file_ext::{FileExt, OpenOptionsExt};
use subspace_farmer_components::plotting::{
    plot_sector, PieceGetterRetryPolicy, PlotSectorOptions, PlottedSector,
};
use subspace_farmer_components::sector::{
    sector_size, SectorContentsMap, SectorMetadata, SectorMetadataChecksummed,
};
use subspace_farmer_components::{FarmerProtocolInfo, ReadAt};
use subspace_proof_of_space::chia::ChiaTable;
use subspace_proof_of_space::Table;

type PosTable = ChiaTable;

const MAX_PIECES_IN_SECTOR: u16 = 1000;

pub fn criterion_benchmark(c: &mut Criterion) {
    println!("Initializing...");
    let base_path = env::var("BASE_PATH")
        .map(|base_path| base_path.parse().unwrap())
        .unwrap_or_else(|_error| env::temp_dir());
    let pieces_in_sector = env::var("PIECES_IN_SECTOR")
        .map(|base_path| base_path.parse().unwrap())
        .unwrap_or_else(|_error| MAX_PIECES_IN_SECTOR);
    let persist_sector = env::var("PERSIST_SECTOR")
        .map(|persist_sector| persist_sector == "1")
        .unwrap_or_else(|_error| false);
    let sectors_count = env::var("SECTORS_COUNT")
        .map(|sectors_count| sectors_count.parse().unwrap())
        .unwrap_or(10);

    let public_key = PublicKey::default();
    let sector_index = 0;
    let mut input = RecordedHistorySegment::new_boxed();
    StdRng::seed_from_u64(42).fill(AsMut::<[u8]>::as_mut(input.as_mut()));
    let kzg = Kzg::new(kzg::embedded_kzg_settings());
    let mut archiver = Archiver::new(kzg.clone()).unwrap();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut table_generator = PosTable::generator();
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
    let global_challenge = Blake3Hash::default();
    let solution_range = SolutionRange::MAX;

    let sector_size = sector_size(pieces_in_sector);

    let persisted_sector = base_path.join(format!("subspace_bench_sector_{pieces_in_sector}.plot"));

    let (plotted_sector, plotted_sector_bytes) = if persist_sector && persisted_sector.is_file() {
        println!(
            "Reading persisted sector from {}...",
            persisted_sector.display()
        );

        let plotted_sector_bytes = fs::read(&persisted_sector).unwrap();
        let sector_contents_map = SectorContentsMap::from_bytes(
            &plotted_sector_bytes[..SectorContentsMap::encoded_size(pieces_in_sector)],
            pieces_in_sector,
        )
        .unwrap();
        let sector_metadata = SectorMetadataChecksummed::from(SectorMetadata {
            sector_index,
            pieces_in_sector,
            s_bucket_sizes: sector_contents_map.s_bucket_sizes(),
            history_size: farmer_protocol_info.history_size,
        });

        (
            PlottedSector {
                sector_id: SectorId::new(public_key.hash(), sector_index),
                sector_index,
                sector_metadata,
                piece_indexes: vec![],
            },
            plotted_sector_bytes,
        )
    } else {
        println!("Plotting one sector...");

        let mut plotted_sector_bytes = Vec::new();
        let mut plotted_sector_metadata_bytes = Vec::new();

        let plotted_sector = block_on(plot_sector::<PosTable, _>(PlotSectorOptions {
            public_key: &public_key,
            sector_index,
            piece_getter: &archived_history_segment,
            piece_getter_retry_policy: PieceGetterRetryPolicy::default(),
            farmer_protocol_info: &farmer_protocol_info,
            kzg: &kzg,
            erasure_coding: &erasure_coding,
            pieces_in_sector,
            sector_output: &mut plotted_sector_bytes,
            sector_metadata_output: &mut plotted_sector_metadata_bytes,
            downloading_semaphore: black_box(None),
            encoding_semaphore: black_box(None),
            table_generator: &mut table_generator,
        }))
        .unwrap();

        (plotted_sector, plotted_sector_bytes)
    };

    assert_eq!(plotted_sector_bytes.len(), sector_size);

    if persist_sector && !persisted_sector.is_file() {
        println!(
            "Writing persisted sector into {}...",
            persisted_sector.display()
        );
        fs::write(persisted_sector, &plotted_sector_bytes).unwrap()
    }

    let mut group = c.benchmark_group("auditing");
    group.throughput(Throughput::Elements(1));
    group.bench_function("memory", |b| {
        b.iter(|| {
            audit_sector(
                black_box(&public_key),
                black_box(sector_index),
                black_box(&global_challenge),
                black_box(solution_range),
                black_box(&plotted_sector_bytes),
                black_box(&plotted_sector.sector_metadata),
            );
        })
    });

    {
        println!("Writing {sectors_count} sectors to disk...");

        let plot_file_path = base_path.join("subspace_bench_plot.plot");
        let mut plot_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .advise_random_access()
            .open(&plot_file_path)
            .unwrap();

        plot_file
            .preallocate(sector_size as u64 * sectors_count)
            .unwrap();
        plot_file.advise_random_access().unwrap();

        for _i in 0..sectors_count {
            plot_file
                .write_all(plotted_sector_bytes.as_slice())
                .unwrap();
        }

        group.throughput(Throughput::Elements(sectors_count));
        group.bench_function("disk", |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _i in 0..iters {
                    for sector_index in 0..sectors_count as usize {
                        let sector = plot_file.offset(sector_index * sector_size);
                        audit_sector(
                            black_box(&public_key),
                            black_box(sector_index as SectorIndex),
                            black_box(&global_challenge),
                            black_box(solution_range),
                            black_box(&sector),
                            black_box(&plotted_sector.sector_metadata),
                        );
                    }
                }
                start.elapsed()
            });
        });

        drop(plot_file);
        fs::remove_file(plot_file_path).unwrap();
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
