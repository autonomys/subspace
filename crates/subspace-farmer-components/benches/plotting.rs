use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use futures::executor::block_on;
use rand::{thread_rng, Rng};
use std::num::{NonZeroU64, NonZeroUsize};
use std::{env, io};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    HistorySize, PublicKey, Record, RecordedHistorySegment, SegmentIndex, PIECES_IN_SECTOR,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::plotting::{plot_sector, PieceGetterRetryPolicy};
use subspace_farmer_components::sector::sector_size;
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_proof_of_space::chia::ChiaTable;

fn criterion_benchmark(c: &mut Criterion) {
    println!("Initializing...");
    let pieces_in_sector = env::var("PIECES_IN_SECTOR")
        .map(|base_path| base_path.parse().unwrap())
        .unwrap_or_else(|_error| PIECES_IN_SECTOR);

    let public_key = PublicKey::default();
    let sector_index = 0;
    let mut input = RecordedHistorySegment::new_boxed();
    thread_rng().fill(AsMut::<[u8]>::as_mut(input.as_mut()));
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
        sector_expiration: SegmentIndex::ONE,
    };

    let mut group = c.benchmark_group("plotting");
    group.throughput(Throughput::Bytes(sector_size(pieces_in_sector) as u64));
    group.bench_function("no-writes", |b| {
        b.iter(|| {
            block_on(plot_sector::<_, _, _, ChiaTable>(
                black_box(&public_key),
                black_box(sector_index),
                black_box(&archived_history_segment),
                black_box(PieceGetterRetryPolicy::default()),
                black_box(&farmer_protocol_info),
                black_box(&kzg),
                black_box(&erasure_coding),
                black_box(pieces_in_sector),
                black_box(&mut io::sink()),
                black_box(&mut io::sink()),
                Default::default(),
            ))
            .unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
