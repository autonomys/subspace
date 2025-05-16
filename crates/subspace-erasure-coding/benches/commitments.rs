use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kzg::G1;
use rust_kzg_blst::types::g1::FsG1;
use std::num::NonZeroUsize;
use subspace_core_primitives::segments::ArchivedHistorySegment;
use subspace_erasure_coding::ErasureCoding;
use subspace_kzg::Commitment;

fn criterion_benchmark(c: &mut Criterion) {
    let num_shards = ArchivedHistorySegment::NUM_PIECES;
    let scale = NonZeroUsize::new(num_shards.ilog2() as usize)
        .expect("Recorded history segment contains at very least one record; qed");
    let ec = ErasureCoding::new(scale).unwrap();

    let source_commitments = (0..num_shards / 2)
        .map(|_| Commitment::from(FsG1::rand()))
        .collect::<Vec<_>>();

    c.bench_function("extend", |b| {
        b.iter(|| {
            ec.extend_commitments(black_box(&source_commitments))
                .unwrap()
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
