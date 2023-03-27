use blst_from_scratch::types::g1::FsG1;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kzg::G1;
use std::num::NonZeroUsize;
use subspace_core_primitives::crypto::kzg::Commitment;
use subspace_erasure_coding::ErasureCoding;

fn criterion_benchmark(c: &mut Criterion) {
    let scale = NonZeroUsize::new(8).unwrap();
    let num_shards = 2usize.pow(scale.get() as u32);
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
