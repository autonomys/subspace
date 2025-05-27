use core::num::NonZeroU32;
use criterion::{criterion_group, criterion_main, Criterion};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use std::hint::black_box;
use subspace_core_primitives::pot::PotSeed;
use subspace_proof_of_time::{prove, verify};

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::from_seed(Default::default());
    let mut seed = PotSeed::default();
    rng.fill_bytes(seed.as_mut());
    // About 1s on 6.0 GHz Raptor Lake CPU (14900K)
    let pot_iterations = NonZeroU32::new(200_032_000).expect("Not zero; qed");

    c.bench_function("prove", |b| {
        b.iter(|| {
            black_box(prove(black_box(seed), black_box(pot_iterations))).unwrap();
        })
    });

    let checkpoints = prove(seed, pot_iterations).unwrap();

    c.bench_function("verify", |b| {
        b.iter(|| {
            black_box(verify(
                black_box(seed),
                black_box(pot_iterations),
                black_box(&checkpoints),
            ))
            .unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
