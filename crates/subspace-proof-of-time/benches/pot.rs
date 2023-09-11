use core::num::NonZeroU32;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use subspace_core_primitives::PotSeed;
use subspace_proof_of_time::{prove, verify};

fn criterion_benchmark(c: &mut Criterion) {
    let mut seed = PotSeed::default();
    thread_rng().fill(seed.as_mut());
    // About 1s on 5.5 GHz Raptor Lake CPU
    let pot_iterations = NonZeroU32::new(183_270_000).expect("Not zero; qed");

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
                black_box(&*checkpoints),
            ))
            .unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
