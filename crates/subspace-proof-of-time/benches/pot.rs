use core::num::{NonZeroU32, NonZeroU8};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use subspace_core_primitives::{PotKey, PotSeed};
use subspace_proof_of_time::ProofOfTime;

fn criterion_benchmark(c: &mut Criterion) {
    let mut seed = PotSeed::default();
    thread_rng().fill(seed.as_mut());
    let mut key = PotKey::default();
    thread_rng().fill(key.as_mut());
    let checkpoints_1 = NonZeroU8::new(1).expect("Not zero; qed");
    let checkpoints_8 = NonZeroU8::new(8).expect("Not zero; qed");
    // About 1s on 5.5 GHz Raptor Lake CPU
    let pot_iterations = NonZeroU32::new(183_270_000).expect("Not zero; qed");
    let proof_of_time_sequential = ProofOfTime::new(pot_iterations, checkpoints_1).unwrap();
    let proof_of_time = ProofOfTime::new(pot_iterations, checkpoints_8).unwrap();

    c.bench_function("prove/sequential", |b| {
        b.iter(|| {
            proof_of_time_sequential.create(black_box(&seed), black_box(&key));
        })
    });

    c.bench_function("prove/checkpoints", |b| {
        b.iter(|| {
            proof_of_time.create(black_box(&seed), black_box(&key));
        })
    });

    let checkpoints = proof_of_time.create(&seed, &key);

    c.bench_function("verify", |b| {
        b.iter(|| {
            proof_of_time
                .verify(black_box(&seed), black_box(&key), black_box(&checkpoints))
                .unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
