use core::num::{NonZeroU32, NonZeroU8};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use subspace_core_primitives::{BlockHash, PotKey, PotSeed};
use subspace_proof_of_time::ProofOfTime;

fn criterion_benchmark(c: &mut Criterion) {
    let mut seed = PotSeed::default();
    thread_rng().fill(seed.as_mut());
    let mut key = PotKey::default();
    thread_rng().fill(key.as_mut());
    let slot_number = 1;
    let mut injected_block_hash = BlockHash::default();
    thread_rng().fill(injected_block_hash.as_mut());
    let checkpoints_1 = NonZeroU8::new(1).expect("Creating checkpoints cannot fail");
    let checkpoints_8 = NonZeroU8::new(8).expect("Creating checkpoints cannot fail");
    // About 1s on 5.5 GHz Raptor Lake CPU
    let pot_iterations = NonZeroU32::new(166_000_000).expect("Creating pot_iterations cannot fail");
    let proof_of_time_sequential = ProofOfTime::new(pot_iterations, checkpoints_1)
        .expect("Failed to create proof_of_time_sequential");
    let proof_of_time =
        ProofOfTime::new(pot_iterations, checkpoints_8).expect("Failed to create proof_of_time");

    c.bench_function("prove/sequential", |b| {
        b.iter(|| {
            proof_of_time_sequential.create(
                black_box(seed),
                black_box(key),
                black_box(slot_number),
                black_box(injected_block_hash),
            );
        })
    });

    c.bench_function("prove/checkpoints", |b| {
        b.iter(|| {
            proof_of_time.create(
                black_box(seed),
                black_box(key),
                black_box(slot_number),
                black_box(injected_block_hash),
            );
        })
    });

    let proof = proof_of_time.create(seed, key, slot_number, injected_block_hash);

    c.bench_function("verify", |b| {
        b.iter(|| {
            proof_of_time.verify(black_box(&proof)).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
