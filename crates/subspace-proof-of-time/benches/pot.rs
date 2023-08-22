use core::num::NonZeroU32;
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
    // About 1s on 5.5 GHz Raptor Lake CPU
    let pot_iterations = NonZeroU32::new(183_270_000).expect("Not zero; qed");
    let proof_of_time = ProofOfTime::new(pot_iterations).unwrap();

    c.bench_function("prove", |b| {
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
