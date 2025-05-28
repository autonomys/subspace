use core::num::NonZeroU32;
use criterion::{criterion_group, criterion_main, Criterion};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use std::hint::black_box;
use subspace_core_primitives::pot::PotSeed;
use subspace_proof_of_time::prove;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::from_seed(Default::default());
    let mut seed = PotSeed::default();
    rng.fill_bytes(seed.as_mut());
    // About 1s on 6.0 GHz Raptor Lake CPU (14900K)
    let pot_iterations = NonZeroU32::new(200_032_000).expect("Not zero; qed");

    let cpu_cores = core_affinity::get_core_ids().expect("Must be able to get CPU cores");
    for cpu_core in cpu_cores {
        if !core_affinity::set_for_current(cpu_core) {
            panic!("Failed to set CPU affinity");
        }

        c.bench_function(&format!("prove/cpu-{}", cpu_core.id), move |b| {
            b.iter(|| {
                black_box(prove(black_box(seed), black_box(pot_iterations))).unwrap();
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
