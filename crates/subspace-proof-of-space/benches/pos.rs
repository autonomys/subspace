#![feature(const_trait_impl)]

#[cfg(any(feature = "chia-legacy", feature = "chia", feature = "shim"))]
use criterion::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "parallel")]
use rayon::ThreadPoolBuilder;
#[cfg(any(feature = "chia-legacy", feature = "chia", feature = "shim"))]
use subspace_core_primitives::PosSeed;
#[cfg(any(feature = "chia-legacy", feature = "chia", feature = "shim"))]
use subspace_proof_of_space::{Quality, Table};

#[cfg(any(feature = "chia-legacy", feature = "chia", feature = "shim"))]
const SEED: PosSeed = PosSeed::from([
    35, 2, 52, 4, 51, 55, 23, 84, 91, 10, 111, 12, 13, 222, 151, 16, 228, 211, 254, 45, 92, 198,
    204, 10, 9, 10, 11, 129, 139, 171, 15, 23,
]);

#[cfg(any(feature = "chia-legacy", feature = "chia", feature = "shim"))]
fn pos_bench<PosTable>(
    c: &mut Criterion,
    name: &'static str,
    challenge_index_without_solution: u32,
    challenge_index_with_solution: u32,
) where
    PosTable: Table,
{
    ThreadPoolBuilder::new()
        // Change number of threads if necessary
        .num_threads(4)
        .build_global()
        .unwrap();

    let mut group = c.benchmark_group(name);

    group.bench_function("table/single", |b| {
        b.iter(|| {
            PosTable::generate(black_box(&SEED));
        });
    });

    #[cfg(feature = "parallel")]
    {
        group.bench_function("table/parallel", |b| {
            b.iter(|| {
                PosTable::generate_parallel(black_box(&SEED));
            });
        });
    }

    let table = PosTable::generate(&SEED);

    group.bench_function("quality/no-solution", |b| {
        b.iter(|| {
            assert!(table
                .find_quality(black_box(challenge_index_without_solution))
                .is_none());
        });
    });

    group.bench_function("quality/solution", |b| {
        b.iter(|| {
            assert!(table
                .find_quality(black_box(challenge_index_with_solution))
                .is_some());
        });
    });

    let quality = table.find_quality(challenge_index_with_solution).unwrap();

    group.bench_function("proof", |b| {
        b.iter(|| {
            quality.create_proof();
        });
    });

    let proof = quality.create_proof();

    group.bench_function("verification", |b| {
        b.iter(|| {
            assert!(
                PosTable::is_proof_valid(&SEED, challenge_index_with_solution, &proof).is_some()
            );
        });
    });
    group.finish();
}

pub fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(not(any(feature = "chia-legacy", feature = "chia", feature = "shim")))]
    {
        let _ = c;
        panic!(r#"Enable "chia" and/or "shim" feature to run benches"#);
    }
    #[cfg(feature = "chia-legacy")]
    {
        // This challenge index with above seed is known to not have a solution
        let challenge_index_without_solution = 0;
        // This challenge index with above seed is known to have a solution
        let challenge_index_with_solution = 1;

        pos_bench::<subspace_proof_of_space::chia_legacy::ChiaTable>(
            c,
            "chia-legacy",
            challenge_index_without_solution,
            challenge_index_with_solution,
        )
    }
    #[cfg(feature = "chia")]
    {
        // This challenge index with above seed is known to not have a solution
        let challenge_index_without_solution = 1232460437;
        // This challenge index with above seed is known to have a solution
        let challenge_index_with_solution = 124537303;

        pos_bench::<subspace_proof_of_space::chia::ChiaTable>(
            c,
            "chia",
            challenge_index_without_solution,
            challenge_index_with_solution,
        )
    }
    #[cfg(feature = "shim")]
    {
        // This challenge index with above seed is known to not have a solution
        let challenge_index_without_solution = 0;
        // This challenge index with above seed is known to have a solution
        let challenge_index_with_solution = 2;

        pos_bench::<subspace_proof_of_space::shim::ShimTable>(
            c,
            "shim",
            challenge_index_without_solution,
            challenge_index_with_solution,
        )
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
