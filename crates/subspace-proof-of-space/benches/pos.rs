#![feature(const_trait_impl)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(feature = "parallel")]
use rayon::ThreadPoolBuilder;
use subspace_core_primitives::PosSeed;
use subspace_proof_of_space::{Table, TableGenerator};

fn pos_bench<PosTable>(
    c: &mut Criterion,
    name: &'static str,
    challenge_index_without_solution: u32,
    challenge_index_with_solution: u32,
) where
    PosTable: Table,
{
    let seed = PosSeed::from([
        35, 2, 52, 4, 51, 55, 23, 84, 91, 10, 111, 12, 13, 222, 151, 16, 228, 211, 254, 45, 92,
        198, 204, 10, 9, 10, 11, 129, 139, 171, 15, 23,
    ]);

    #[cfg(feature = "parallel")]
    {
        // Repeated initialization is not supported, we just ignore errors here because of it
        let _ = ThreadPoolBuilder::new()
            // Change number of threads if necessary
            // .num_threads(4)
            .build_global();
    }

    let mut group = c.benchmark_group(name);

    let mut generator_instance = PosTable::generator();
    group.bench_function("table/single", |b| {
        b.iter(|| {
            generator_instance.generate(black_box(&seed));
        });
    });

    #[cfg(feature = "parallel")]
    {
        let mut generator_instance = PosTable::generator();
        group.bench_function("table/parallel/1x", |b| {
            b.iter(|| {
                generator_instance.generate_parallel(black_box(&seed));
            });
        });

        let mut generator_instances = [
            PosTable::generator(),
            PosTable::generator(),
            PosTable::generator(),
            PosTable::generator(),
            PosTable::generator(),
            PosTable::generator(),
            PosTable::generator(),
            PosTable::generator(),
        ];
        group.bench_function("table/parallel/8x", |b| {
            b.iter(|| {
                rayon::scope(|scope| {
                    for g in &mut generator_instances {
                        scope.spawn(|_scope| {
                            g.generate_parallel(black_box(&seed));
                        });
                    }
                });
            });
        });
    }

    let table = generator_instance.generate(&seed);

    group.bench_function("proof/missing", |b| {
        b.iter(|| {
            assert!(table
                .find_proof(black_box(challenge_index_without_solution))
                .is_none());
        });
    });

    group.bench_function("proof/present", |b| {
        b.iter(|| {
            assert!(table
                .find_proof(black_box(challenge_index_with_solution))
                .is_some());
        });
    });

    let proof = table.find_proof(challenge_index_with_solution).unwrap();

    group.bench_function("verification", |b| {
        b.iter(|| {
            assert!(PosTable::is_proof_valid(
                &seed,
                challenge_index_with_solution,
                &proof
            ));
        });
    });
    group.finish();
}

pub fn criterion_benchmark(c: &mut Criterion) {
    {
        // This challenge index with above seed is known to not have a solution
        let challenge_index_without_solution = 1232460437;
        // This challenge index with above seed is known to have a solution
        let challenge_index_with_solution = 600426542;

        pos_bench::<subspace_proof_of_space::chia::ChiaTable>(
            c,
            "chia",
            challenge_index_without_solution,
            challenge_index_with_solution,
        )
    }
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
