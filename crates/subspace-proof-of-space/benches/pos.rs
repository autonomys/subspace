#![feature(const_trait_impl)]

#[cfg(feature = "alloc")]
use criterion::Throughput;
use criterion::{Criterion, criterion_group, criterion_main};
#[cfg(feature = "parallel")]
use rayon::ThreadPoolBuilder;
#[cfg(feature = "alloc")]
use std::hint::black_box;
#[cfg(feature = "alloc")]
use subspace_core_primitives::pieces::Record;
#[cfg(feature = "alloc")]
use subspace_core_primitives::pos::PosSeed;
use subspace_proof_of_space::Table;
#[cfg(feature = "alloc")]
use subspace_proof_of_space::TableGenerator;

#[cfg(not(feature = "alloc"))]
#[expect(
    clippy::extra_unused_type_parameters,
    reason = "Needs to match the normal version of the function"
)]
fn pos_bench<PosTable>(
    _c: &mut Criterion,
    _name: &'static str,
    _challenge_index_without_solution: u32,
    _challenge_index_with_solution: u32,
) where
    PosTable: Table,
{
    panic!(
        "`alloc` feature needs to be enabled to run benchmarks (`parallel` for benchmarking \
        parallel version)"
    )
}

#[cfg(feature = "alloc")]
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

    let generator = PosTable::generator();
    group.throughput(Throughput::Elements(1));
    group.bench_function("table/single/1x", |b| {
        b.iter(|| {
            generator.generate(black_box(&seed));
        });
    });

    #[cfg(feature = "parallel")]
    {
        {
            group.throughput(Throughput::Elements(2));
            group.bench_function("table/single/2x", |b| {
                b.iter(|| {
                    rayon::scope(|scope| {
                        for _ in 0..2 {
                            scope.spawn(|_scope| {
                                generator.generate(black_box(&seed));
                            });
                        }
                    });
                });
            });
        }

        {
            group.throughput(Throughput::Elements(4));
            group.bench_function("table/single/4x", |b| {
                b.iter(|| {
                    rayon::scope(|scope| {
                        for _ in 0..4 {
                            scope.spawn(|_scope| {
                                generator.generate(black_box(&seed));
                            });
                        }
                    });
                });
            });
        }

        {
            group.throughput(Throughput::Elements(8));
            group.bench_function("table/single/8x", |b| {
                b.iter(|| {
                    rayon::scope(|scope| {
                        for _ in 0..8 {
                            scope.spawn(|_scope| {
                                generator.generate(black_box(&seed));
                            });
                        }
                    });
                });
            });
        }

        {
            group.throughput(Throughput::Elements(16));
            group.bench_function("table/single/16x", |b| {
                b.iter(|| {
                    rayon::scope(|scope| {
                        for _ in 0..16 {
                            scope.spawn(|_scope| {
                                generator.generate(black_box(&seed));
                            });
                        }
                    });
                });
            });
        }
    }

    #[cfg(feature = "parallel")]
    {
        group.throughput(Throughput::Elements(1));
        group.bench_function("table/parallel/1x", |b| {
            b.iter(|| {
                generator.generate_parallel(black_box(&seed));
            });
        });

        group.throughput(Throughput::Elements(2));
        group.bench_function("table/parallel/2x", |b| {
            b.iter(|| {
                rayon::scope(|scope| {
                    for _ in 0..2 {
                        scope.spawn(|_scope| {
                            generator.generate_parallel(black_box(&seed));
                        });
                    }
                });
            });
        });

        group.throughput(Throughput::Elements(4));
        group.bench_function("table/parallel/4x", |b| {
            b.iter(|| {
                rayon::scope(|scope| {
                    for _ in 0..4 {
                        scope.spawn(|_scope| {
                            generator.generate_parallel(black_box(&seed));
                        });
                    }
                });
            });
        });

        group.throughput(Throughput::Elements(8));
        group.bench_function("table/parallel/8x", |b| {
            b.iter(|| {
                rayon::scope(|scope| {
                    for _ in 0..8 {
                        scope.spawn(|_scope| {
                            generator.generate_parallel(black_box(&seed));
                        });
                    }
                });
            });
        });

        group.throughput(Throughput::Elements(16));
        group.bench_function("table/parallel/16x", |b| {
            b.iter(|| {
                rayon::scope(|scope| {
                    for _ in 0..16 {
                        scope.spawn(|_scope| {
                            generator.generate_parallel(black_box(&seed));
                        });
                    }
                });
            });
        });
    }

    let table = generator.generate(&seed);

    group.throughput(Throughput::Elements(1));
    group.bench_function("proof/missing", |b| {
        b.iter(|| {
            assert!(
                table
                    .find_proof(black_box(challenge_index_without_solution))
                    .is_none()
            );
        });
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("proof/present", |b| {
        b.iter(|| {
            assert!(
                table
                    .find_proof(black_box(challenge_index_with_solution))
                    .is_some()
            );
        });
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("proof/for-record", |b| {
        b.iter(|| {
            let mut found_proofs = 0_usize;
            for challenge_index in 0..Record::NUM_S_BUCKETS as u32 {
                if table.find_proof(black_box(challenge_index)).is_some() {
                    found_proofs += 1;

                    if found_proofs == Record::NUM_CHUNKS {
                        break;
                    }
                }
            }
        });
    });

    let proof = table.find_proof(challenge_index_with_solution).unwrap();

    group.throughput(Throughput::Elements(1));
    group.bench_function("verification", |b| {
        b.iter(|| {
            assert!(<PosTable as Table>::is_proof_valid(
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
        let challenge_index_without_solution = 1;
        // This challenge index with above seed is known to have a solution
        let challenge_index_with_solution = 0;

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
