use criterion::{black_box, criterion_group, criterion_main, Criterion};
use subspace_core_primitives::PosSeed;
use subspace_proof_of_space::chia::ChiaTable;
#[cfg(feature = "shim")]
use subspace_proof_of_space::shim::ShimTable;
use subspace_proof_of_space::{Quality, Table};

pub fn criterion_benchmark(c: &mut Criterion) {
    let seed = PosSeed::from([
        35, 2, 52, 4, 51, 55, 23, 84, 91, 10, 111, 12, 13, 222, 151, 16, 228, 211, 254, 45, 92,
        198, 204, 10, 9, 10, 11, 129, 139, 171, 15, 23,
    ]);
    {
        // This challenge index with above seed is known to not have a solution
        let challenge_index_without_solution = 0;
        // This challenge index with above seed is known to have a solution
        let challenge_index_with_solution = 1;

        let mut group = c.benchmark_group("chia");

        group.bench_function("table", |b| {
            b.iter(|| {
                ChiaTable::generate(black_box(&seed));
            });
        });

        let table = ChiaTable::generate(&seed);

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
                    ChiaTable::is_proof_valid(&seed, challenge_index_with_solution, &proof)
                        .is_some()
                );
            });
        });
        group.finish();
    }
    #[cfg(feature = "shim")]
    {
        // This challenge index with above seed is known to not have a solution
        let challenge_index_without_solution = 0;
        // This challenge index with above seed is known to have a solution
        let challenge_index_with_solution = 2;

        let mut group = c.benchmark_group("shim");

        group.bench_function("table", |b| {
            b.iter(|| {
                ShimTable::generate(black_box(&seed));
            });
        });

        let table = ShimTable::generate(&seed);

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
                    ShimTable::is_proof_valid(&seed, challenge_index_with_solution, &proof)
                        .is_some()
                );
            });
        });
        group.finish();
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
