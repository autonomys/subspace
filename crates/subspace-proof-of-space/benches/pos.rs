use criterion::{black_box, criterion_group, criterion_main, Criterion};
use subspace_core_primitives::PosSeed;
use subspace_proof_of_space::Table;

pub fn criterion_benchmark(c: &mut Criterion) {
    let seed = PosSeed([
        35, 2, 52, 4, 51, 55, 23, 84, 91, 10, 111, 12, 13, 222, 151, 16, 228, 211, 254, 45, 92,
        198, 204, 10, 9, 10, 11, 129, 139, 171, 15, 23,
    ]);
    // This challenge index with above seed is known to not have a solution
    let challenge_index_without_solution = 0;
    // This challenge index with above seed is known to have a solution
    let challenge_index_with_solution = 1;

    let mut group = c.benchmark_group("pos");

    group.bench_function("table", |b| {
        b.iter(|| {
            Table::generate(black_box(&seed));
        });
    });

    let table = Table::generate(&seed);

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
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
