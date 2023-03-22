use criterion::{black_box, criterion_group, criterion_main, Criterion};
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::Scalar;

fn criterion_benchmark(c: &mut Criterion) {
    let data = {
        // Multiple of 32
        let mut data = rand::random::<[u8; 256]>();

        // We can only store 254 bits, set last byte to zero because of that
        data.chunks_exact_mut(Scalar::FULL_BYTES)
            .flat_map(|chunk| chunk.iter_mut().last())
            .for_each(|last_byte| *last_byte = 0);

        data
    };

    let kzg = Kzg::new(embedded_kzg_settings());

    c.bench_function("create-polynomial", |b| {
        b.iter(|| {
            kzg.poly(black_box(&data)).unwrap();
        })
    });

    c.bench_function("commit", |b| {
        let polynomial = kzg.poly(&data).unwrap();
        b.iter(|| {
            kzg.commit(black_box(&polynomial)).unwrap();
        })
    });

    c.bench_function("create-witness", |b| {
        let polynomial = kzg.poly(&data).unwrap();

        b.iter(|| {
            kzg.create_witness(black_box(&polynomial), black_box(0))
                .unwrap();
        })
    });

    c.bench_function("verify", |b| {
        let polynomial = kzg.poly(&data).unwrap();
        let commitment = kzg.commit(&polynomial).unwrap();
        let index = 0;
        let witness = kzg.create_witness(&polynomial, index).unwrap();
        let values = data.chunks_exact(Scalar::FULL_BYTES);
        let num_values = values.len();
        let value = values.into_iter().next().unwrap();

        b.iter(|| {
            kzg.verify(
                black_box(&commitment),
                black_box(num_values),
                black_box(index),
                black_box(value),
                black_box(&witness),
            );
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
