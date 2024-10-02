use criterion::{black_box, criterion_group, criterion_main, Criterion};
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg, Scalar};
use subspace_core_primitives::pieces::RawRecord;
use subspace_core_primitives::ScalarBytes;

fn criterion_benchmark(c: &mut Criterion) {
    let values = (0..RawRecord::NUM_CHUNKS)
        .map(|_| Scalar::from(rand::random::<[u8; ScalarBytes::SAFE_BYTES]>()))
        .collect::<Vec<_>>();

    let kzg = Kzg::new(embedded_kzg_settings());

    c.bench_function("create-polynomial", |b| {
        b.iter(|| {
            kzg.poly(black_box(&values)).unwrap();
        })
    });

    {
        let polynomial = kzg.poly(&values).unwrap();

        c.bench_function("commit", |b| {
            b.iter(|| {
                kzg.commit(black_box(&polynomial)).unwrap();
            })
        });
    }

    let num_values = values.len();

    {
        let polynomial = kzg.poly(&values).unwrap();

        c.bench_function("create-witness", |b| {
            b.iter(|| {
                kzg.create_witness(black_box(&polynomial), black_box(num_values), black_box(0))
                    .unwrap();
            })
        });
    }

    {
        let polynomial = kzg.poly(&values).unwrap();
        let commitment = kzg.commit(&polynomial).unwrap();
        let index = 0;
        let witness = kzg.create_witness(&polynomial, num_values, index).unwrap();
        let value = values.first().unwrap();

        c.bench_function("verify", |b| {
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
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
