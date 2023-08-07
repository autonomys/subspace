use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;

const AMOUNT_OF_DATA: usize = 5 * 1024 * 1024;
const SMALL_BLOCK_SIZE: usize = 500;

fn criterion_benchmark(c: &mut Criterion) {
    let mut input = vec![0u8; AMOUNT_OF_DATA];
    thread_rng().fill(input.as_mut_slice());
    let kzg = Kzg::new(kzg::embedded_kzg_settings());
    let archiver = Archiver::new(kzg).unwrap();

    c.bench_function("segment-archiving-large-block", |b| {
        b.iter(|| {
            archiver.clone().add_block(
                black_box(input.clone()),
                black_box(Default::default()),
                black_box(true),
            );
        })
    });

    c.bench_function("segment-archiving-small-blocks/incremental", |b| {
        b.iter(|| {
            let mut archiver = archiver.clone();
            for chunk in input.chunks(SMALL_BLOCK_SIZE) {
                archiver.add_block(
                    black_box(chunk.to_vec()),
                    black_box(Default::default()),
                    black_box(true),
                );
            }
        })
    });

    c.bench_function("segment-archiving-small-blocks/non-incremental", |b| {
        b.iter(|| {
            let mut archiver = archiver.clone();
            for chunk in input.chunks(SMALL_BLOCK_SIZE) {
                archiver.add_block(
                    black_box(chunk.to_vec()),
                    black_box(Default::default()),
                    black_box(false),
                );
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
