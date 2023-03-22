use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{PIECES_IN_SEGMENT, RECORD_SIZE};

// This is helpful for overriding locally for benching different parameters
const RECORDED_HISTORY_SEGMENT_SIZE: u32 = RECORD_SIZE * PIECES_IN_SEGMENT / 2;

fn criterion_benchmark(c: &mut Criterion) {
    let mut input = vec![0u8; RECORDED_HISTORY_SEGMENT_SIZE as usize];
    thread_rng().fill(input.as_mut_slice());
    let kzg = Kzg::new(kzg::embedded_kzg_settings());
    let mut archiver = Archiver::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg).unwrap();

    c.bench_function("segment-archiving", |b| {
        b.iter(|| {
            archiver.add_block(input.clone(), Default::default());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
