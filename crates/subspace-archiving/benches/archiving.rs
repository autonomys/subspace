#![feature(int_log)]

use criterion::{criterion_group, criterion_main, Criterion};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::RECORD_SIZE;

const MERKLE_NUM_LEAVES: u32 = 256;
pub const RECORDED_HISTORY_SEGMENT_SIZE: u32 = RECORD_SIZE * MERKLE_NUM_LEAVES / 2;

pub fn criterion_benchmark(c: &mut Criterion) {
    let input = vec![1u8; RECORDED_HISTORY_SEGMENT_SIZE.try_into().unwrap()];
    let kzg = Kzg::random(MERKLE_NUM_LEAVES).unwrap();

    c.bench_function("archiving-2-blocks", |b| {
        b.iter(|| {
            let mut archiver =
                Archiver::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg.clone()).unwrap();
            for _ in 0..2 {
                archiver.add_block(input.clone(), Default::default());
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
