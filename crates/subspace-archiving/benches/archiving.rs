#![feature(int_log)]

use criterion::{criterion_group, criterion_main, Criterion};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::{PIECE_SIZE, SHA256_HASH_SIZE};

const MERKLE_NUM_LEAVES: u32 = 256;
const WITNESS_SIZE: u32 = SHA256_HASH_SIZE as u32 * MERKLE_NUM_LEAVES.log2();
pub const RECORD_SIZE: u32 = PIECE_SIZE as u32 - WITNESS_SIZE;
pub const RECORDED_HISTORY_SEGMENT_SIZE: u32 = RECORD_SIZE * MERKLE_NUM_LEAVES / 2;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut input = Vec::<u8>::with_capacity(RECORDED_HISTORY_SEGMENT_SIZE.try_into().unwrap());
    input.resize(input.capacity(), 1);

    c.bench_function("archiving-2-blocks", |b| {
        b.iter(|| {
            let mut archiver = Archiver::new(
                RECORD_SIZE.try_into().unwrap(),
                RECORDED_HISTORY_SEGMENT_SIZE.try_into().unwrap(),
            )
            .unwrap();
            for _ in 0..2 {
                archiver.add_block(input.clone(), Default::default());
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
