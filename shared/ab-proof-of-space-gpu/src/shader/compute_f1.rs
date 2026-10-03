#[cfg(all(test, not(target_arch = "spirv")))]
mod cpu_tests;
#[cfg(all(test, not(miri), not(target_arch = "spirv")))]
mod gpu_tests;

use crate::shader::constants::{K, MAX_BUCKET_SIZE, MAX_TABLE_SIZE, NUM_BUCKETS, PARAM_EXT};
#[cfg(target_arch = "spirv")]
use crate::shader::polyfills::ArrayIndexingPolyfill;
use crate::shader::types::{Position, PositionExt, PositionR, X, Y};
use crate::shader::u32n::U32N;
use ab_chacha8::{ChaCha8Block, ChaCha8State};
use core::mem::MaybeUninit;
use spirv_std::arch::atomic_i_increment;
use spirv_std::glam::{UVec3, UVec4};
use spirv_std::memory::{Scope, Semantics};
use spirv_std::spirv;

const fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

const fn lcm(a: u32, b: u32) -> u32 {
    let g = gcd(a, b);
    (a / g) * b
}

// TODO: Same number as hardcoded in `#[spirv(compute(threads(..)))]` below, can be removed once
//  https://github.com/Rust-GPU/rust-gpu/discussions/287 is resolved
pub const WORKGROUP_SIZE: u32 = 256;
const CHACHA8_BLOCK_BITS: u32 = size_of::<ChaCha8Block>() as u32 * u8::BITS;
const CHACHA8_BLOCK_WORDS: usize = size_of::<ChaCha8Block>() / size_of::<u32>();
// This number is both a multiple of `K` (bits per element) and ChaCha8 block (bits per block)
const BITS_PER_INVOCATION: u32 = lcm(CHACHA8_BLOCK_BITS, K as u32);
pub const ELEMENTS_PER_INVOCATION: u32 = BITS_PER_INVOCATION / K as u32;
const BLOCKS_PER_INVOCATION: u32 = BITS_PER_INVOCATION / CHACHA8_BLOCK_BITS;
// `+1` is needed due to the way `compute_fn_impl` does slightly outside what it, strictly speaking,
// needs (for efficiency purposes)
const INVOCATION_KEYSTREAM_WORDS: usize = BLOCKS_PER_INVOCATION as usize * CHACHA8_BLOCK_WORDS + 1;

#[derive(Debug, Copy, Clone)]
pub struct UniformChaCha8Block([UVec4; 4]);

impl From<ChaCha8Block> for UniformChaCha8Block {
    #[inline(always)]
    fn from(value: ChaCha8Block) -> Self {
        Self([
            UVec4 {
                x: value[0],
                y: value[1],
                z: value[2],
                w: value[3],
            },
            UVec4 {
                x: value[4],
                y: value[5],
                z: value[6],
                w: value[7],
            },
            UVec4 {
                x: value[8],
                y: value[9],
                z: value[10],
                w: value[11],
            },
            UVec4 {
                x: value[12],
                y: value[13],
                z: value[14],
                w: value[15],
            },
        ])
    }
}

impl From<UniformChaCha8Block> for ChaCha8Block {
    #[inline(always)]
    fn from(value: UniformChaCha8Block) -> Self {
        [
            value.0[0].x,
            value.0[0].y,
            value.0[0].z,
            value.0[0].w,
            value.0[1].x,
            value.0[1].y,
            value.0[1].z,
            value.0[1].w,
            value.0[2].x,
            value.0[2].y,
            value.0[2].z,
            value.0[2].w,
            value.0[3].x,
            value.0[3].y,
            value.0[3].z,
            value.0[3].w,
        ]
    }
}

// TODO: Make unsafe and avoid bounds check
// TODO: Reuse code from `ab-proof-of-space` after https://github.com/Rust-GPU/rust-gpu/pull/249 and
//  https://github.com/Rust-GPU/rust-gpu/discussions/301
/// `partial_y_offset` is in bits within `partial_y`
#[inline(always)]
fn compute_f1_impl(x: X, chacha8_keystream: &[u32; INVOCATION_KEYSTREAM_WORDS]) -> Y {
    let skip_bits = (u32::from(K) * u32::from(x)) % BITS_PER_INVOCATION;
    let skip_u32s = skip_bits / u32::BITS;
    let partial_y_offset = skip_bits % u32::BITS;

    let high = chacha8_keystream[skip_u32s as usize].to_be();
    let low = chacha8_keystream[skip_u32s as usize + 1].to_be();
    let partial_y = U32N::from_low_high(low, high);

    let pre_y = partial_y >> (u64::BITS - u32::from(K + PARAM_EXT) - partial_y_offset);
    let pre_y = pre_y.as_u32();
    // Mask for clearing the rest of bits of `pre_y`.
    let pre_y_mask = (u32::MAX << PARAM_EXT) & (u32::MAX >> (u32::BITS - u32::from(K + PARAM_EXT)));

    // Extract `PARAM_EXT` most significant bits from `x` and store in the final offset of
    // eventual `y` with the rest of bits being zero (`x` is `0..2^K`)
    let pre_ext = u32::from(x) >> (K - PARAM_EXT);

    // Combine all of the bits together:
    // [padding zero bits][`K` bits from `partial_y`][`PARAM_EXT` bits from `x`]
    Y::from((pre_y & pre_y_mask) | pre_ext)
}

/// Compute Chia's `f1()` function for the whole table using the initial state of ChaCha8 cipher
/// straight into buckets of the first table.
///
/// Buckets need to be sorted by position afterward due to concurrent writes that do not have
/// deterministic order. Content of the bucket beyond the size specified in `bucket_sizes` is
/// undefined.
///
/// # Safety
/// `bucket_sizes` must be zero-initialized, which is the case by default in `wgpu`.
#[spirv(compute(threads(256), entry_point_name = "compute_f1"))]
pub unsafe fn compute_f1(
    #[spirv(global_invocation_id)] global_invocation_id: UVec3,
    #[spirv(uniform, descriptor_set = 0, binding = 0)] initial_state: &UniformChaCha8Block,
    #[spirv(storage_buffer, descriptor_set = 0, binding = 1)] bucket_sizes: &mut [u32; NUM_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 2)] buckets: &mut [[MaybeUninit<PositionR>; MAX_BUCKET_SIZE];
             NUM_BUCKETS],
) {
    // TODO: Make a single input bounds check and use unsafe to avoid bounds check later
    let global_invocation_id = global_invocation_id.x;

    let initial_state = ChaCha8State::from_repr(ChaCha8Block::from(*initial_state));

    let x_start = global_invocation_id * ELEMENTS_PER_INVOCATION;

    // TODO: More idiomatic version currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    // let chacha8_keystream = [MaybeUninit<ChaCha8Block>; BLOCKS_PER_INVOCATION as usize];
    let mut chacha8_keystream = [0u32; INVOCATION_KEYSTREAM_WORDS];
    // TODO: More idiomatic version currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    let first_block_counter = x_start * u32::from(K) / CHACHA8_BLOCK_BITS;
    for block_index in 0..BLOCKS_PER_INVOCATION {
        let counter = first_block_counter + block_index;

        let block = initial_state.compute_block(counter);
        // TODO: More idiomatic version currently doesn't compile:
        //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
        let block_write_offset = block_index as usize * CHACHA8_BLOCK_WORDS;
        #[expect(clippy::manual_memcpy, reason = "Doesn't compile under rust-gpu")]
        for offset in 0..CHACHA8_BLOCK_WORDS {
            chacha8_keystream[block_write_offset + offset] = block[offset];
        }
    }

    // TODO: More idiomatic version currently doesn't compile:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    for x in x_start..(x_start + ELEMENTS_PER_INVOCATION).min(MAX_TABLE_SIZE) {
        let y = compute_f1_impl(X::from(x), &chacha8_keystream);

        let (bucket_index, r) = y.into_bucket_index_and_r();
        // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition
        let bucket_size = unsafe { bucket_sizes.get_unchecked_mut(bucket_index as usize) };
        // SAFETY: TODO: Probably should not be unsafe to begin with:
        //  https://github.com/Rust-GPU/rust-gpu/pull/394#issuecomment-3316594485
        let bucket_offset = unsafe {
            atomic_i_increment::<_, { Scope::QueueFamily as u32 }, { Semantics::NONE.bits() }>(
                bucket_size,
            )
        };

        // SAFETY: Bucket is obtained using division by `PARAM_BC` and fits by definition. Bucket
        // size upper bound is known statically to be [`MAX_BUCKET_SIZE`], so `bucket_offset` is
        // also always within bounds.
        unsafe {
            buckets
                .get_unchecked_mut(bucket_index as usize)
                .get_unchecked_mut(bucket_offset as usize)
        }
        .write(PositionR {
            position: Position::from_u32(x),
            r,
        });
    }
}
