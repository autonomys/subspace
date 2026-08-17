use crate::shader::MIN_SUBGROUP_SIZE;
use crate::shader::constants::{
    K, NUM_MATCH_BUCKETS, NUM_S_BUCKETS, NUM_TABLES, REDUCED_MATCHES_COUNT,
};
use crate::shader::find_matches_and_compute_f7::{NUM_ELEMENTS_PER_S_BUCKET, ProofTargets};
use crate::shader::types::{Position, PositionExt};
use core::mem::MaybeUninit;
use spirv_std::arch::{
    atomic_or, subgroup_ballot, subgroup_memory_barrier, subgroup_shuffle, subgroup_u_min,
    workgroup_memory_barrier_with_group_sync,
};
use spirv_std::glam::UVec3;
use spirv_std::memory::{Scope, Semantics};
use spirv_std::spirv;
#[cfg(not(target_arch = "spirv"))]
use subspace_core_primitives::pos::PosProof;

// TODO: Same number as hardcoded in `#[spirv(compute(threads(..)))]` below, can be removed once
//  https://github.com/Rust-GPU/rust-gpu/discussions/287 is resolved
pub const WORKGROUP_SIZE: u32 = 256;
const PROOF_X_SOURCES: usize = 2usize.pow(NUM_TABLES as u32 - 1);
const PROOF_BITS: usize = PROOF_X_SOURCES * K as usize;
const PROOF_BYTES: usize = PROOF_BITS.div_ceil(u8::BITS as usize);
pub const PROOF_U32_WORDS: usize = PROOF_BYTES.div_ceil(size_of::<u32>());
pub const FOUND_PROOFS_U32_WORDS: usize = {
    assert!(NUM_S_BUCKETS.is_multiple_of(u32::BITS as usize));

    NUM_S_BUCKETS / u32::BITS as usize
};

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Proofs {
    found_proofs: [MaybeUninit<u32>; FOUND_PROOFS_U32_WORDS],
    // TODO: Calculate bit mask for proofs found upfront and reduce the size here to just
    //  `NUM_CHUNKS`
    proofs: [MaybeUninit<u32>; PROOF_U32_WORDS * NUM_S_BUCKETS],
}

// This is equivalent to the above but used for interpretation by the host
#[derive(Debug, Copy, Clone)]
#[cfg(not(target_arch = "spirv"))]
#[repr(C)]
pub struct ProofsHost {
    // TODO: Would have been nice to avoid filtering-out on the host
    /// S-buckets at which proofs were found, there will be more than `Record::NUM_CHUNKS` proofs
    /// here, needs to be filtered-out by the host
    pub found_proofs: [u8; NUM_S_BUCKETS / u8::BITS as usize],
    // TODO: Calculate bit mask for proofs found upfront and reduce the size here to just
    //  `NUM_CHUNKS`
    /// All proofs, those that correspond to set bits of `found_proofs` exist
    pub proofs: [PosProof; NUM_S_BUCKETS],
}

#[cfg(not(target_arch = "spirv"))]
const _: () = {
    assert!(size_of::<Proofs>() == size_of::<ProofsHost>());
};

// TODO: Optimize this for various cases like when all buckets fit into subgroup size, when subgroup
//  size is large enough to process multiple buckets at once (especially since buckets often are
//  less than 16 elements, meaning AMD GPUs can process 4 at once) with clustered subgroup
//  operations, etc.
// TODO: Make unsafe and avoid bounds check
#[expect(
    clippy::too_many_arguments,
    reason = "Both I/O and Vulkan stuff together take a lot of arguments"
)]
#[inline(always)]
fn find_local_proof_targets<const SUBGROUP_SIZE: u32>(
    local_invocation_id: u32,
    subgroup_id: u32,
    subgroup_local_invocation_id: u32,
    positions_group_index: u32,
    bucket_sizes: &mut [u32; NUM_S_BUCKETS],
    buckets: &[[ProofTargets; NUM_ELEMENTS_PER_S_BUCKET]; NUM_S_BUCKETS],
    found_proofs: &mut [MaybeUninit<u32>; FOUND_PROOFS_U32_WORDS],
    found_proofs_scratch: &mut [MaybeUninit<u32>; (WORKGROUP_SIZE / u32::BITS) as usize],
) -> [Position; 2] {
    let local_invocation_id = local_invocation_id as usize;
    let base = positions_group_index * SUBGROUP_SIZE;

    let mut min = [Position::SENTINEL; 2];

    let local_bucket_size = {
        let bucket_id = base + subgroup_local_invocation_id;

        let local_bucket_size = bucket_sizes[bucket_id as usize];
        bucket_sizes[bucket_id as usize] = 0;

        local_bucket_size
    };

    for local_bucket_id in 0..SUBGROUP_SIZE {
        let bucket_id = (base + local_bucket_id) as usize;
        let bucket_size = subgroup_shuffle(local_bucket_size, local_bucket_id);
        let bucket = &buckets[bucket_id];

        // TODO: Can't use the struct due to this issue in Naga:
        //  https://github.com/gfx-rs/wgpu/issues/8389#issuecomment-3430788603
        // let mut local_min = ProofTargets {
        //     absolute_position: u32::MAX,
        //     positions: [Position::SENTINEL; 2],
        // };
        let mut local_min_absolute_position = [u32::MAX];
        let mut local_min_positions = [Position::SENTINEL; 2];

        for index in (subgroup_local_invocation_id..bucket_size).step_by(SUBGROUP_SIZE as usize) {
            let proof_targets = bucket[index as usize];
            if proof_targets.absolute_position < local_min_absolute_position[0] {
                local_min_absolute_position[0] = proof_targets.absolute_position;
                local_min_positions = proof_targets.positions;
            }
        }

        let min_absolute_position = subgroup_u_min(local_min_absolute_position[0]);
        let source_lane_mask =
            subgroup_ballot(local_min_absolute_position[0] == min_absolute_position);
        // TODO: This intrinsic is not supported by `wgpu` yet:
        //  https://github.com/gfx-rs/wgpu/issues/8403
        // let source_lane = subgroup_ballot_find_lsb(source_lane_mask);
        let source_lane_mask = source_lane_mask.to_array();
        let mut source_lane = u32::MAX;
        for i in 0..SUBGROUP_SIZE.div_ceil(u32::BITS) {
            let word = source_lane_mask[i as usize];
            if word != 0 {
                source_lane = word.trailing_zeros() + i * u32::BITS;
                break;
            }
        }
        let local_min = subgroup_shuffle(local_min_positions, source_lane);

        if subgroup_local_invocation_id == local_bucket_id {
            min = local_min;
        }
    }

    let has_proof = local_bucket_size > 0;
    let found_proofs_words = subgroup_ballot(has_proof);

    if SUBGROUP_SIZE >= u32::BITS {
        // For subgroup sizes that are multiple of `u32` words, results can be written directly into
        // global memory
        // TODO: should have been `subgroup_elect()`, but it is not implemented in `wgpu` yet:
        //  https://github.com/gfx-rs/wgpu/issues/5555
        if subgroup_local_invocation_id == 0 {
            let start_word = (base / u32::BITS) as usize;
            found_proofs[start_word].write(found_proofs_words.x);

            if SUBGROUP_SIZE >= 2 * u32::BITS {
                found_proofs[start_word + 1].write(found_proofs_words.y);

                if SUBGROUP_SIZE >= 4 * u32::BITS {
                    found_proofs[start_word + 2].write(found_proofs_words.z);
                    found_proofs[start_word + 3].write(found_proofs_words.w);
                }
            }
        }
    } else {
        if local_invocation_id < found_proofs_scratch.len() {
            found_proofs_scratch[local_invocation_id].write(0);
        }

        workgroup_memory_barrier_with_group_sync();

        // For subgroups of smaller sizes aggregate results in shared memory first, then write to
        // global memory
        // TODO: should have been `subgroup_elect()`, but it is not implemented in `wgpu` yet:
        //  https://github.com/gfx-rs/wgpu/issues/5555
        if subgroup_local_invocation_id == 0 {
            let local_start_bit = subgroup_id * SUBGROUP_SIZE;
            let local_word_index = (local_start_bit / u32::BITS) as usize;
            let local_word_shift = local_start_bit % u32::BITS;

            // SAFETY: Initialized above
            let found_proofs_word =
                unsafe { found_proofs_scratch[local_word_index].assume_init_mut() };
            // SAFETY: TODO: Probably should not be unsafe to begin with:
            //  https://github.com/Rust-GPU/rust-gpu/pull/394#issuecomment-3316594485
            unsafe {
                atomic_or::<_, { Scope::Workgroup as u32 }, { Semantics::NONE.bits() }>(
                    found_proofs_word,
                    found_proofs_words.x << local_word_shift,
                );
            }
        }

        workgroup_memory_barrier_with_group_sync();

        if local_invocation_id < found_proofs_scratch.len() {
            let workgroup_base_group_index = positions_group_index - subgroup_id;
            let workgroup_start_bucket = workgroup_base_group_index * SUBGROUP_SIZE;
            let global_start_word = (workgroup_start_bucket / u32::BITS) as usize;

            // SAFETY: Initialized above
            let found_proofs_word =
                unsafe { found_proofs_scratch[local_invocation_id].assume_init() };
            found_proofs[global_start_word + local_invocation_id].write(found_proofs_word);
        }
    }

    min
}

// TODO: Make unsafe and avoid bounds check
#[expect(
    clippy::too_many_arguments,
    reason = "Both I/O and Vulkan stuff together take a lot of arguments"
)]
fn find_proofs_impl<const SUBGROUP_SIZE: u32>(
    local_invocation_id: u32,
    subgroup_id: u32,
    subgroup_local_invocation_id: u32,
    positions_group_index: u32,
    // TODO: This should have been `&[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]`,
    //  but it currently doesn't compile if flattened:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    table_2_positions: &[[Position; 2]; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    table_3_positions: &[[Position; 2]; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    table_4_positions: &[[Position; 2]; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    table_5_positions: &[[Position; 2]; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    table_6_positions: &[[Position; 2]; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    bucket_sizes: &mut [u32; NUM_S_BUCKETS],
    buckets: &[[ProofTargets; NUM_ELEMENTS_PER_S_BUCKET]; NUM_S_BUCKETS],
    found_proofs: &mut [MaybeUninit<u32>; FOUND_PROOFS_U32_WORDS],
    // TODO: This should have been `&mut [[MaybeUninit<u32>; PROOF_U32_WORDS]; NUM_S_BUCKETS]`,
    //  but it currently doesn't compile if flattened:
    //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
    proofs: &mut [MaybeUninit<u32>; PROOF_U32_WORDS * NUM_S_BUCKETS],
    found_proofs_scratch: &mut [MaybeUninit<u32>; (WORKGROUP_SIZE / u32::BITS) as usize],
) where
    [(); PROOF_X_SOURCES.div_ceil(SUBGROUP_SIZE as usize)]:,
    [(); PROOF_U32_WORDS.div_ceil(SUBGROUP_SIZE as usize)]:,
{
    let table_6_proof_targets = find_local_proof_targets::<SUBGROUP_SIZE>(
        local_invocation_id,
        subgroup_id,
        subgroup_local_invocation_id,
        positions_group_index,
        bucket_sizes,
        buckets,
        found_proofs,
        found_proofs_scratch,
    );

    // TODO: This proof zeroing will not be needed once proofs are assembled in registers and no
    //  longer use atomic writes
    // Zero the proofs range with coalesced writes
    {
        let positions_group_words = SUBGROUP_SIZE as usize * PROOF_U32_WORDS;
        let base_word = positions_group_index as usize * positions_group_words;

        for offset in (subgroup_local_invocation_id as usize..positions_group_words)
            .step_by(SUBGROUP_SIZE as usize)
        {
            proofs[base_word + offset].write(0);
        }

        subgroup_memory_barrier();
    }

    // `0` for left `1` for right
    let left_right = (subgroup_local_invocation_id % 2) as usize;
    // Otherwise `left_right` will not work as expected
    const {
        assert!(MIN_SUBGROUP_SIZE >= 2);
    }

    // `chunk_index` is used to emulate `for _ in 0..2` loops, while using a single variable for
    // tracking the progress instead of a separate variable for each loop
    let mut chunk_index = 0u32;
    // Reading positions from table 6
    loop {
        let table_6_proof_targets = subgroup_shuffle(
            table_6_proof_targets,
            SUBGROUP_SIZE / 2 * (chunk_index & 1) + subgroup_local_invocation_id / 2,
        );
        let table_6_proof_target = table_6_proof_targets[left_right];

        let table_5_proof_targets = if table_6_proof_target == Position::SENTINEL {
            [Position::SENTINEL; 2]
        } else {
            table_6_positions[table_6_proof_target as usize]
        };

        // Reading positions from table 5
        chunk_index <<= 1u8;
        loop {
            let table_5_proof_targets = subgroup_shuffle(
                table_5_proof_targets,
                SUBGROUP_SIZE / 2 * (chunk_index & 1) + subgroup_local_invocation_id / 2,
            );
            let table_5_proof_target = table_5_proof_targets[left_right];

            let table_4_proof_targets = if table_5_proof_target == Position::SENTINEL {
                [Position::SENTINEL; 2]
            } else {
                table_5_positions[table_5_proof_target as usize]
            };

            // Reading positions from table 4
            chunk_index <<= 1u8;
            loop {
                let table_4_proof_targets = subgroup_shuffle(
                    table_4_proof_targets,
                    SUBGROUP_SIZE / 2 * (chunk_index & 1) + subgroup_local_invocation_id / 2,
                );
                let table_4_proof_target = table_4_proof_targets[left_right];

                let table_3_proof_targets = if table_4_proof_target == Position::SENTINEL {
                    [Position::SENTINEL; 2]
                } else {
                    table_4_positions[table_4_proof_target as usize]
                };

                // Reading positions from table 3
                chunk_index <<= 1u8;
                loop {
                    let table_3_proof_targets = subgroup_shuffle(
                        table_3_proof_targets,
                        SUBGROUP_SIZE / 2 * (chunk_index & 1) + subgroup_local_invocation_id / 2,
                    );
                    let table_3_proof_target = table_3_proof_targets[left_right];

                    let table_2_proof_targets = if table_3_proof_target == Position::SENTINEL {
                        [Position::SENTINEL; 2]
                    } else {
                        table_3_positions[table_3_proof_target as usize]
                    };

                    // Reading positions from table 2
                    chunk_index <<= 1u8;
                    loop {
                        let table_2_proof_targets = subgroup_shuffle(
                            table_2_proof_targets,
                            SUBGROUP_SIZE / 2 * (chunk_index & 1)
                                + subgroup_local_invocation_id / 2,
                        );
                        let table_2_proof_target = table_2_proof_targets[left_right];

                        let [x_left, x_right] = if table_2_proof_target == Position::SENTINEL {
                            [Position::SENTINEL; 2]
                        } else {
                            table_2_positions[table_2_proof_target as usize]
                        };

                        let global_x_left_offset =
                            subgroup_local_invocation_id * 2 + chunk_index * SUBGROUP_SIZE * 2;
                        let group_proof_index = global_x_left_offset / PROOF_X_SOURCES as u32;
                        let x_left_offset = global_x_left_offset % PROOF_X_SOURCES as u32;
                        let global_proof_index =
                            positions_group_index * SUBGROUP_SIZE + group_proof_index;

                        let proof_base = global_proof_index as usize * PROOF_U32_WORDS;
                        let first_proof_word_index =
                            ((u32::from(K) * x_left_offset) / u32::BITS) as usize;

                        // TODO: Writes below can be optimized by building the full proof into the
                        //  registers first and only write final result without atomics to global
                        //  memory

                        let mut local_proof_words = [0u32; 3];
                        let x_left_offset_in_bits = u32::from(K) * x_left_offset;
                        {
                            let bit_offset = x_left_offset_in_bits % u32::BITS;
                            let x_shifted_to_start = x_left << (u32::BITS - u32::from(K));

                            let first_word = x_shifted_to_start >> bit_offset;
                            let second_word =
                                x_shifted_to_start.unbounded_shl(u32::BITS - bit_offset);

                            local_proof_words[0] = first_word;
                            local_proof_words[1] = second_word;
                        }

                        let max_local_proof_word_index = {
                            let x_right_offset_in_bits = x_left_offset_in_bits + u32::from(K);
                            let local_proof_words_index = (x_right_offset_in_bits / u32::BITS)
                                as usize
                                - first_proof_word_index;
                            let bit_offset = x_right_offset_in_bits % u32::BITS;
                            let x_shifted_to_start = x_right << (u32::BITS - u32::from(K));

                            let first_word = x_shifted_to_start >> bit_offset;
                            let second_word =
                                x_shifted_to_start.unbounded_shl(u32::BITS - bit_offset);

                            local_proof_words[local_proof_words_index] |= first_word;
                            local_proof_words[local_proof_words_index + 1] = second_word;

                            local_proof_words_index + usize::from(second_word != 0)
                        };

                        // The first word is written unconditionally
                        {
                            // SAFETY: The whole proof is initialized at the beginning of the
                            // function
                            let word = unsafe {
                                proofs[proof_base + first_proof_word_index].assume_init_mut()
                            };
                            // SAFETY: TODO: Probably should not be unsafe to begin with:
                            //  https://github.com/Rust-GPU/rust-gpu/pull/394#issuecomment-3316594485
                            unsafe {
                                atomic_or::<
                                    _,
                                    { Scope::Subgroup as u32 },
                                    { Semantics::NONE.bits() },
                                >(
                                    word, local_proof_words[0].to_be()
                                );
                            }
                        }
                        // Process remaining words, the loop is unrolled to save vector registers
                        if max_local_proof_word_index > 0 {
                            // SAFETY: The whole proof is initialized at the beginning of the
                            // function
                            let word = unsafe {
                                proofs[proof_base + first_proof_word_index + 1].assume_init_mut()
                            };
                            // SAFETY: TODO: Probably should not be unsafe to begin with:
                            //  https://github.com/Rust-GPU/rust-gpu/pull/394#issuecomment-3316594485
                            unsafe {
                                atomic_or::<
                                    _,
                                    { Scope::Subgroup as u32 },
                                    { Semantics::NONE.bits() },
                                >(
                                    word, local_proof_words[1].to_be()
                                );
                            }
                        }
                        if max_local_proof_word_index > 1 {
                            // SAFETY: The whole proof is initialized at the beginning of the
                            // function
                            let word = unsafe {
                                proofs[proof_base + first_proof_word_index + 2].assume_init_mut()
                            };
                            // SAFETY: TODO: Probably should not be unsafe to begin with:
                            //  https://github.com/Rust-GPU/rust-gpu/pull/394#issuecomment-3316594485
                            unsafe {
                                atomic_or::<
                                    _,
                                    { Scope::Subgroup as u32 },
                                    { Semantics::NONE.bits() },
                                >(
                                    word, local_proof_words[2].to_be()
                                );
                            }
                        }

                        if chunk_index & 1 == 1 {
                            break;
                        }
                        chunk_index += 1;
                    }
                    chunk_index >>= 1u8;

                    if chunk_index & 1 == 1 {
                        break;
                    }
                    chunk_index += 1;
                }
                chunk_index >>= 1u8;

                if chunk_index & 1 == 1 {
                    break;
                }
                chunk_index += 1;
            }
            chunk_index >>= 1u8;

            if chunk_index & 1 == 1 {
                break;
            }
            chunk_index += 1;
        }
        chunk_index >>= 1u8;

        if chunk_index & 1 == 1 {
            break;
        }
        chunk_index += 1;
    }
}

/// NOTE: bucket sizes are zeroed after use
// TODO: Maybe split `found_proofs` and `proofs` searching into separate shaders, such that less
//  compute is wasted on searching proofs overall (right now up to half of the compute is wasted
//  when computing proofs). It'll also be easier to add hashing after proof computation that way.
#[spirv(compute(threads(256), entry_point_name = "find_proofs"))]
#[expect(
    clippy::too_many_arguments,
    reason = "Both I/O and Vulkan stuff together take a lot of arguments"
)]
pub fn find_proofs(
    #[spirv(workgroup_id)] workgroup_id: UVec3,
    #[spirv(local_invocation_id)] local_invocation_id: UVec3,
    #[spirv(subgroup_id)] subgroup_id: u32,
    #[spirv(subgroup_size)] subgroup_size: u32,
    #[spirv(num_subgroups)] num_subgroups: u32,
    #[spirv(subgroup_local_invocation_id)] subgroup_local_invocation_id: u32,
    #[spirv(storage_buffer, descriptor_set = 0, binding = 0)]
    table_2_positions: &[[Position; 2]; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 1)]
    table_3_positions: &[[Position; 2]; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 2)]
    table_4_positions: &[[Position; 2]; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 3)]
    table_5_positions: &[[Position; 2]; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 4)]
    table_6_positions: &[[Position; 2]; REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 5)] bucket_sizes: &mut [u32;
             NUM_S_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 6)] buckets: &[[ProofTargets; NUM_ELEMENTS_PER_S_BUCKET];
         NUM_S_BUCKETS],
    #[spirv(storage_buffer, descriptor_set = 0, binding = 7)] proofs: &mut Proofs,
    #[spirv(workgroup)] found_proofs_scratch: &mut [MaybeUninit<u32>;
             (WORKGROUP_SIZE / u32::BITS) as usize],
) {
    let local_invocation_id = local_invocation_id.x;
    let workgroup_id = workgroup_id.x;

    let global_subgroup_id = workgroup_id * num_subgroups + subgroup_id;

    let positions_group_index = global_subgroup_id;
    // Specify some common subgroup sizes so the driver can easily eliminate dead code. This is
    // important because `local_words` inside the function is generic and impacts the number of
    // registers used, so we want to minimize them.
    match subgroup_size {
        // Hypothetically possible
        1 => {
            find_proofs_impl::<1>(
                local_invocation_id,
                subgroup_id,
                subgroup_local_invocation_id,
                positions_group_index,
                table_2_positions,
                table_3_positions,
                table_4_positions,
                table_5_positions,
                table_6_positions,
                bucket_sizes,
                buckets,
                &mut proofs.found_proofs,
                &mut proofs.proofs,
                found_proofs_scratch,
            );
        }
        // Hypothetically possible
        2 => {
            find_proofs_impl::<2>(
                local_invocation_id,
                subgroup_id,
                subgroup_local_invocation_id,
                positions_group_index,
                table_2_positions,
                table_3_positions,
                table_4_positions,
                table_5_positions,
                table_6_positions,
                bucket_sizes,
                buckets,
                &mut proofs.found_proofs,
                &mut proofs.proofs,
                found_proofs_scratch,
            );
        }
        // LLVMpipe (Mesa 24, SSE)
        4 => {
            find_proofs_impl::<4>(
                local_invocation_id,
                subgroup_id,
                subgroup_local_invocation_id,
                positions_group_index,
                table_2_positions,
                table_3_positions,
                table_4_positions,
                table_5_positions,
                table_6_positions,
                bucket_sizes,
                buckets,
                &mut proofs.found_proofs,
                &mut proofs.proofs,
                found_proofs_scratch,
            );
        }
        // LLVMpipe (Mesa 25, AVX/AVX2)
        8 => {
            find_proofs_impl::<8>(
                local_invocation_id,
                subgroup_id,
                subgroup_local_invocation_id,
                positions_group_index,
                table_2_positions,
                table_3_positions,
                table_4_positions,
                table_5_positions,
                table_6_positions,
                bucket_sizes,
                buckets,
                &mut proofs.found_proofs,
                &mut proofs.proofs,
                found_proofs_scratch,
            );
        }
        // Raspberry PI 5
        16 => {
            find_proofs_impl::<16>(
                local_invocation_id,
                subgroup_id,
                subgroup_local_invocation_id,
                positions_group_index,
                table_2_positions,
                table_3_positions,
                table_4_positions,
                table_5_positions,
                table_6_positions,
                bucket_sizes,
                buckets,
                &mut proofs.found_proofs,
                &mut proofs.proofs,
                found_proofs_scratch,
            );
        }
        // Intel/Nvidia
        32 => {
            find_proofs_impl::<32>(
                local_invocation_id,
                subgroup_id,
                subgroup_local_invocation_id,
                positions_group_index,
                table_2_positions,
                table_3_positions,
                table_4_positions,
                table_5_positions,
                table_6_positions,
                bucket_sizes,
                buckets,
                &mut proofs.found_proofs,
                &mut proofs.proofs,
                found_proofs_scratch,
            );
        }
        // AMD
        64 => {
            find_proofs_impl::<64>(
                local_invocation_id,
                subgroup_id,
                subgroup_local_invocation_id,
                positions_group_index,
                table_2_positions,
                table_3_positions,
                table_4_positions,
                table_5_positions,
                table_6_positions,
                bucket_sizes,
                buckets,
                &mut proofs.found_proofs,
                &mut proofs.proofs,
                found_proofs_scratch,
            );
        }
        // Hypothetically possible
        128 => {
            find_proofs_impl::<128>(
                local_invocation_id,
                subgroup_id,
                subgroup_local_invocation_id,
                positions_group_index,
                table_2_positions,
                table_3_positions,
                table_4_positions,
                table_5_positions,
                table_6_positions,
                bucket_sizes,
                buckets,
                &mut proofs.found_proofs,
                &mut proofs.proofs,
                found_proofs_scratch,
            );
        }
        _ => {
            // https://registry.khronos.org/vulkan/specs/latest/man/html/SubgroupSize.html
            unreachable!("All Vulkan targets use power of two and subgroup size <= 128")
        }
    }
}
