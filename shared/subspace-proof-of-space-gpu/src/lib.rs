// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use rust_kzg_blst::types::fr::FsFr;

extern "C" {
    /// # Returns
    /// * `usize` - The number of available GPUs.
    fn gpu_count() -> usize;

    /// # Parameters
    /// * `k: The size parameter for the table.
    /// * `seed: A pointer to the seed data.
    /// * `lg_record_size: The logarithm of the record size.
    /// * `challenge_index: A mutable pointer to store the index of the challenge.
    /// * `record: A pointer to the record data.
    /// * `chunks_scratch: A mutable pointer to a scratch space for chunk data.
    /// * `proof_count: A mutable pointer to store the count of proofs.
    /// * `source_record_chunks: A mutable pointer to the source record chunks.
    /// * `parity_record_chunks: A mutable pointer to the parity record chunks.
    /// * `gpu_id: The ID of the GPU to use.
    ///
    /// # Returns
    /// * `sppark::Error` - An error code indicating the result of the operation.
    ///
    /// # Assumptions
    /// * `seed` must be a valid pointer to a 32-byte.
    /// * `record` must be a valid pointer to the record data (`*const Record`), with a length of `1 << lg_record_size`.
    /// * `source_record_chunks` and `parity_record_chunks` must be valid mutable pointers to `Scalar` elements, each with a length of `1 << lg_record_size`.
    /// * `chunks_scratch` must be a valid mutable pointer where up to `challenges_count` 32-byte chunks of GPU-calculated data will be written.
    /// * `gpu_id` must be a valid identifier of an available GPU. The available GPUs can be determined by using the `gpu_count` function.
    fn generate_and_encode_pospace_dispatch(
        k: u32,
        seed: *const [u8; 32],
        lg_record_size: u32,
        challenge_index: *mut u32,
        record: *const [u8; 32],
        chunks_scratch: *mut [u8; 32],
        proof_count: *mut u32,
        source_record_chunks: *mut FsFr,
        parity_record_chunks: *mut FsFr,
        gpu_id: i32,
    ) -> sppark::Error;
}

///////////////////////////////////////////////////////////////////////////////
// Rust functions
///////////////////////////////////////////////////////////////////////////////

/// Returns the number of available GPUs.
pub fn gpu_count_api(
) -> usize {

    let ngpu = unsafe {
        gpu_count()
    };
    ngpu
}

/// Generates and encodes PoSpace on the GPU.
///
/// This function performs the generation and encoding of PoSpace
/// on a GPU. It uses the specified parameters to perform the computations and
/// ensures that errors are properly handled by returning a `Result` type.
///
/// # Parameters
///
/// ## Input
///
/// - `k`: The size parameter for the table.
/// - `seed`: A 32-byte seed used for the table generation process.
/// - `record`: A slice of bytes (`&[u8]`). These records are the data on which the proof of space will be generated.
/// - `gpu_id`: ID of the GPU to use. This parameter specifies which GPU to use for the computation.
///
/// ## Output
///
/// - `source_record_chunks`: A mutable vector of original data chunks of type FsFr, each 32 bytes in size.
/// - `parity_record_chunks`: A mutable vector of parity chunks derived from the source, each 32 bytes in size.
/// - `proof_count`: A mutable reference to the proof count. This value will be updated with the number of proofs generated.
/// - `chunks_scratch`:  A mutable vector used to store the processed chunks. This vector holds the final results after combining record chunks and proof hashes.
/// - `challenge_index`: A mutable vector used to map the challenges to specific parts of the data.
pub fn generate_and_encode_pospace(
    k: u8,
    seed: &[u8; 32],
    record: &[[u8; 32]],
    gpu_id: i32
) -> Result<(u32, Vec<[u8; 32]>, Vec<u32>, Vec<FsFr>, Vec<FsFr>), String> {
    let record_len = record.len();
    let challenge_len = 2 * record_len;
    let lg_record_size = (record_len).ilog2();

    if challenge_len > u32::MAX as usize {
        return Err(String::from("challenge_len is too large to fit in u32"));
    }

    let mut proof_count: u32 = 0;
    let mut chunks_scratch: Vec<[u8; 32]> = Vec::with_capacity(challenge_len);
    let mut challenge_index: Vec<u32> = Vec::with_capacity(challenge_len);
    let mut source_record_chunks: Vec<FsFr> = Vec::with_capacity(record_len);
    let mut parity_record_chunks: Vec<FsFr> = Vec::with_capacity(record_len);

    let err = unsafe {
        generate_and_encode_pospace_dispatch(
            k as u32,
            seed,
            lg_record_size,
            challenge_index.as_mut_ptr(),
            record.as_ptr(),
            chunks_scratch.as_mut_ptr(),
            &mut proof_count,
            source_record_chunks.as_mut_ptr(),
            parity_record_chunks.as_mut_ptr(),
            gpu_id,
        )
    };

    if err.code != 0 {
        return Err(String::from(err));
    }

    unsafe {
        chunks_scratch.set_len(challenge_len);
        challenge_index.set_len(challenge_len);
        source_record_chunks.set_len(record_len);
        parity_record_chunks.set_len(record_len);
    }

    Ok((proof_count, chunks_scratch, challenge_index, source_record_chunks, parity_record_chunks))
}
