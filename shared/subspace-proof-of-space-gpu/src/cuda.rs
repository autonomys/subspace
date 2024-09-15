// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests;

use rust_kzg_blst::types::fr::FsFr;
use std::ops::DerefMut;
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::{PosProof, PosSeed, Record};

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
        parity_record_chunks: *mut FsFr,
        gpu_id: i32,
    ) -> sppark::Error;
}

/// Returns [`CudaDevice`] for each available device
pub fn cuda_devices() -> Vec<CudaDevice> {
    let num_devices = unsafe { gpu_count() };

    (0i32..)
        .take(num_devices)
        .map(|gpu_id| CudaDevice { gpu_id })
        .collect()
}

/// Wrapper data structure encapsulating a single CUDA-capable device
#[derive(Debug)]
pub struct CudaDevice {
    gpu_id: i32,
}

impl CudaDevice {
    /// Cuda device ID
    pub fn id(&self) -> i32 {
        self.gpu_id
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
        &self,
        seed: &PosSeed,
        record: &mut Record,
        encoded_chunks_used_output: impl ExactSizeIterator<Item = impl DerefMut<Target = bool>>,
    ) -> Result<(), String> {
        let record_len = Record::NUM_CHUNKS;
        let challenge_len = Record::NUM_S_BUCKETS;
        let lg_record_size = record_len.ilog2();

        if challenge_len > u32::MAX as usize {
            return Err(String::from("challenge_len is too large to fit in u32"));
        }

        let mut proof_count = 0u32;
        let mut chunks_scratch_gpu = Vec::<[u8; Scalar::FULL_BYTES]>::with_capacity(challenge_len);
        let mut challenge_index_gpu = Vec::<u32>::with_capacity(challenge_len);
        let mut parity_record_chunks = Vec::<Scalar>::with_capacity(Record::NUM_CHUNKS);

        let error = unsafe {
            generate_and_encode_pospace_dispatch(
                u32::from(PosProof::K),
                &**seed,
                lg_record_size,
                challenge_index_gpu.as_mut_ptr(),
                record.as_ptr(),
                chunks_scratch_gpu.as_mut_ptr(),
                &mut proof_count,
                Scalar::slice_mut_to_repr(&mut parity_record_chunks).as_mut_ptr(),
                self.gpu_id,
            )
        };

        if error.code != 0 {
            let error = error.to_string();
            if error.contains("the provided PTX was compiled with an unsupported toolchain.") {
                return Err(format!(
                    "Nvidia driver is likely too old, make sure install version 550 or newer: \
                    {error}"
                ));
            }
            return Err(error);
        }

        let proof_count = proof_count as usize;
        unsafe {
            chunks_scratch_gpu.set_len(proof_count);
            challenge_index_gpu.set_len(proof_count);
            parity_record_chunks.set_len(Record::NUM_CHUNKS);
        }

        let mut encoded_chunks_used = vec![false; challenge_len];
        let source_record_chunks = record.to_vec();

        let mut chunks_scratch = challenge_index_gpu
            .into_iter()
            .zip(chunks_scratch_gpu)
            .collect::<Vec<_>>();

        chunks_scratch
            .sort_unstable_by(|(a_out_index, _), (b_out_index, _)| a_out_index.cmp(b_out_index));

        // We don't need all the proofs
        chunks_scratch.truncate(proof_count.min(Record::NUM_CHUNKS));

        for (out_index, _chunk) in &chunks_scratch {
            encoded_chunks_used[*out_index as usize] = true;
        }

        encoded_chunks_used_output
            .zip(&encoded_chunks_used)
            .for_each(|(mut output, input)| *output = *input);

        record
            .iter_mut()
            .zip(
                chunks_scratch
                    .into_iter()
                    .map(|(_out_index, chunk)| chunk)
                    .chain(
                        source_record_chunks
                            .into_iter()
                            .zip(parity_record_chunks)
                            .flat_map(|(a, b)| [a, b.to_bytes()])
                            .zip(encoded_chunks_used.iter())
                            // Skip chunks that were used previously
                            .filter_map(|(record_chunk, encoded_chunk_used)| {
                                if *encoded_chunk_used {
                                    None
                                } else {
                                    Some(record_chunk)
                                }
                            }),
                    ),
            )
            .for_each(|(output_chunk, input_chunk)| {
                *output_chunk = input_chunk;
            });

        Ok(())
    }
}
