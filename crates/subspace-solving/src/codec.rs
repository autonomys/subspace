// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Codec for the [Subspace Network Blockchain](https://subspace.network) based on the
//! [SLOTH permutation](https://eprint.iacr.org/2015/366).

use log::error;
use rayon::prelude::*;
use sloth256_189::cpu;
#[cfg(feature = "cuda")]
use sloth256_189::cuda;
use subspace_core_primitives::{crypto, Sha256Hash, PIECE_SIZE};
use thiserror::Error;

/// Number of pieces for GPU should be multiples of 1024
#[cfg(feature = "cuda")]
const GPU_PIECE_BLOCK: usize = 1024;
const ENCODE_ROUNDS: usize = 1;

/// CPU encoding errors
#[derive(Debug, Error)]
pub enum BatchEncodeError {
    /// Pieces argument is not multiple of piece size
    #[error("Pieces argument is not multiple of piece size")]
    NotMultipleOfPieceSize,
    /// CPU encoding error
    #[error("CPU encoding error: {0}")]
    CpuEncodeError(cpu::EncodeError),
    /// CUDA encoding error
    #[cfg(feature = "cuda")]
    #[error("CUDA encoding error: {0}")]
    CudaEncodeError(cuda::EncodeError),
}

impl From<cpu::EncodeError> for BatchEncodeError {
    fn from(error: cpu::EncodeError) -> Self {
        Self::CpuEncodeError(error)
    }
}

#[cfg(feature = "cuda")]
impl From<cuda::EncodeError> for BatchEncodeError {
    fn from(error: cuda::EncodeError) -> Self {
        Self::CudaEncodeError(error)
    }
}

fn mix_public_key_hash_with_piece_index(public_key_hash: &mut [u8], piece_index: u64) {
    // XOR `piece_index` (as little-endian bytes) with last bytes of `expanded_iv`
    public_key_hash
        .iter_mut()
        .rev()
        .zip(piece_index.to_le_bytes().iter().rev())
        .for_each(|(iv_byte, index_byte)| {
            *iv_byte ^= index_byte;
        });
}

/// Subspace codec is used to encode pieces of archived history before writing them to disk and also
/// to decode them after reading from disk.
#[derive(Debug, Copy, Clone)]
pub struct SubspaceCodec {
    farmer_public_key_hash: Sha256Hash,
    #[cfg(feature = "cuda")]
    cuda_available: bool,
    cpu_cores: usize,
}

impl SubspaceCodec {
    /// New instance with 256-bit prime and 4096-byte genesis piece size
    pub fn new<P: AsRef<[u8]>>(farmer_public_key: &P) -> Self {
        #[cfg(feature = "cuda")]
        let cuda_available = cuda::is_cuda_available();

        let farmer_public_key_hash = crypto::sha256_hash(farmer_public_key);

        Self {
            farmer_public_key_hash,
            #[cfg(feature = "cuda")]
            cuda_available,
            cpu_cores: num_cpus::get(),
        }
    }
}

impl SubspaceCodec {
    /// Create an encoding based on genesis piece using provided encoding key hash, nonce and
    /// desired number of rounds
    pub fn encode(&self, piece: &mut [u8], piece_index: u64) -> Result<(), cpu::EncodeError> {
        cpu::encode(piece, &self.create_expanded_iv(piece_index), ENCODE_ROUNDS)
    }

    /// Number of elements processed efficiently during one iteration of batched encoding.
    pub fn batch_size(&self) -> usize {
        #[cfg(feature = "cuda")]
        if self.cuda_available {
            return GPU_PIECE_BLOCK;
        }

        self.cpu_cores
    }

    /// Encode given batch of pieces using the best method available, which might be GPU, CPU or
    /// combination of both.
    ///
    /// [`SubspaceCodec::recommended_batch_size()`] can be used to determine the recommended batch
    /// size, input should ideally contain at least that many worth of pieces to achieve highest
    /// efficiency, it is recommended that the input is a multiple of that, but, strictly speaking,
    /// doesn't have to be.
    ///
    /// NOTE: When error is returned, some pieces might have been modified and should be considered
    /// in inconsistent state!
    #[allow(unused_mut)]
    pub fn batch_encode(
        &mut self,
        mut pieces: &mut [u8],
        mut piece_indexes: &[u64],
    ) -> Result<(), BatchEncodeError> {
        if pieces.len() % PIECE_SIZE != 0 {
            return Err(BatchEncodeError::NotMultipleOfPieceSize);
        }

        #[cfg(feature = "cuda")]
        if self.cuda_available {
            let mut pieces_to_process = pieces.len() / PIECE_SIZE;

            // GPU will accept multiples of 1024 pieces
            if pieces_to_process >= 1024 {
                pieces_to_process = pieces_to_process / GPU_PIECE_BLOCK * GPU_PIECE_BLOCK;
                // process the multiples of 1024 pieces in GPU
                let cuda_result = self.batch_encode_cuda(
                    &mut pieces[..pieces_to_process * PIECE_SIZE],
                    &piece_indexes[..pieces_to_process],
                );

                if let Err(e) = cuda_result {
                    error!("An error happened on the GPU: '{}'", e);
                    self.cuda_available = false;
                    // TODO: maybe also return from the GPU last successful encoding,
                    // so that CPU can continue from there
                    // because this implementation does not cover the case when GPU creates a problem
                    // after some pieces are successfully encoded
                } else {
                    // Leave the rest for CPU
                    pieces = &mut pieces[pieces_to_process * PIECE_SIZE..];
                    piece_indexes = &piece_indexes[pieces_to_process..];
                }
            }
        }

        self.batch_encode_cpu(pieces, piece_indexes)?;

        Ok(())
    }

    /// Decode piece
    pub fn decode(&self, piece: &mut [u8], piece_index: u64) -> Result<(), cpu::DecodeError> {
        cpu::decode(piece, &self.create_expanded_iv(piece_index), ENCODE_ROUNDS)
    }

    fn create_expanded_iv(&self, piece_index: u64) -> Sha256Hash {
        let mut expanded_iv = self.farmer_public_key_hash;

        mix_public_key_hash_with_piece_index(&mut expanded_iv, piece_index);

        expanded_iv
    }

    fn batch_encode_cpu(
        &self,
        pieces: &mut [u8],
        piece_indexes: &[u64],
    ) -> Result<(), cpu::EncodeError> {
        pieces
            .par_chunks_exact_mut(PIECE_SIZE)
            .zip_eq(piece_indexes)
            .try_for_each(|(piece, &piece_index)| self.encode(piece, piece_index))
    }

    #[cfg(feature = "cuda")]
    fn batch_encode_cuda(
        &self,
        pieces: &mut [u8],
        piece_indexes: &[u64],
    ) -> Result<(), cuda::EncodeError> {
        use subspace_core_primitives::SHA256_HASH_SIZE;
        let mut expanded_ivs = vec![0u8; pieces.len() / PIECE_SIZE * SHA256_HASH_SIZE];
        expanded_ivs
            .par_chunks_exact_mut(SHA256_HASH_SIZE)
            .zip_eq(piece_indexes)
            .for_each(|(expanded_iv, &piece_index)| {
                expanded_iv.copy_from_slice(&self.farmer_public_key_hash);

                mix_public_key_hash_with_piece_index(expanded_iv, piece_index);
            });

        cuda::encode(pieces, &expanded_ivs, ENCODE_ROUNDS)
    }
}
