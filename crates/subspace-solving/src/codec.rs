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

#[cfg(feature = "std")]
use rayon::prelude::*;
use sloth256_189::cpu;
#[cfg(feature = "opencl")]
use sloth256_189::opencl::{self, OpenClBatch, OpenClEncoder};
#[cfg(feature = "opencl")]
use std::sync::{Arc, Mutex};
use subspace_core_primitives::{crypto, Sha256Hash, PIECE_SIZE};

/// Number of pieces for GPU to encode in a batch
#[cfg(feature = "opencl")]
const GPU_PIECE_BLOCK: usize = 1024;
const ENCODE_ROUNDS: usize = 1;

/// Encoding errors
#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum BatchEncodeError {
    /// Pieces argument is not multiple of piece size
    #[cfg_attr(
        feature = "thiserror",
        error("Pieces argument is not multiple of piece size")
    )]
    NotMultipleOfPieceSize,
    /// CPU encoding error
    #[cfg_attr(feature = "thiserror", error("CPU encoding error: {0}"))]
    CpuEncodeError(#[from] cpu::EncodeError),
    /// OpenCL encoder error
    #[cfg(feature = "opencl")]
    #[cfg_attr(feature = "thiserror", error("OpenCL error: {0}"))]
    OpenCLEncodeError(#[from] opencl::OpenCLEncodeError),
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
#[derive(Debug, Clone)]
pub struct SubspaceCodec {
    farmer_public_key_hash: Sha256Hash,
    #[cfg(feature = "opencl")]
    // Type is so complicated in order to make everything thread safe and clonable
    opencl_encoder: Option<Arc<Mutex<OpenClEncoder>>>,
    cpu_cores: usize,
}

impl SubspaceCodec {
    /// New instance with 256-bit prime and 4096-byte genesis piece size
    pub fn new(farmer_public_key: &[u8]) -> Self {
        #[cfg(feature = "opencl")]
        let opencl_encoder = opencl::OpenClEncoder::new(Some(OpenClBatch {
            size: GPU_PIECE_BLOCK * PIECE_SIZE,
            layers: ENCODE_ROUNDS,
        }))
        .map(Mutex::new)
        .map(Arc::new)
        .ok();
        Self {
            farmer_public_key_hash: crypto::sha256_hash(farmer_public_key),
            #[cfg(feature = "opencl")]
            opencl_encoder,
            #[cfg(feature = "std")]
            cpu_cores: num_cpus::get(),
            #[cfg(not(feature = "std"))]
            cpu_cores: 1,
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
        #[cfg(feature = "opencl")]
        if self.opencl_encoder.is_some() {
            return GPU_PIECE_BLOCK;
        }

        self.cpu_cores
    }

    /// Encode given batch of pieces using the best method available, which might be GPU, CPU or
    /// combination of both.
    ///
    /// [`SubspaceCodec::batch_size()`] can be used to determine the recommended batch size, input
    /// should ideally contain at least that many worth of pieces to achieve highest efficiency, it
    /// is recommended that the input is a multiple of that, but, strictly speaking, doesn't have to
    /// be.
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

        #[cfg(feature = "opencl")]
        {
            let mut pieces_to_process = pieces.len() / PIECE_SIZE;

            if pieces_to_process >= GPU_PIECE_BLOCK {
                pieces_to_process = pieces_to_process / GPU_PIECE_BLOCK * GPU_PIECE_BLOCK;

                let opencl_result = self.batch_encode_opencl(
                    &mut pieces[..pieces_to_process * PIECE_SIZE],
                    &piece_indexes[..pieces_to_process],
                );

                if let Err(error) = opencl_result {
                    tracing::error!(%error, "An error happened on the GPU");
                    // Just in case use for all the next times
                    self.opencl_encoder = None;
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

    #[cfg(feature = "std")]
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

    #[cfg(not(feature = "std"))]
    fn batch_encode_cpu(
        &self,
        pieces: &mut [u8],
        piece_indexes: &[u64],
    ) -> Result<(), cpu::EncodeError> {
        pieces
            .chunks_exact_mut(PIECE_SIZE)
            .zip(piece_indexes)
            .try_for_each(|(piece, &piece_index)| self.encode(piece, piece_index))
    }

    #[cfg(feature = "opencl")]
    fn batch_encode_opencl(
        &mut self,
        pieces: &mut [u8],
        piece_indexes: &[u64],
    ) -> Result<(), opencl::OpenCLEncodeError> {
        use subspace_core_primitives::SHA256_HASH_SIZE;
        let mut expanded_ivs = vec![0u8; pieces.len() / PIECE_SIZE * SHA256_HASH_SIZE];
        expanded_ivs
            .par_chunks_exact_mut(SHA256_HASH_SIZE)
            .zip_eq(piece_indexes)
            .for_each(|(expanded_iv, &piece_index)| {
                expanded_iv.copy_from_slice(&self.farmer_public_key_hash);

                mix_public_key_hash_with_piece_index(expanded_iv, piece_index);
            });

        self.opencl_encoder
            .as_mut()
            .unwrap()
            .lock()
            .expect("Lock is never poisoned")
            .encode(pieces, &expanded_ivs, ENCODE_ROUNDS)
    }
}
