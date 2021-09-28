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

//! Encoder for the [Subspace Network Blockchain](https://subspace.network) based on the
//! [SLOTH permutation](https://eprint.iacr.org/2015/366).
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations, missing_docs)]

use ring::digest;
use sloth256_189::cpu;
#[cfg(feature = "cuda")]
use sloth256_189::cuda;
use std::io::Write;
use subspace_core_primitives::{crypto, Piece, Sha256Hash, PIECE_SIZE, PRIME_SIZE};

#[cfg(feature = "cuda")]
/// Number of pieces for GPU should be multiples of 1024
const GPU_PIECE_BLOCK: usize = 1024;
const GENESIS_PIECE_SEED: &str = "spartan";
const ENCODE_ROUNDS: usize = 1;

// TODO: Refactor into Subspace
/// Spartan struct used to encode and validate
#[derive(Debug, Clone)]
pub struct Spartan {
    genesis_piece: Piece,
    public_key_hash: Sha256Hash,
    cuda_available: bool,
}

impl Spartan {
    /// New instance with 256-bit prime and 4096-byte genesis piece size
    pub fn new(public_key: &[u8]) -> Self {
        #[cfg(feature = "cuda")]
        let cuda_available = cuda::is_cuda_available();
        #[cfg(not(feature = "cuda"))]
        let cuda_available = false;

        let public_key_hash = crypto::sha256_hash(public_key);

        Spartan {
            genesis_piece: genesis_piece_from_seed(GENESIS_PIECE_SEED),
            public_key_hash,
            cuda_available,
        }
    }
}

impl Spartan {
    // TODO: Refactor from being CUDA-specific to be batch-oriented
    /// Returns true if CUDA is available
    pub fn is_cuda_available(&self) -> bool {
        self.cuda_available
    }

    /// Create an encoding based on genesis piece using provided encoding key hash, nonce and
    /// desired number of rounds
    pub fn encode(&self, nonce: u64) -> Piece {
        let mut expanded_iv = self.public_key_hash;
        for (i, &byte) in nonce.to_le_bytes().iter().rev().enumerate() {
            expanded_iv[PRIME_SIZE - i - 1] ^= byte;
        }

        let mut encoding = self.genesis_piece;

        cpu::encode(&mut encoding, &expanded_iv, ENCODE_ROUNDS).unwrap();

        encoding
    }

    // TODO: Refactor from being CUDA-specific to be batch-oriented
    /// Encode given batch of pieces using GPU, and CPU for the leftovers
    #[cfg(feature = "cuda")]
    pub fn cuda_batch_encode(&self, pieces: &mut [u8], nonce_array: &[u64]) {
        // each expanded_iv will be in format [u8; 32], so `piece_amount` expanded_iv's
        // should consume [u8; 32 * piece_amount] space.
        let piece_count = pieces.len() / PIECE_SIZE;
        let mut expanded_iv_vector: Vec<u8> = Vec::with_capacity(piece_count * PRIME_SIZE);
        let mut expanded_iv;
        for nonce in nonce_array {
            // same public_key_hash will be used for each expanded_iv
            expanded_iv = self.public_key_hash;

            // select the nonce from nonce_array, xor it with the public_key_hash
            nonce
                .to_le_bytes()
                .iter()
                .rev()
                .zip(expanded_iv.iter_mut().rev())
                .for_each(|(nonce_byte, expanded_iv_byte)| *expanded_iv_byte ^= nonce_byte);
            //*/
            expanded_iv_vector.extend(expanded_iv);
        }

        // If there any leftovers from 1024x pieces, cpu will handle them
        let cpu_encode_end_index = piece_count % GPU_PIECE_BLOCK;

        // CPU encoding:
        for x in 0..cpu_encode_end_index {
            cpu::encode(
                &mut pieces[x * PIECE_SIZE..(x + 1) * PIECE_SIZE],
                &expanded_iv_vector[x * PRIME_SIZE..(x + 1) * PRIME_SIZE],
                ENCODE_ROUNDS,
            )
            .unwrap();
        }

        // GPU encoding:
        cuda::encode(
            &mut pieces[cpu_encode_end_index * PIECE_SIZE..],
            &expanded_iv_vector[cpu_encode_end_index * PRIME_SIZE..],
            ENCODE_ROUNDS,
        )
        .unwrap();
    }

    /// Check if previously created encoding is valid
    pub fn is_encoding_valid(&self, mut encoding: Piece, nonce: u64) -> bool {
        let mut expanded_iv = self.public_key_hash;
        for (i, &byte) in nonce.to_le_bytes().iter().rev().enumerate() {
            expanded_iv[PRIME_SIZE - i - 1] ^= byte;
        }

        cpu::decode(&mut encoding, &expanded_iv, ENCODE_ROUNDS).unwrap();

        encoding == self.genesis_piece
    }
}

fn genesis_piece_from_seed(seed: &str) -> Piece {
    let mut piece = [0u8; PIECE_SIZE];
    let mut input = seed.as_bytes().to_vec();
    for mut chunk in piece.chunks_mut(digest::SHA256.output_len) {
        input = digest::digest(&digest::SHA256, &input).as_ref().to_vec();
        chunk.write_all(input.as_ref()).unwrap();
    }
    piece
}
