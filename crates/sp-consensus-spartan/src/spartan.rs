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

//! Spartan-based PoR.

use ring::{digest, hmac};
use sloth256_189::cpu;
use std::convert::TryInto;
use std::io::Write;
pub use subspace_core_primitives::{Piece, PIECE_SIZE};

pub const PRIME_SIZE_BYTES: usize = 32;
pub const GENESIS_PIECE_SEED: &str = "spartan";
pub const ENCODE_ROUNDS: usize = 1;
pub const SIGNING_CONTEXT: &[u8] = b"FARMER";

pub type Tag = [u8; 8];
pub type Salt = [u8; 8];

#[derive(Clone)]
pub struct Spartan {
    genesis_piece: [u8; PIECE_SIZE],
}

impl Spartan {
    /// New instance with 256-bit prime and 4096-byte genesis piece size
    pub fn new(genesis_piece: [u8; PIECE_SIZE]) -> Self {
        Spartan { genesis_piece }
    }
}

impl Default for Spartan {
    fn default() -> Self {
        Self {
            genesis_piece: genesis_piece_from_seed(GENESIS_PIECE_SEED),
        }
    }
}

impl Spartan {
    /// Create an encoding based on genesis piece using provided encoding key hash, nonce and
    /// desired number of rounds
    pub fn encode(
        &self,
        encoding_key_hash: [u8; PRIME_SIZE_BYTES],
        nonce: u64,
        rounds: usize,
    ) -> [u8; PIECE_SIZE] {
        let mut expanded_iv = encoding_key_hash;
        for (i, &byte) in nonce.to_le_bytes().iter().rev().enumerate() {
            expanded_iv[PRIME_SIZE_BYTES - i - 1] ^= byte;
        }

        let mut encoding = self.genesis_piece;

        cpu::encode(&mut encoding, &expanded_iv, rounds).unwrap();

        encoding
    }

    /// Check if previously created encoding is valid
    pub fn is_encoding_valid(
        &self,
        mut encoding: Piece,
        public_key: &[u8],
        nonce: u64,
        rounds: usize,
    ) -> bool {
        let encoding_key_hash = hash_public_key(public_key);
        let mut expanded_iv = encoding_key_hash;
        for (i, &byte) in nonce.to_le_bytes().iter().rev().enumerate() {
            expanded_iv[PRIME_SIZE_BYTES - i - 1] ^= byte;
        }

        cpu::decode(&mut encoding, &expanded_iv, rounds).unwrap();

        encoding == self.genesis_piece
    }
}

pub fn is_commitment_valid(encoding: &Piece, tag: &Tag, salt: &Salt) -> bool {
    let correct_tag = create_tag(encoding, salt);
    &correct_tag == tag
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

fn hash_public_key(public_key: &[u8]) -> [u8; PRIME_SIZE_BYTES] {
    let mut array = [0u8; PRIME_SIZE_BYTES];
    let hash = digest::digest(&digest::SHA256, public_key);
    array.copy_from_slice(&hash.as_ref()[..PRIME_SIZE_BYTES]);
    array
}

fn create_tag(encoding: &[u8], salt: &[u8]) -> Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    hmac::sign(&key, encoding).as_ref()[0..8]
        .try_into()
        .unwrap()
}
