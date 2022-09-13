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

//! Various cryptographic utilities used across Subspace Network.

use crate::{Blake2b256Hash, Sha256Hash, BLAKE2B_256_HASH_SIZE};
use blake2_rfc::blake2b::{blake2b, Blake2b};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// BLAKE2b-256 hashing of a single value.
pub fn blake2b_256_hash(data: &[u8]) -> Blake2b256Hash {
    blake2b(BLAKE2B_256_HASH_SIZE, &[], data)
        .as_bytes()
        .try_into()
        .expect("Initialized with correct length; qed")
}

/// BLAKE2b-256 hashing of a pair of values.
pub fn blake2b_256_hash_pair(a: &[u8], b: &[u8]) -> Blake2b256Hash {
    let mut state = Blake2b::new(BLAKE2B_256_HASH_SIZE);
    state.update(a);
    state.update(b);
    state
        .finalize()
        .as_bytes()
        .try_into()
        .expect("Initialized with correct length; qed")
}

/// Hmac with Sha2-256 hash function.
pub fn hmac_sha256(key: &[u8], piece: &[u8]) -> Sha256Hash {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("Sha256 HMAC can take key of any size; qed");
    mac.update(piece);

    // `result` has type `Output` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    mac.finalize()
        .into_bytes()
        .as_slice()
        .try_into()
        .expect("Sha256 output is always 32 bytes; qed")
}
