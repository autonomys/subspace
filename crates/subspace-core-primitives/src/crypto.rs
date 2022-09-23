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

pub mod kzg;

use crate::{Blake2b256Hash, BLAKE2B_256_HASH_SIZE};
use blake2_rfc::blake2b::{blake2b, Blake2b};

/// BLAKE2b-256 hashing of a single value.
pub fn blake2b_256_hash(data: &[u8]) -> Blake2b256Hash {
    blake2b_256_hash_with_key(data, &[])
}

/// BLAKE2b-256 keyed hashing of a single value.
///
/// PANIC: Panics if key is longer than 64 bytes.
pub fn blake2b_256_hash_with_key(data: &[u8], key: &[u8]) -> Blake2b256Hash {
    blake2b(BLAKE2B_256_HASH_SIZE, key, data)
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
