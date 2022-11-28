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

use crate::Blake2b256Hash;
use blake2::digest::typenum::U32;
use blake2::digest::{FixedOutput, Update};
use blake2::{Blake2b, Blake2bMac, Digest};

/// BLAKE2b-256 hashing of a single value.
pub fn blake2b_256_hash(data: &[u8]) -> Blake2b256Hash {
    let mut state = Blake2b::<U32>::new();
    Update::update(&mut state, data);
    state.finalize_fixed().into()
}

/// BLAKE2b-256 hashing of a single value truncated to 254 bits.
///
/// TODO: We probably wouldn't need this eventually
pub fn blake2b_256_254_hash(data: &[u8]) -> Blake2b256Hash {
    let mut hash = blake2b_256_hash(data);
    // Erase last 2 bits to effectively truncate the hash (number is interpreted as little-endian)
    hash[31] &= 0b00111111;
    hash
}

/// BLAKE2b-256 keyed hashing of a single value.
///
/// PANIC: Panics if key is longer than 64 bytes.
pub fn blake2b_256_hash_with_key(data: &[u8], key: &[u8]) -> Blake2b256Hash {
    let mut state = Blake2bMac::<U32>::new_with_salt_and_personal(key, &[], &[])
        .expect("Only panics when key is over 64 bytes as specified in function description");
    Update::update(&mut state, data);
    state.finalize_fixed().into()
}

/// BLAKE2b-256 hashing of a list of values.
pub fn blake2b_256_hash_list(data: &[&[u8]]) -> Blake2b256Hash {
    let mut state = Blake2b::<U32>::new();
    for d in data {
        Update::update(&mut state, d);
    }
    state
        .finalize()
        .try_into()
        .expect("Initialized with correct length; qed")
}
