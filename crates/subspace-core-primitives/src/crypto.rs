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

use crate::{Blake3Hash, ScalarBytes};

/// BLAKE3 hashing of a single value.
pub fn blake3_hash(data: &[u8]) -> Blake3Hash {
    blake3::hash(data).as_bytes().into()
}

/// BLAKE3 hashing of a single value in parallel (only useful for large values well above 128kiB).
#[cfg(feature = "parallel")]
#[inline]
pub fn blake3_hash_parallel(data: &[u8]) -> Blake3Hash {
    let mut state = blake3::Hasher::new();
    state.update_rayon(data);
    state.finalize().as_bytes().into()
}

/// BLAKE3 keyed hashing of a single value.
#[inline]
pub fn blake3_hash_with_key(key: &[u8; 32], data: &[u8]) -> Blake3Hash {
    blake3::keyed_hash(key, data).as_bytes().into()
}

/// BLAKE3 hashing of a list of values.
#[inline]
pub fn blake3_hash_list(data: &[&[u8]]) -> Blake3Hash {
    let mut state = blake3::Hasher::new();
    for d in data {
        state.update(d);
    }
    state.finalize().as_bytes().into()
}

/// BLAKE3 hashing of a single value truncated to 254 bits as Scalar for usage with KZG.
#[inline]
pub fn blake3_254_hash_to_scalar(data: &[u8]) -> ScalarBytes {
    let mut hash = blake3_hash(data);
    // Erase first 2 bits to effectively truncate the hash (number is interpreted as big-endian)
    hash[0] &= 0b00111111;
    ScalarBytes(*hash)
}
