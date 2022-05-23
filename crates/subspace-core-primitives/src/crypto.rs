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

use crate::Sha256Hash;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Simple Sha2-256 hashing.
pub fn sha256_hash(data: &[u8]) -> Sha256Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher
        .finalize()
        .as_slice()
        .try_into()
        .expect("Sha256 output is always 32 bytes; qed")
}

/// Simple Sha2-256 hashing of a pair of values.
pub fn sha256_hash_pair(a: &[u8], b: &[u8]) -> Sha256Hash {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher
        .finalize()
        .as_slice()
        .try_into()
        .expect("Sha256 output is always 32 bytes; qed")
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
