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

//! Set of modules that implement utilities for solving and verifying of solutions in
//! [Subspace Network Blockchain](https://subspace.network).

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations, missing_docs)]

mod codec;

pub use codec::SubspaceCodec;
use sha2::{Digest, Sha256};
use subspace_core_primitives::{crypto, Piece, Randomness, Salt, Tag};

/// Signing context used for creating solution signatures by farmer
pub const SOLUTION_SIGNING_CONTEXT: &[u8] = b"FARMER";

/// Size of `Tag` in bytes.
pub const TAG_SIZE: usize = core::mem::size_of::<Tag>();

/// Check whether commitment tag of a piece is valid for a particular salt, which is used as a
/// Proof-of-Replication
pub fn is_tag_valid(piece: &Piece, tag: Tag, salt: Salt) -> bool {
    create_tag(piece, salt) == tag
}

/// Create a commitment tag of a piece for a particular salt
pub fn create_tag(piece: &[u8], salt: Salt) -> Tag {
    crypto::hmac_sha256(salt, piece)[..TAG_SIZE]
        .try_into()
        .expect("Slice is always of correct size; qed")
}

/// Derive global slot challenge from epoch randomness
pub fn derive_global_challenge<Slot: Into<u64>>(epoch_randomness: &Randomness, slot: Slot) -> Tag {
    let mut hasher = Sha256::new();
    hasher.update(epoch_randomness);
    hasher.update(&Into::<u64>::into(slot).to_le_bytes());
    hasher.finalize()[..TAG_SIZE]
        .try_into()
        .expect("Slice is always of correct size; qed")
}

/// Derive local challenge for farmer's public key hash from global challenge
pub fn derive_local_challenge<C: AsRef<[u8]>, H: AsRef<[u8]>>(
    global_challenge: C,
    farmer_public_key_hash: H,
) -> Tag {
    let mut hasher = Sha256::new();
    hasher.update(global_challenge.as_ref());
    hasher.update(farmer_public_key_hash.as_ref());
    hasher.finalize()[..TAG_SIZE]
        .try_into()
        .expect("Slice is always of correct size; qed")
}
