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
#![cfg_attr(not(feature = "std"), no_std)]

mod codec;

pub use codec::{BatchEncodeError, SubspaceCodec};
pub use construct_uint::PieceDistance;
use schnorrkel::SignatureResult;
use subspace_core_primitives::{
    crypto, LocalChallenge, Piece, Randomness, Salt, Sha256Hash, Tag, TAG_SIZE,
};

/// Signing context used for creating solution signatures by farmers.
pub const SOLUTION_SIGNING_CONTEXT: &[u8] = b"farmer_solution";

/// Signing context used for creating reward signatures by farmers.
pub const REWARD_SIGNING_CONTEXT: &[u8] = b"farmer_reward";

#[allow(clippy::assign_op_pattern, clippy::ptr_offset_with_cast)]
mod construct_uint {
    //! This module is needed to scope clippy allows

    use num_traits::{WrappingAdd, WrappingSub};
    use subspace_core_primitives::PieceIndexHash;

    uint::construct_uint! {
        /// Distance to piece index hash from farmer identity
        pub struct PieceDistance(4);
    }

    impl PieceDistance {
        /// Calculates the distance metric between piece index hash and farmer address.
        pub fn distance(PieceIndexHash(piece): &PieceIndexHash, address: &[u8]) -> Self {
            let piece = Self::from_big_endian(piece);
            let address = Self::from_big_endian(address);
            subspace_core_primitives::bidirectional_distance(&piece, &address)
        }

        /// Convert piece distance to big endian bytes
        pub fn to_bytes(self) -> [u8; 32] {
            self.into()
        }

        /// The middle of the piece distance field.
        /// The analogue of `0b1000_0000` for `u8`.
        pub const MIDDLE: Self = {
            // TODO: This assumes that numbers are stored little endian,
            //  should be replaced with just `Self::MAX / 2`, but it is not `const fn` in Rust yet.
            Self([u64::MAX, u64::MAX, u64::MAX, u64::MAX / 2])
        };
    }

    impl WrappingAdd for PieceDistance {
        fn wrapping_add(&self, other: &Self) -> Self {
            self.overflowing_add(*other).0
        }
    }

    impl WrappingSub for PieceDistance {
        fn wrapping_sub(&self, other: &Self) -> Self {
            self.overflowing_sub(*other).0
        }
    }

    impl From<PieceIndexHash> for PieceDistance {
        fn from(PieceIndexHash(hash): PieceIndexHash) -> Self {
            hash.into()
        }
    }

    impl From<PieceDistance> for PieceIndexHash {
        fn from(distance: PieceDistance) -> Self {
            Self(distance.into())
        }
    }
}

/// Check whether commitment tag of a piece is valid for a particular salt, which is used as a
/// Proof-of-Replication
pub fn is_tag_valid(piece: &Piece, salt: Salt, tag: Tag) -> bool {
    create_tag(piece, salt) == tag
}

/// Create a commitment tag of a piece for a particular salt.
pub fn create_tag(piece: &[u8], salt: Salt) -> Tag {
    crypto::hmac_sha256(&salt, piece)[..TAG_SIZE]
        .try_into()
        .expect("Slice is always of correct size; qed")
}

/// Derive global slot challenge from global randomness.
pub fn derive_global_challenge(global_randomness: &Randomness, slot: u64) -> Sha256Hash {
    crypto::sha256_hash_pair(global_randomness, &slot.to_le_bytes())
}

/// Verify local challenge for farmer's public key that was derived from the global challenge.
pub fn is_local_challenge_valid(
    global_challenge: Sha256Hash,
    local_challenge: &LocalChallenge,
    public_key: &[u8],
) -> SignatureResult<()> {
    let signature = schnorrkel::Signature::from_bytes(local_challenge)?;
    let public_key = schnorrkel::PublicKey::from_bytes(public_key)?;

    let ctx = schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT);
    public_key.verify(ctx.bytes(&global_challenge), &signature)
}
