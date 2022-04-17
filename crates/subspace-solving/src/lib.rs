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

pub use codec::{BatchEncodeError, SubspaceCodec};
pub use construct_uint::PieceDistance;
use schnorrkel::SignatureResult;
use sha2::{Digest, Sha256};
use subspace_core_primitives::{crypto, LocalChallenge, Piece, Randomness, Salt, Tag, TAG_SIZE};

/// Signing context used for creating solution signatures by farmer
pub const SOLUTION_SIGNING_CONTEXT: &[u8] = b"farmer_solution";

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
        pub fn distance(PieceIndexHash(piece): &PieceIndexHash, address: impl AsRef<[u8]>) -> Self {
            let piece = Self::from_big_endian(piece);
            let address = Self::from_big_endian(address.as_ref());
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
}

/// Check whether commitment tag of a piece is valid for a particular salt, which is used as a
/// Proof-of-Replication
pub fn is_tag_valid(piece: &Piece, salt: Salt, tag: Tag) -> bool {
    create_tag(piece, salt) == tag
}

/// Create a commitment tag of a piece for a particular salt.
pub fn create_tag(piece: impl AsRef<[u8]>, salt: Salt) -> Tag {
    crypto::hmac_sha256(salt, piece.as_ref())[..TAG_SIZE]
        .try_into()
        .expect("Slice is always of correct size; qed")
}

/// Derive global slot challenge from global randomness.
pub fn derive_global_challenge<Slot: Into<u64>>(global_randomness: &Randomness, slot: Slot) -> Tag {
    let mut hasher = Sha256::new();
    hasher.update(global_randomness);
    hasher.update(&Into::<u64>::into(slot).to_le_bytes());
    hasher.finalize()[..TAG_SIZE]
        .try_into()
        .expect("Slice is always of correct size; qed")
}

/// Verify local challenge for farmer's public key that was derived from the global challenge.
pub fn is_local_challenge_valid<P: AsRef<[u8]>>(
    global_challenge: Tag,
    local_challenge: &LocalChallenge,
    public_key: P,
) -> SignatureResult<()> {
    let signature = schnorrkel::Signature::from_bytes(local_challenge)?;
    let public_key = schnorrkel::PublicKey::from_bytes(public_key.as_ref())?;

    let ctx = schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT);
    public_key.verify(ctx.bytes(&global_challenge), &signature)
}
