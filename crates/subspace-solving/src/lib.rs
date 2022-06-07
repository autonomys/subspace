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

// TODO: Uncomment after update of sloth to 0.4
//#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

mod codec;

pub use codec::{BatchEncodeError, SubspaceCodec};
pub use construct_uint::{PieceDistance, U256};
use merlin::Transcript;
use schnorrkel::vrf::{VRFInOut, VRFOutput, VRFProof};
use schnorrkel::{Keypair, PublicKey, SignatureResult};
use subspace_core_primitives::{
    crypto, LocalChallenge, Piece, Randomness, Salt, Sha256Hash, Tag, TagSignature, TAG_SIZE,
};

const LOCAL_CHALLENGE_LABEL: &[u8] = b"subspace_local_challenge";
const PLOT_TARGET_CONTEXT: &[u8] = b"subspace_plot_target";
const TAG_SIGNATURE_LABEL: &[u8] = b"subspace_tag_signature";

/// Signing context used for creating reward signatures by farmers.
pub const REWARD_SIGNING_CONTEXT: &[u8] = b"subspace_reward";

#[allow(clippy::assign_op_pattern, clippy::ptr_offset_with_cast)]
mod construct_uint {
    //! This module is needed to scope clippy allows

    use num_traits::{WrappingAdd, WrappingSub};
    use subspace_core_primitives::PieceIndexHash;

    uint::construct_uint! {
        pub struct U256(4);
    }

    /// Distance to piece index hash from farmer identity
    pub type PieceDistance = U256;

    impl U256 {
        /// Calculates the distance metric between piece index hash and farmer address.
        pub fn distance(PieceIndexHash(piece): &PieceIndexHash, address: &[u8]) -> PieceDistance {
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

    impl WrappingAdd for U256 {
        fn wrapping_add(&self, other: &Self) -> Self {
            self.overflowing_add(*other).0
        }
    }

    impl WrappingSub for U256 {
        fn wrapping_sub(&self, other: &Self) -> Self {
            self.overflowing_sub(*other).0
        }
    }

    impl From<PieceIndexHash> for U256 {
        fn from(PieceIndexHash(hash): PieceIndexHash) -> Self {
            hash.into()
        }
    }

    impl From<U256> for PieceIndexHash {
        fn from(distance: U256) -> Self {
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

// TODO: Separate type for global challenge
/// Derive global slot challenge from global randomness.
pub fn derive_global_challenge(global_randomness: &Randomness, slot: u64) -> Sha256Hash {
    crypto::sha256_hash_pair(global_randomness, &slot.to_le_bytes())
}

fn create_local_challenge_transcript(global_challenge: &Sha256Hash) -> Transcript {
    let mut transcript = Transcript::new(LOCAL_CHALLENGE_LABEL);
    transcript.append_message(b"global challenge", global_challenge);
    transcript
}

/// Derive local challenge for farmer from keypair and global challenge.
pub fn derive_local_challenge(keypair: &Keypair, global_challenge: Sha256Hash) -> LocalChallenge {
    let (in_out, proof, _) = keypair.vrf_sign(create_local_challenge_transcript(&global_challenge));

    LocalChallenge {
        output: in_out.output.to_bytes(),
        proof: proof.to_bytes(),
    }
}

/// Derive local challenge and target for farmer from keypair and global challenge.
pub fn derive_local_challenge_and_target(
    keypair: &Keypair,
    global_challenge: Sha256Hash,
) -> (LocalChallenge, Tag) {
    let (in_out, proof, _) = keypair.vrf_sign(create_local_challenge_transcript(&global_challenge));

    let local_challenge = LocalChallenge {
        output: in_out.output.to_bytes(),
        proof: proof.to_bytes(),
    };
    let target = in_out.make_bytes(PLOT_TARGET_CONTEXT);

    (local_challenge, target)
}

/// Verify local challenge for farmer's public key that was derived from the global challenge.
pub fn verify_local_challenge(
    public_key: &PublicKey,
    global_challenge: Sha256Hash,
    local_challenge: &LocalChallenge,
) -> SignatureResult<VRFInOut> {
    public_key
        .vrf_verify(
            create_local_challenge_transcript(&global_challenge),
            &VRFOutput(local_challenge.output),
            &VRFProof::from_bytes(&local_challenge.proof)?,
        )
        .map(|(in_out, _)| in_out)
}

/// Derive challenge target from public key and local challenge.
///
/// NOTE: If you are not the signer then you must verify the local challenge before calling this
/// function.
pub fn derive_target(
    public_key: &PublicKey,
    global_challenge: Sha256Hash,
    local_challenge: &LocalChallenge,
) -> SignatureResult<Tag> {
    let in_out = VRFOutput(local_challenge.output).attach_input_hash(
        public_key,
        create_local_challenge_transcript(&global_challenge),
    )?;

    Ok(in_out.make_bytes(PLOT_TARGET_CONTEXT))
}

/// Transcript used for creation and verification of VRF signatures for tags.
pub fn create_tag_signature_transcript(tag: Tag) -> Transcript {
    let mut transcript = Transcript::new(TAG_SIGNATURE_LABEL);
    transcript.append_message(b"tag", &tag);
    transcript
}

/// Create tag signature using farmer's keypair.
pub fn create_tag_signature(keypair: &Keypair, tag: Tag) -> TagSignature {
    let (in_out, proof, _) = keypair.vrf_sign(create_tag_signature_transcript(tag));

    TagSignature {
        output: in_out.output.to_bytes(),
        proof: proof.to_bytes(),
    }
}

/// Verify that tag signature was created correctly.
pub fn verify_tag_signature(
    tag: Tag,
    tag_signature: &TagSignature,
    public_key: &PublicKey,
) -> SignatureResult<VRFInOut> {
    public_key
        .vrf_verify(
            create_tag_signature_transcript(tag),
            &VRFOutput(tag_signature.output),
            &VRFProof::from_bytes(&tag_signature.proof)?,
        )
        .map(|(in_out, _)| in_out)
}
