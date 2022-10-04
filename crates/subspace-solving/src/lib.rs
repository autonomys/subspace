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

use bitvec::prelude::*;
pub use codec::{BatchEncodeError, SubspaceCodec};
use merlin::Transcript;
use schnorrkel::vrf::{VRFInOut, VRFOutput, VRFProof};
use schnorrkel::{Keypair, PublicKey, SignatureResult};
use subspace_core_primitives::crypto::kzg::Witness;
use subspace_core_primitives::crypto::{
    blake2b_256_hash, blake2b_256_hash_list, blake2b_256_hash_with_key,
};
use subspace_core_primitives::{
    Blake2b256Hash, LocalChallenge, Piece, Randomness, Salt, SectorId, SolutionRange, Tag,
    TagSignature, TAG_SIZE,
};

const LOCAL_CHALLENGE_LABEL: &[u8] = b"subspace_local_challenge";
const PLOT_TARGET_CONTEXT: &[u8] = b"subspace_plot_target";
const TAG_SIGNATURE_LABEL: &[u8] = b"subspace_tag_signature";

/// Signing context used for creating reward signatures by farmers.
pub const REWARD_SIGNING_CONTEXT: &[u8] = b"subspace_reward";

/// Check whether commitment tag of a piece is valid for a particular salt, which is used as a
/// Proof-of-Replication
pub fn is_tag_valid(piece: &Piece, salt: Salt, tag: Tag) -> bool {
    create_tag(piece, salt) == tag
}

/// Create a commitment tag of a piece for a particular salt.
pub fn create_tag(piece: &[u8], salt: Salt) -> Tag {
    blake2b_256_hash_with_key(piece, &salt)[..TAG_SIZE]
        .try_into()
        .expect("Slice is always of correct size; qed")
}

// TODO: Separate type for global challenge
/// Derive global slot challenge from global randomness.
pub fn derive_global_challenge(global_randomness: &Randomness, slot: u64) -> Blake2b256Hash {
    blake2b_256_hash_list(&[global_randomness, &slot.to_le_bytes()])
}

fn create_local_challenge_transcript(global_challenge: &Blake2b256Hash) -> Transcript {
    let mut transcript = Transcript::new(LOCAL_CHALLENGE_LABEL);
    transcript.append_message(b"global challenge", global_challenge);
    transcript
}

/// Derive local challenge for farmer from keypair and global challenge.
pub fn derive_local_challenge(
    keypair: &Keypair,
    global_challenge: Blake2b256Hash,
) -> LocalChallenge {
    let (in_out, proof, _) = keypair.vrf_sign(create_local_challenge_transcript(&global_challenge));

    LocalChallenge {
        output: in_out.output.to_bytes(),
        proof: proof.to_bytes(),
    }
}

/// Derive local challenge and target for farmer from keypair and global challenge.
pub fn derive_local_challenge_and_target(
    keypair: &Keypair,
    global_challenge: Blake2b256Hash,
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
    global_challenge: Blake2b256Hash,
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
    global_challenge: Blake2b256Hash,
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

// TODO: This is temporary and correct V2 spec will use Chia PoS primitive instead
/// Derive one-time pad for piece chunk encoding/decoding. One-time pad is big enough for any
/// reasonable size of `space_l`, but doesn't have to be used fully.
pub fn derive_piece_chunk_otp(
    sector_id: &SectorId,
    piece_witness: &Witness,
    chunk_index: u32,
) -> [u8; 8] {
    let hash = blake2b_256_hash_list(&[
        sector_id.as_ref(),
        &piece_witness.to_bytes(),
        &chunk_index.to_le_bytes(),
    ]);

    [
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ]
}

/// Expand chunk to be the same size as solution range for further comparison
pub fn expand_chunk(chunk: &BitSlice<u8, Lsb0>) -> SolutionRange {
    let mut bytes = 0u64.to_le_bytes();

    bytes
        .view_bits_mut::<Lsb0>()
        .iter_mut()
        .zip(chunk)
        .for_each(|(mut expanded, source)| {
            *expanded = *source;
        });

    let hash = blake2b_256_hash(&bytes);

    SolutionRange::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ])
}
