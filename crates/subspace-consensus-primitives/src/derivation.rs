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

use core::mem;
use merlin::Transcript;
use schnorrkel::vrf::VRFOutput;
use schnorrkel::{Keypair, PublicKey, SignatureResult};
use sp_arithmetic::traits::SaturatedConversion;
use subspace_core_primitives::{
    crypto, LocalChallenge, Randomness, Salt, Sha256Hash, Tag, TagSignature, RANDOMNESS_CONTEXT,
    RANDOMNESS_LENGTH, SALT_HASHING_PREFIX, SALT_SIZE, TAG_SIZE,
};

/// Derive randomness from tag signature.
///
/// NOTE: If you are not the signer then you must verify the local challenge before calling this
/// function.
pub fn derive_randomness<PublicKey>(
    public_key: &PublicKey,
    tag: Tag,
    tag_signature: &TagSignature,
) -> SignatureResult<Randomness>
where
    PublicKey: AsRef<[u8]>,
{
    let in_out = VRFOutput(tag_signature.output).attach_input_hash(
        &schnorrkel::PublicKey::from_bytes(public_key.as_ref())?,
        create_tag_signature_transcript(tag),
    )?;

    Ok(in_out.make_bytes(RANDOMNESS_CONTEXT))
}

/// Derives next solution range based on the total era slots and slot probability
pub fn derive_next_solution_range(
    start_slot: u64,
    current_slot: u64,
    slot_probability: (u64, u64),
    current_solution_range: u64,
    era_duration: u64,
) -> u64 {
    // calculate total slots within this era
    let era_slot_count = current_slot - start_slot;

    // Now we need to re-calculate solution range. The idea here is to keep block production at
    // the same pace while space pledged on the network changes. For this we adjust previous
    // solution range according to actual and expected number of blocks per era.

    // Below is code analogous to the following, but without using floats:
    // ```rust
    // let actual_slots_per_block = era_slot_count as f64 / era_duration as f64;
    // let expected_slots_per_block =
    //     slot_probability.1 as f64 / slot_probability.0 as f64;
    // let adjustment_factor =
    //     (actual_slots_per_block / expected_slots_per_block).clamp(0.25, 4.0);
    //
    // next_solution_range =
    //     (solution_ranges.current as f64 * adjustment_factor).round() as u64;
    // ```
    u64::saturated_from(
        u128::from(current_solution_range)
            .saturating_mul(u128::from(era_slot_count))
            .saturating_mul(u128::from(slot_probability.0))
            / u128::from(era_duration)
            / u128::from(slot_probability.1),
    )
    .clamp(
        current_solution_range / 4,
        current_solution_range.saturating_mul(4),
    )
}

const SALT_HASHING_PREFIX_LEN: usize = SALT_HASHING_PREFIX.len();

/// Derives next salt value from the randomness provided.
pub fn derive_next_salt_from_randomness(eon_index: u64, randomness: &Randomness) -> Salt {
    let mut input = [0u8; SALT_HASHING_PREFIX_LEN + RANDOMNESS_LENGTH + mem::size_of::<u64>()];
    input[..SALT_HASHING_PREFIX_LEN].copy_from_slice(SALT_HASHING_PREFIX);
    input[SALT_HASHING_PREFIX_LEN..SALT_HASHING_PREFIX_LEN + RANDOMNESS_LENGTH]
        .copy_from_slice(randomness);
    input[SALT_HASHING_PREFIX_LEN + RANDOMNESS_LENGTH..].copy_from_slice(&eon_index.to_le_bytes());

    crypto::sha256_hash(&input)[..SALT_SIZE]
        .try_into()
        .expect("Slice has exactly the size needed; qed")
}

const LOCAL_CHALLENGE_LABEL: &[u8] = b"subspace_local_challenge";
const PLOT_TARGET_CONTEXT: &[u8] = b"subspace_plot_target";
const TAG_SIGNATURE_LABEL: &[u8] = b"subspace_tag_signature";

/// Signing context used for creating reward signatures by farmers.
pub const REWARD_SIGNING_CONTEXT: &[u8] = b"subspace_reward";

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

pub(crate) fn create_local_challenge_transcript(global_challenge: &Sha256Hash) -> Transcript {
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
