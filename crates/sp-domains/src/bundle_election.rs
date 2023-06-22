use crate::{DomainId, ExecutorPublicKey, StakeWeight};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::crypto::{VrfPublic, Wraps};
use sp_core::sr25519::vrf::{VrfInput, VrfOutput, VrfSignature};
use subspace_core_primitives::crypto::blake2b_256_hash_list;
use subspace_core_primitives::Blake2b256Hash;

const VRF_TRANSCRIPT_LABEL: &[u8] = b"executor";

const LOCAL_RANDOMNESS_CONTEXT: &[u8] = b"bundle_election_local_randomness_context";

type LocalRandomness = [u8; core::mem::size_of::<u128>()];

fn derive_local_randomness(
    vrf_output: &VrfOutput,
    public_key: &ExecutorPublicKey,
    global_challenge: &Blake2b256Hash,
) -> Result<LocalRandomness, parity_scale_codec::Error> {
    vrf_output.make_bytes(
        LOCAL_RANDOMNESS_CONTEXT,
        &make_local_randomness_input(global_challenge),
        public_key.as_ref(),
    )
}

/// Returns the domain-specific solution for the challenge of producing a bundle.
pub fn derive_bundle_election_solution(
    domain_id: DomainId,
    vrf_output: &VrfOutput,
    public_key: &ExecutorPublicKey,
    global_challenge: &Blake2b256Hash,
) -> Result<u128, parity_scale_codec::Error> {
    let local_randomness = derive_local_randomness(vrf_output, public_key, global_challenge)?;
    let local_domain_randomness =
        blake2b_256_hash_list(&[&domain_id.to_le_bytes(), &local_randomness]);

    let election_solution = u128::from_le_bytes(
        local_domain_randomness
            .split_at(core::mem::size_of::<u128>())
            .0
            .try_into()
            .expect("Local domain randomness must fit into u128; qed"),
    );

    Ok(election_solution)
}

/// Returns the election threshold based on the stake weight proportion and slot probability.
pub fn calculate_bundle_election_threshold(
    stake_weight: StakeWeight,
    total_stake_weight: StakeWeight,
    slot_probability: (u64, u64),
) -> u128 {
    // The calculation is written for not causing the overflow, which might be harder to
    // understand, the formula in a readable form is as followes:
    //
    //              slot_probability.0      stake_weight
    // threshold =  ------------------ * --------------------- * u128::MAX
    //              slot_probability.1    total_stake_weight
    //
    // TODO: better to have more audits on this calculation.
    u128::MAX / u128::from(slot_probability.1) * u128::from(slot_probability.0) / total_stake_weight
        * stake_weight
}

pub fn is_election_solution_within_threshold(election_solution: u128, threshold: u128) -> bool {
    election_solution <= threshold
}

/// Make a VRF inout.
pub fn make_local_randomness_input(global_challenge: &Blake2b256Hash) -> VrfInput {
    VrfInput::new(
        VRF_TRANSCRIPT_LABEL,
        &[(b"global challenge", global_challenge)],
    )
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum VrfProofError {
    /// Invalid vrf proof.
    BadProof,
}

/// Verify the vrf proof generated in the bundle election.
pub(crate) fn verify_vrf_proof(
    public_key: &ExecutorPublicKey,
    vrf_signature: &VrfSignature,
    global_challenge: &Blake2b256Hash,
) -> Result<(), VrfProofError> {
    if !public_key.as_inner_ref().vrf_verify(
        &make_local_randomness_input(global_challenge).into(),
        vrf_signature,
    ) {
        return Err(VrfProofError::BadProof);
    }

    Ok(())
}
