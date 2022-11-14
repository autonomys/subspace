use crate::{DomainId, ExecutorPublicKey, ProofOfElection, StakeWeight};
use merlin::Transcript;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use schnorrkel::vrf::{VRFOutput, VRFProof, VRF_OUTPUT_LENGTH};
use schnorrkel::{SignatureError, SignatureResult};
use sp_core::H256;
#[cfg(feature = "std")]
use sp_keystore::vrf::{VRFTranscriptData, VRFTranscriptValue};
use sp_runtime::traits::BlakeTwo256;
use sp_std::vec::Vec;
use sp_trie::{read_trie_value, LayoutV1, StorageProof};
use subspace_core_primitives::crypto::blake2b_256_hash_list;
use subspace_core_primitives::Blake2b256Hash;
use well_known_keys::{AUTHORITIES, SLOT_PROBABILITY, TOTAL_STAKE_WEIGHT};

const VRF_TRANSCRIPT_LABEL: &[u8] = b"executor";

const LOCAL_RANDOMNESS_CONTEXT: &[u8] = b"bundle_election_local_randomness_context";

type LocalRandomness = [u8; core::mem::size_of::<u128>()];

fn derive_local_randomness(
    vrf_output: [u8; VRF_OUTPUT_LENGTH],
    public_key: &ExecutorPublicKey,
    global_challenge: &Blake2b256Hash,
) -> SignatureResult<LocalRandomness> {
    let in_out = VRFOutput(vrf_output).attach_input_hash(
        &schnorrkel::PublicKey::from_bytes(public_key.as_ref())?,
        make_local_randomness_transcript(global_challenge),
    )?;

    Ok(in_out.make_bytes(LOCAL_RANDOMNESS_CONTEXT))
}

/// Returns the domain-specific solution for the challenge of producing a bundle.
pub fn derive_bundle_election_solution(
    domain_id: DomainId,
    vrf_output: [u8; VRF_OUTPUT_LENGTH],
    public_key: &ExecutorPublicKey,
    global_challenge: &Blake2b256Hash,
) -> SignatureResult<u128> {
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

/// Make a VRF transcript.
pub fn make_local_randomness_transcript(global_challenge: &Blake2b256Hash) -> Transcript {
    let mut transcript = Transcript::new(VRF_TRANSCRIPT_LABEL);
    transcript.append_message(b"global challenge", global_challenge);
    transcript
}

/// Make a VRF transcript data.
#[cfg(feature = "std")]
pub fn make_local_randomness_transcript_data(
    global_challenge: &Blake2b256Hash,
) -> VRFTranscriptData {
    VRFTranscriptData {
        label: VRF_TRANSCRIPT_LABEL,
        items: vec![(
            "global challenge",
            VRFTranscriptValue::Bytes(global_challenge.to_vec()),
        )],
    }
}

pub mod well_known_keys {
    use crate::DomainId;
    use sp_std::vec;
    use sp_std::vec::Vec;

    /// Storage key of `pallet_executor_registry::Authorities`.
    ///
    /// Authorities::<T>::hashed_key().
    pub(crate) const AUTHORITIES: [u8; 32] = [
        185, 61, 20, 0, 90, 16, 106, 134, 14, 150, 35, 100, 152, 229, 203, 187, 94, 6, 33, 196,
        134, 154, 166, 12, 2, 190, 154, 220, 201, 138, 13, 29,
    ];

    /// Storage key of `pallet_executor_registry::TotalStakeWeight`.
    ///
    /// TotalStakeWeight::<T>::hashed_key().
    pub(crate) const TOTAL_STAKE_WEIGHT: [u8; 32] = [
        185, 61, 20, 0, 90, 16, 106, 134, 14, 150, 35, 100, 152, 229, 203, 187, 173, 245, 4, 89,
        128, 92, 85, 189, 74, 160, 138, 209, 188, 18, 62, 94,
    ];

    /// Storage key of `pallet_executor_registry::SlotProbability`.
    ///
    /// SlotProbability::<T>::hashed_key().
    pub(crate) const SLOT_PROBABILITY: [u8; 32] = [
        185, 61, 20, 0, 90, 16, 106, 134, 14, 150, 35, 100, 152, 229, 203, 187, 60, 16, 174, 72,
        214, 175, 220, 254, 34, 167, 168, 222, 147, 18, 4, 168,
    ];

    // TODO: return the correct core domain storage keys
    pub fn bundle_election_storage_keys(_domain_id: DomainId) -> Vec<[u8; 32]> {
        vec![AUTHORITIES, TOTAL_STAKE_WEIGHT, SLOT_PROBABILITY]
    }
}

/// Parameters for the bundle election.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleElectionParams {
    pub authorities: Vec<(ExecutorPublicKey, StakeWeight)>,
    pub total_stake_weight: StakeWeight,
    pub slot_probability: (u64, u64),
}

impl BundleElectionParams {
    pub fn empty() -> Self {
        Self {
            authorities: Vec::new(),
            total_stake_weight: 0,
            slot_probability: (0, 0),
        }
    }
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum VrfProofError {
    /// Can not construct the vrf public_key/output/proof from the raw bytes.
    VrfSignatureConstructionError,
    /// Invalid vrf proof.
    BadProof,
}

/// Verify the vrf proof generated in the bundle election.
pub fn verify_vrf_proof(
    public_key: &ExecutorPublicKey,
    vrf_output: &[u8],
    vrf_proof: &[u8],
    global_challenge: &Blake2b256Hash,
) -> Result<(), VrfProofError> {
    let public_key = schnorrkel::PublicKey::from_bytes(public_key.as_ref())
        .map_err(|_| VrfProofError::VrfSignatureConstructionError)?;

    public_key
        .vrf_verify(
            make_local_randomness_transcript(global_challenge),
            &VRFOutput::from_bytes(vrf_output)
                .map_err(|_| VrfProofError::VrfSignatureConstructionError)?,
            &VRFProof::from_bytes(vrf_proof)
                .map_err(|_| VrfProofError::VrfSignatureConstructionError)?,
        )
        .map_err(|_| VrfProofError::BadProof)?;

    Ok(())
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum ReadBundleElectionParamsError {
    /// Trie error.
    TrieError,
    /// The value does not exist in the trie.
    MissingValue,
    /// Failed to decode the value read from the trie.
    DecodeError,
}

/// Returns the bundle election parameters read from the given storage proof.
pub fn read_bundle_election_params(
    storage_proof: StorageProof,
    state_root: &H256,
) -> Result<BundleElectionParams, ReadBundleElectionParamsError> {
    let db = storage_proof.into_memory_db::<BlakeTwo256>();

    let read_value = |storage_key| {
        read_trie_value::<LayoutV1<BlakeTwo256>, _>(&db, state_root, storage_key, None, None)
            .map_err(|_| ReadBundleElectionParamsError::TrieError)
    };

    let authorities =
        read_value(&AUTHORITIES)?.ok_or(ReadBundleElectionParamsError::MissingValue)?;
    let authorities: Vec<(ExecutorPublicKey, StakeWeight)> =
        Decode::decode(&mut authorities.as_slice())
            .map_err(|_| ReadBundleElectionParamsError::DecodeError)?;

    let total_stake_weight_value =
        read_value(&TOTAL_STAKE_WEIGHT)?.ok_or(ReadBundleElectionParamsError::MissingValue)?;
    let total_stake_weight: StakeWeight = Decode::decode(&mut total_stake_weight_value.as_slice())
        .map_err(|_| ReadBundleElectionParamsError::DecodeError)?;

    let slot_probability_value =
        read_value(&SLOT_PROBABILITY)?.ok_or(ReadBundleElectionParamsError::MissingValue)?;
    let slot_probability: (u64, u64) = Decode::decode(&mut slot_probability_value.as_slice())
        .map_err(|_| ReadBundleElectionParamsError::DecodeError)?;

    Ok(BundleElectionParams {
        authorities,
        total_stake_weight,
        slot_probability,
    })
}

#[derive(Debug)]
pub enum BundleSolutionError {
    /// Can not retrieve the state needed from the storage proof.
    BadStorageProof(ReadBundleElectionParamsError),
    /// Bundle author is not found in the authority set.
    AuthorityNotFound,
    /// Failed to derive the bundle election solution.
    FailedToDeriveBundleElectionSolution(SignatureError),
    /// Election solution does not satisfy the threshold.
    InvalidElectionSolution,
}

pub fn verify_system_bundle_solution<SecondaryHash>(
    proof_of_election: &ProofOfElection<SecondaryHash>,
    verified_state_root: H256,
) -> Result<(), BundleSolutionError> {
    let ProofOfElection {
        domain_id,
        vrf_output,
        executor_public_key,
        global_challenge,
        storage_proof,
        ..
    } = proof_of_election;

    let BundleElectionParams {
        authorities,
        total_stake_weight,
        slot_probability,
    } = read_bundle_election_params(storage_proof.clone(), &verified_state_root)
        .map_err(BundleSolutionError::BadStorageProof)?;

    let stake_weight = authorities
        .iter()
        .find_map(|(authority, weight)| {
            if authority == executor_public_key {
                Some(weight)
            } else {
                None
            }
        })
        .ok_or(BundleSolutionError::AuthorityNotFound)?;

    let election_solution = derive_bundle_election_solution(
        *domain_id,
        *vrf_output,
        executor_public_key,
        global_challenge,
    )
    .map_err(BundleSolutionError::FailedToDeriveBundleElectionSolution)?;

    let threshold =
        calculate_bundle_election_threshold(*stake_weight, total_stake_weight, slot_probability);

    if !is_election_solution_within_threshold(election_solution, threshold) {
        return Err(BundleSolutionError::InvalidElectionSolution);
    }

    Ok(())
}
