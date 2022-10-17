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

//! Primitives for executor pallet.

#![cfg_attr(not(feature = "std"), no_std)]

use crate::well_known_keys::{AUTHORITIES, SLOT_PROBABILITY, TOTAL_STAKE_WEIGHT};
use merlin::Transcript;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use schnorrkel::vrf::{VRFOutput, VRFProof};
use sp_consensus_slots::Slot;
use sp_core::crypto::KeyTypeId;
use sp_core::H256;
#[cfg(feature = "std")]
use sp_keystore::vrf::{VRFTranscriptData, VRFTranscriptValue};
use sp_runtime::traits::{BlakeTwo256, Hash as HashT, Header as HeaderT, NumberFor};
use sp_runtime::transaction_validity::{InvalidTransaction, TransactionValidity};
use sp_runtime::OpaqueExtrinsic;
use sp_std::borrow::Cow;
use sp_std::vec;
use sp_std::vec::Vec;
use sp_trie::{read_trie_value, LayoutV1, StorageProof};
use subspace_core_primitives::crypto::blake2b_256_hash_list;
use subspace_core_primitives::{Blake2b256Hash, BlockNumber, Randomness};
use subspace_runtime_primitives::AccountId;

const VRF_TRANSCRIPT_LABEL: &[u8] = b"executor";

/// Key type for Executor.
const KEY_TYPE: KeyTypeId = KeyTypeId(*b"exec");

mod app {
    use super::KEY_TYPE;
    use sp_application_crypto::{app_crypto, sr25519};

    app_crypto!(sr25519, KEY_TYPE);
}

/// An executor authority signature.
pub type ExecutorSignature = app::Signature;

/// An executor authority keypair. Necessarily equivalent to the schnorrkel public key used in
/// the main executor module. If that ever changes, then this must, too.
#[cfg(feature = "std")]
pub type ExecutorPair = app::Pair;

/// An executor authority identifier.
pub type ExecutorId = app::Public;

/// A type that implements `BoundToRuntimeAppPublic`, used for executor signing key.
pub struct ExecutorKey;

impl sp_runtime::BoundToRuntimeAppPublic for ExecutorKey {
    type Public = ExecutorId;
}

/// Stake weight in the bundle election.
pub type StakeWeight = u128;

/// Unique identifier for each domain.
// TODO: unify the DomainId usage across the codebase.
pub type DomainId = u64;

/// Custom invalid validity code for the extrinsics in pallet-executor.
#[repr(u8)]
pub enum InvalidTransactionCode {
    BundleEquivicationProof = 101,
    TrasactionProof = 102,
    ExecutionReceipt = 103,
    Bundle = 104,
    FraudProof = 105,
}

impl From<InvalidTransactionCode> for InvalidTransaction {
    fn from(invalid_code: InvalidTransactionCode) -> Self {
        InvalidTransaction::Custom(invalid_code as u8)
    }
}

impl From<InvalidTransactionCode> for TransactionValidity {
    fn from(invalid_code: InvalidTransactionCode) -> Self {
        InvalidTransaction::Custom(invalid_code as u8).into()
    }
}

/// Header of transaction bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleHeader<Hash> {
    /// The hash of primary block at which the bundle was created.
    pub primary_hash: Hash,
    /// The slot number.
    pub slot_number: u64,
    /// The merkle root of the extrinsics.
    pub extrinsics_root: H256,
}

impl<Hash: Encode> BundleHeader<Hash> {
    /// Returns the hash of this header.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

// TODO: unify the type between the solution and threshold better.
pub fn derive_bundle_election_solution(domain_id: DomainId, vrf_output: &[u8]) -> u64 {
    let local_domain_randomness = blake2b_256_hash_list(&[&domain_id.to_le_bytes(), vrf_output]);

    let election_solution = u64::from_le_bytes(
        local_domain_randomness
            .split_at(core::mem::size_of::<u64>())
            .0
            .try_into()
            .expect("Local domain randomness must fit into u64; qed"),
    );

    election_solution
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
    u128::MAX / total_stake_weight * u128::from(slot_probability.0) / u128::from(slot_probability.1)
        * stake_weight
}

pub fn is_election_solution_within_threshold(election_solution: u128, threshold: u128) -> bool {
    election_solution <= threshold
}

/// Make a VRF transcript.
pub fn make_local_randomness_transcript(slot_randomness: &Blake2b256Hash) -> Transcript {
    let mut transcript = Transcript::new(VRF_TRANSCRIPT_LABEL);
    transcript.append_message(b"slot randomness", slot_randomness);
    transcript
}

/// Make a VRF transcript data.
#[cfg(feature = "std")]
pub fn make_local_randomness_transcript_data(
    slot_randomness: &Blake2b256Hash,
) -> VRFTranscriptData {
    VRFTranscriptData {
        label: VRF_TRANSCRIPT_LABEL,
        items: vec![(
            "slot randomness",
            VRFTranscriptValue::Bytes(slot_randomness.to_vec()),
        )],
    }
}

pub mod well_known_keys {
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

    pub fn bundle_election_storage_keys() -> Vec<[u8; 32]> {
        vec![AUTHORITIES, TOTAL_STAKE_WEIGHT, SLOT_PROBABILITY]
    }
}

/// Parameters for the bundle election.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleElectionParams {
    pub authorities: Vec<(ExecutorId, StakeWeight)>,
    pub total_stake_weight: StakeWeight,
    pub slot_probability: (u64, u64),
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
    public_key: &[u8],
    vrf_output: &[u8],
    vrf_proof: &[u8],
    slot_randomness: &Blake2b256Hash,
) -> Result<(), VrfProofError> {
    let public_key = schnorrkel::PublicKey::from_bytes(public_key)
        .map_err(|_| VrfProofError::VrfSignatureConstructionError)?;

    public_key
        .vrf_verify(
            make_local_randomness_transcript(slot_randomness),
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
        read_trie_value::<LayoutV1<BlakeTwo256>, _>(&db, state_root, storage_key)
            .map_err(|_| ReadBundleElectionParamsError::TrieError)
    };

    let authorities =
        read_value(&AUTHORITIES)?.ok_or(ReadBundleElectionParamsError::MissingValue)?;
    let authorities: Vec<(ExecutorId, StakeWeight)> =
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

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct ProofOfElection {
    /// Domain id.
    pub domain_id: DomainId,
    /// VRF output.
    pub vrf_output: Vec<u8>,
    /// VRF proof.
    pub vrf_proof: Vec<u8>,
    /// VRF public key.
    pub vrf_public_key: Vec<u8>,
    /// Slot randomness.
    pub slot_randomness: Blake2b256Hash,
    /// State root corresponding to the storage proof above.
    pub state_root: H256,
    /// Storage proof for the bundle election state.
    pub storage_proof: StorageProof,
}

impl ProofOfElection {
    pub fn dummy() -> Self {
        Self {
            domain_id: DomainId::default(),
            vrf_output: Vec::new(),
            vrf_proof: Vec::new(),
            vrf_public_key: Vec::new(),
            slot_randomness: Blake2b256Hash::default(),
            state_root: H256::default(),
            storage_proof: StorageProof::empty(),
        }
    }
}

/// Transaction bundle
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct Bundle<Extrinsic, Number, Hash, SecondaryHash> {
    /// The bundle header.
    pub header: BundleHeader<Hash>,
    /// Expected receipts by the primay chain when the bundle was created.
    pub receipts: Vec<ExecutionReceipt<Number, Hash, SecondaryHash>>,
    /// The accompanying extrinsics.
    pub extrinsics: Vec<Extrinsic>,
}

impl<Extrinsic, Number, Hash: Encode, SecondaryHash>
    Bundle<Extrinsic, Number, Hash, SecondaryHash>
{
    /// Returns the hash of this bundle.
    pub fn hash(&self) -> H256 {
        self.header.hash()
    }
}

/// Bundle with opaque extrinsics.
pub type OpaqueBundle<Number, Hash, SecondaryHash> =
    Bundle<OpaqueExtrinsic, Number, Hash, SecondaryHash>;

impl<Extrinsic: Encode, Number, Hash, SecondaryHash>
    Bundle<Extrinsic, Number, Hash, SecondaryHash>
{
    /// Convert a bundle with generic extrinsic to a bundle with opaque extrinsic.
    pub fn into_opaque_bundle(self) -> OpaqueBundle<Number, Hash, SecondaryHash> {
        let Bundle {
            header,
            receipts,
            extrinsics,
        } = self;
        let opaque_extrinsics = extrinsics
            .into_iter()
            .map(|xt| {
                OpaqueExtrinsic::from_bytes(&xt.encode())
                    .expect("We have just encoded a valid extrinsic; qed")
            })
            .collect();
        OpaqueBundle {
            header,
            receipts,
            extrinsics: opaque_extrinsics,
        }
    }
}

/// Signed version of [`Bundle`].
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct SignedBundle<Extrinsic, Number, Hash, SecondaryHash> {
    /// The bundle header.
    pub bundle: Bundle<Extrinsic, Number, Hash, SecondaryHash>,
    /// Proof of bundle election.
    pub proof_of_election: ProofOfElection,
    /// Signature of the bundle.
    pub signature: ExecutorSignature,
    /// Signer of the signature.
    pub signer: ExecutorId,
}

/// [`SignedBundle`] with opaque extrinsic.
pub type SignedOpaqueBundle<Number, Hash, SecondaryHash> =
    SignedBundle<OpaqueExtrinsic, Number, Hash, SecondaryHash>;

impl<Extrinsic: Encode, Number: Encode, Hash: Encode, SecondaryHash: Encode>
    SignedBundle<Extrinsic, Number, Hash, SecondaryHash>
{
    /// Returns the hash of signed bundle.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

impl<Extrinsic: Encode, Number, Hash, SecondaryHash>
    SignedBundle<Extrinsic, Number, Hash, SecondaryHash>
{
    /// Convert a signed bundle with generic extrinsic to a signed bundle with opaque extrinsic.
    pub fn into_signed_opaque_bundle(self) -> SignedOpaqueBundle<Number, Hash, SecondaryHash> {
        SignedOpaqueBundle {
            bundle: self.bundle.into_opaque_bundle(),
            proof_of_election: self.proof_of_election,
            signature: self.signature,
            signer: self.signer,
        }
    }
}

/// Receipt of state execution.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct ExecutionReceipt<Number, Hash, SecondaryHash> {
    /// Primary block number.
    pub primary_number: Number,
    /// Primary block hash.
    pub primary_hash: Hash,
    /// Secondary block hash.
    pub secondary_hash: SecondaryHash,
    /// List of storage roots collected during the block execution.
    pub trace: Vec<SecondaryHash>,
    /// The merkle root of `trace`.
    pub trace_root: Blake2b256Hash,
}

impl<Number: Encode, Hash: Encode, SecondaryHash: Encode>
    ExecutionReceipt<Number, Hash, SecondaryHash>
{
    /// Returns the hash of this execution receipt.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

// TODO: Remove this when the bundle gossip is disabled.
/// Signed version of [`ExecutionReceipt`] which will be gossiped over the executors network.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct SignedExecutionReceipt<Number, Hash, SecondaryHash> {
    /// Execution receipt
    pub execution_receipt: ExecutionReceipt<Number, Hash, SecondaryHash>,
    /// Signature of the execution receipt.
    pub signature: ExecutorSignature,
    /// Signer of the signature.
    pub signer: ExecutorId,
}

impl<Number: Encode, Hash: Encode, SecondaryHash: Encode>
    SignedExecutionReceipt<Number, Hash, SecondaryHash>
{
    /// Returns the hash of signed execution receipt.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

/// Execution phase along with an optional encoded call data.
///
/// Each execution phase has a different method for the runtime call.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum ExecutionPhase {
    /// Executes the `initialize_block` hook.
    InitializeBlock { call_data: Vec<u8> },
    /// Executes some extrinsic.
    /// TODO: maybe optimized to not include the whole extrinsic blob in the future.
    ApplyExtrinsic { call_data: Vec<u8> },
    /// Executes the `finalize_block` hook.
    FinalizeBlock,
}

impl ExecutionPhase {
    /// Returns the method for generating the proof.
    pub fn proving_method(&self) -> &'static str {
        match self {
            // TODO: Replace `SecondaryApi_initialize_block_with_post_state_root` with `Core_initalize_block`
            // Should be a same issue with https://github.com/paritytech/substrate/pull/10922#issuecomment-1068997467
            Self::InitializeBlock { .. } => "SecondaryApi_initialize_block_with_post_state_root",
            Self::ApplyExtrinsic { .. } => "BlockBuilder_apply_extrinsic",
            Self::FinalizeBlock => "BlockBuilder_finalize_block",
        }
    }

    /// Returns the method for verifying the proof.
    ///
    /// The difference with [`Self::proving_method`] is that the return value of verifying method
    /// must contain the post state root info so that it can be used to compare whether the
    /// result of execution reported in [`FraudProof`] is expected or not.
    pub fn verifying_method(&self) -> &'static str {
        match self {
            Self::InitializeBlock { .. } => "SecondaryApi_initialize_block_with_post_state_root",
            Self::ApplyExtrinsic { .. } => "SecondaryApi_apply_extrinsic_with_post_state_root",
            Self::FinalizeBlock => "BlockBuilder_finalize_block",
        }
    }

    /// Returns the call data used to generate and verify the proof.
    pub fn call_data(&self) -> &[u8] {
        match self {
            Self::InitializeBlock { call_data } | Self::ApplyExtrinsic { call_data } => call_data,
            Self::FinalizeBlock => Default::default(),
        }
    }

    /// Returns the post state root for the given execution result.
    pub fn decode_execution_result<Header: HeaderT>(
        &self,
        execution_result: Vec<u8>,
    ) -> Result<Header::Hash, VerificationError> {
        match self {
            ExecutionPhase::InitializeBlock { .. } | ExecutionPhase::ApplyExtrinsic { .. } => {
                let encoded_storage_root = Vec::<u8>::decode(&mut execution_result.as_slice())
                    .map_err(VerificationError::InitializeBlockOrApplyExtrinsicDecode)?;
                Header::Hash::decode(&mut encoded_storage_root.as_slice())
                    .map_err(VerificationError::StorageRootDecode)
            }
            ExecutionPhase::FinalizeBlock => {
                let new_header = Header::decode(&mut execution_result.as_slice())
                    .map_err(VerificationError::HeaderDecode)?;
                Ok(*new_header.state_root())
            }
        }
    }
}

/// Error type of fraud proof verification on primary node.
#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum VerificationError {
    /// Failed to pass the execution proof check.
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to pass the execution proof check")
    )]
    BadProof(sp_std::boxed::Box<dyn sp_state_machine::Error>),
    /// The `post_state_root` calculated by farmer does not match the one declared in [`FraudProof`].
    #[cfg_attr(
        feature = "thiserror",
        error("`post_state_root` mismatches, expected: {expected}, got: {got}")
    )]
    BadPostStateRoot { expected: H256, got: H256 },
    /// Failed to decode the return value of `initialize_block` and `apply_extrinsic`.
    #[cfg_attr(
        feature = "thiserror",
        error(
            "Failed to decode the return value of `initialize_block` and `apply_extrinsic`: {0}"
        )
    )]
    InitializeBlockOrApplyExtrinsicDecode(parity_scale_codec::Error),
    /// Failed to decode the storage root produced by verifying `initialize_block` or `apply_extrinsic`.
    #[cfg_attr(
        feature = "thiserror",
        error(
            "Failed to decode the storage root from verifying `initialize_block` and `apply_extrinsic`: {0}"
        )
    )]
    StorageRootDecode(parity_scale_codec::Error),
    /// Failed to decode the header produced by `finalize_block`.
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to decode the header from verifying `finalize_block`: {0}")
    )]
    HeaderDecode(parity_scale_codec::Error),
    /// Runtime api error.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "thiserror", error("Runtime api error: {0}"))]
    RuntimeApi(#[from] sp_api::ApiError),
}

/// Fraud proof for the state computation.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct FraudProof {
    /// Hash of the signed bundle in which an invalid state transition occurred.
    pub bad_signed_bundle_hash: H256,
    /// Parent number.
    pub parent_number: BlockNumber,
    /// Parent hash of the block at which the invalid execution occurred.
    ///
    /// Runtime code for this block's execution is retrieved on top of the parent block.
    pub parent_hash: H256,
    /// State root before the fraudulent transaction.
    pub pre_state_root: H256,
    /// State root after the fraudulent transaction.
    pub post_state_root: H256,
    /// Proof recorded during the computation.
    pub proof: StorageProof,
    /// Execution phase.
    pub execution_phase: ExecutionPhase,
}

/// Represents a bundle equivocation proof. An equivocation happens when an executor
/// produces more than one bundle on the same slot. The proof of equivocation
/// are the given distinct bundle headers that were signed by the validator and which
/// include the slot number.
#[derive(Clone, Debug, Decode, Encode, PartialEq, TypeInfo)]
pub struct BundleEquivocationProof<Hash> {
    /// The authority id of the equivocator.
    pub offender: AccountId,
    /// The slot at which the equivocation happened.
    pub slot: Slot,
    /// The first header involved in the equivocation.
    pub first_header: BundleHeader<Hash>,
    /// The second header involved in the equivocation.
    pub second_header: BundleHeader<Hash>,
}

impl<Hash: Clone + Default + Encode> BundleEquivocationProof<Hash> {
    /// Returns the hash of this bundle equivocation proof.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }

    // TODO: remove this later.
    /// Constructs a dummy bundle equivocation proof.
    pub fn dummy_at(slot_number: u64) -> Self {
        let dummy_header = BundleHeader {
            primary_hash: Hash::default(),
            slot_number,
            extrinsics_root: H256::default(),
        };
        Self {
            offender: AccountId::decode(&mut sp_runtime::traits::TrailingZeroInput::zeroes())
                .expect("Failed to create zero account"),
            slot: Slot::default(),
            first_header: dummy_header.clone(),
            second_header: dummy_header,
        }
    }
}

/// Represents an invalid transaction proof.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidTransactionProof;

sp_api::decl_runtime_apis! {
    /// API necessary for executor pallet.
    pub trait ExecutorApi<SecondaryHash: Encode + Decode> {
        /// Submits the transaction bundle via an unsigned extrinsic.
        fn submit_transaction_bundle_unsigned(opaque_bundle: SignedOpaqueBundle<NumberFor<Block>, Block::Hash, SecondaryHash>);

        /// Submits the fraud proof via an unsigned extrinsic.
        fn submit_fraud_proof_unsigned(fraud_proof: FraudProof);

        /// Submits the bundle equivocation proof via an unsigned extrinsic.
        fn submit_bundle_equivocation_proof_unsigned(
            bundle_equivocation_proof: BundleEquivocationProof<Block::Hash>,
        );

        /// Submits the invalid transaction proof via an unsigned extrinsic.
        fn submit_invalid_transaction_proof_unsigned(
            invalid_transaction_proof: InvalidTransactionProof,
        );

        /// Extract the bundles from the given extrinsics.
        fn extract_bundles(extrinsics: Vec<Block::Extrinsic>) -> Vec<OpaqueBundle<NumberFor<Block>, Block::Hash, SecondaryHash>>;

        /// Extract the receipts from the given extrinsics.
        fn extract_receipts(
            extrinsics: Vec<Block::Extrinsic>,
        ) -> Vec<ExecutionReceipt<NumberFor<Block>, Block::Hash, SecondaryHash>>;

        /// Extract the fraud proofs from the given extrinsics.
        fn extract_fraud_proofs(extrinsics: Vec<Block::Extrinsic>) -> Vec<FraudProof>;

        /// Generates a randomness seed for extrinsics shuffling.
        fn extrinsics_shuffling_seed(header: Block::Header) -> Randomness;

        /// WASM bundle for execution runtime.
        fn execution_wasm_bundle() -> Cow<'static, [u8]>;

        /// Returns the authority id of current executor.
        fn executor_id() -> ExecutorId;

        /// Returns the best execution chain number.
        fn best_execution_chain_number() -> NumberFor<Block>;

        /// Returns the block number of oldest execution receipt.
        fn oldest_receipt_number() -> NumberFor<Block>;

        /// Returns the maximum receipt drift.
        fn maximum_receipt_drift() -> NumberFor<Block>;
    }
}
