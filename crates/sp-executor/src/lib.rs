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

use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_consensus_slots::Slot;
use sp_core::H256;
use sp_runtime::traits::{BlakeTwo256, Hash as HashT, Header as HeaderT};
use sp_runtime::{OpaqueExtrinsic, RuntimeDebug};
use sp_runtime_interface::pass_by::PassBy;
use sp_std::borrow::Cow;
use sp_std::vec::Vec;
use sp_trie::StorageProof;
use subspace_core_primitives::{Randomness, Sha256Hash};
use subspace_runtime_primitives::AccountId;

/// Header of transaction bundle.
#[derive(Decode, Encode, TypeInfo, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct BundleHeader {
    /// The slot number.
    pub slot_number: u64,
    /// The merkle root of the extrinsics.
    pub extrinsics_root: H256,
}

impl BundleHeader {
    /// Returns the hash of this header.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

/// Transaction bundle
#[derive(Decode, Encode, TypeInfo, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct Bundle<Extrinsic> {
    /// The bundle header.
    pub header: BundleHeader,
    /// The accompanying extrinsics.
    pub extrinsics: Vec<Extrinsic>,
}

impl<Extrinsic> Bundle<Extrinsic> {
    /// Returns the hash of this bundle.
    pub fn hash(&self) -> H256 {
        self.header.hash()
    }
}

/// Bundle with opaque extrinsics.
#[derive(Decode, Encode, TypeInfo, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct OpaqueBundle {
    /// The bundle header.
    pub header: BundleHeader,
    /// THe accompanying opaque extrinsics.
    pub opaque_extrinsics: Vec<OpaqueExtrinsic>,
}

impl OpaqueBundle {
    /// Returns the hash of this bundle.
    pub fn hash(&self) -> H256 {
        self.header.hash()
    }
}

impl<Extrinsic: sp_runtime::traits::Extrinsic + Encode> From<Bundle<Extrinsic>> for OpaqueBundle {
    fn from(bundle: Bundle<Extrinsic>) -> Self {
        let Bundle { header, extrinsics } = bundle;
        let opaque_extrinsics = extrinsics
            .into_iter()
            .map(|xt| {
                OpaqueExtrinsic::from_bytes(&xt.encode())
                    .expect("We have just encoded a valid extrinsic; qed")
            })
            .collect();
        Self {
            header,
            opaque_extrinsics,
        }
    }
}

/// Receipt of state execution.
#[derive(Decode, Encode, TypeInfo, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct ExecutionReceipt<Hash> {
    /// Primary block hash.
    pub primary_hash: H256,
    /// Secondary block hash.
    pub secondary_hash: Hash,
    /// List of storage roots collected during the block execution.
    pub trace: Vec<Hash>,
    /// The merkle root of `trace`.
    pub trace_root: Sha256Hash,
}

impl<Hash: Encode> ExecutionReceipt<Hash> {
    /// Returns the hash of this execution receipt.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

// TODO: this might be unneccessary, ideally we could interact with the runtime using `ExecutionReceipt` directly.
// Refer to the comment https://github.com/subspace/subspace/pull/219#discussion_r776749767
#[derive(Decode, Encode, TypeInfo, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct OpaqueExecutionReceipt(Vec<u8>);

impl<Hash: Encode> From<ExecutionReceipt<Hash>> for OpaqueExecutionReceipt {
    fn from(inner: ExecutionReceipt<Hash>) -> Self {
        Self(inner.encode())
    }
}

/// Execution phase along with an optional encoded call data.
///
/// Each execution phase has a different method for the runtime call.
#[derive(Decode, Encode, TypeInfo, PartialEq, Eq, Clone, RuntimeDebug)]
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
#[derive(RuntimeDebug)]
pub enum VerificationError {
    /// Failed to pass the execution proof check.
    BadProof(sp_std::boxed::Box<dyn sp_state_machine::Error>),
    /// The `post_state_root` calculated by farmer does not match the one declared in [`FraudProof`].
    BadPostStateRoot { expected: H256, got: H256 },
    /// Failed to decode the return value of `initialize_block` and `apply_extrinsic`.
    InitializeBlockOrApplyExtrinsicDecode(parity_scale_codec::Error),
    /// Failed to decode the storage root produced by verifying `initialize_block` or `apply_extrinsic`.
    StorageRootDecode(parity_scale_codec::Error),
    /// Failed to decode the header produced by `finalize_block`.
    HeaderDecode(parity_scale_codec::Error),
}

/// Fraud proof for the state computation.
#[derive(Decode, Encode, TypeInfo, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct FraudProof {
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

impl PassBy for FraudProof {
    type PassBy = sp_runtime_interface::pass_by::Codec<Self>;
}

/// Represents a bundle equivocation proof. An equivocation happens when an executor
/// produces more than one bundle on the same slot. The proof of equivocation
/// are the given distinct bundle headers that were signed by the validator and which
/// include the slot number.
#[derive(Clone, Debug, Decode, Encode, PartialEq, TypeInfo)]
pub struct BundleEquivocationProof {
    /// The authority id of the equivocator.
    pub offender: AccountId,
    /// The slot at which the equivocation happened.
    pub slot: Slot,
    /// The first header involved in the equivocation.
    pub first_header: BundleHeader,
    /// The second header involved in the equivocation.
    pub second_header: BundleHeader,
}

impl BundleEquivocationProof {
    /// Returns the hash of this bundle equivocation proof.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }

    // TODO: remove this later.
    /// Constructs a dummy bundle equivocation proof.
    pub fn dummy_at(slot_number: u64) -> Self {
        let dummy_header = BundleHeader {
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
#[derive(Clone, Debug, Decode, Encode, PartialEq, TypeInfo)]
pub struct InvalidTransactionProof;

sp_api::decl_runtime_apis! {
    /// API necessary for executor pallet.
    pub trait ExecutorApi {
        /// Submits the execution receipt via an unsigned extrinsic.
        fn submit_execution_receipt_unsigned(
            opaque_execution_receipt: OpaqueExecutionReceipt,
        ) -> Option<()>;

        /// Submits the transaction bundle via an unsigned extrinsic.
        fn submit_transaction_bundle_unsigned(opaque_bundle: OpaqueBundle) -> Option<()>;

        /// Submits the fraud proof via an unsigned extrinsic.
        fn submit_fraud_proof_unsigned(fraud_proof: FraudProof) -> Option<()>;

        /// Submits the bundle equivocation proof via an unsigned extrinsic.
        fn submit_bundle_equivocation_proof_unsigned(
            bundle_equivocation_proof: BundleEquivocationProof,
        ) -> Option<()>;

        /// Submits the invalid transaction proof via an unsigned extrinsic.
        fn submit_invalid_transaction_proof_unsigned(
            invalid_transaction_proof: InvalidTransactionProof,
        ) -> Option<()>;

        /// Extract the bundles from extrinsics in a block.
        fn extract_bundles(extrinsics: Vec<OpaqueExtrinsic>) -> Vec<OpaqueBundle>;

        /// Generates a randomness seed for extrinsics shuffling.
        fn extrinsics_shuffling_seed(header: Block::Header) -> Randomness;

        /// WASM bundle for execution runtime.
        fn execution_wasm_bundle() -> Cow<'static, [u8]>;
    }
}

// TODO: remove once the fraud proof verification is moved into the client.
pub mod fraud_proof_ext {
    use sp_externalities::ExternalitiesExt;
    use sp_runtime_interface::runtime_interface;

    /// Externalities for verifying fraud proof.
    pub trait Externalities: Send {
        /// Returns `true` when the proof is valid.
        fn verify_fraud_proof(&self, proof: &crate::FraudProof) -> bool;
    }

    #[cfg(feature = "std")]
    sp_externalities::decl_extension! {
        /// An extension to verify the fraud proof.
        pub struct FraudProofExt(Box<dyn Externalities>);
    }

    #[cfg(feature = "std")]
    impl FraudProofExt {
        pub fn new<E: Externalities + 'static>(fraud_proof: E) -> Self {
            Self(Box::new(fraud_proof))
        }
    }

    #[runtime_interface]
    pub trait FraudProof {
        /// Verify fraud proof.
        fn verify(&mut self, proof: &crate::FraudProof) -> bool {
            self.extension::<FraudProofExt>()
                .expect("No `FraudProof` associated for the current context!")
                .verify_fraud_proof(proof)
        }
    }
}
