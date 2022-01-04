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
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT};
use sp_runtime::{OpaqueExtrinsic, RuntimeDebug};
use sp_std::vec::Vec;
use sp_trie::StorageProof;
use subspace_core_primitives::Randomness;
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
    /// Secondary block hash?
    pub secondary_hash: Hash,
    /// State root after finishing the execution.
    pub state_root: Hash,
    /// Merkle root of the execution.
    pub state_transition_root: Hash,
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

/// Fraud proof for the state computation.
#[derive(Decode, Encode, TypeInfo, PartialEq, Eq, Clone, RuntimeDebug)]
pub struct FraudProof {
    /// Proof recorded during the computation.
    pub proof: StorageProof,
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
        /// Submits the candidate receipt via an unsigned extrinsic.
        fn submit_candidate_receipt_unsigned(
            head_number: <<Block as BlockT>::Header as HeaderT>::Number,
            head_hash: <Block as BlockT>::Hash,
        ) -> Option<()>;

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

        /// Returns the block hash given the block number.
        fn head_hash(
            number: <<Block as BlockT>::Header as HeaderT>::Number,
        ) -> Option<<Block as BlockT>::Hash>;

        /// Returns the latest block hash of executor chain.
        fn pending_head() -> Option<<Block as BlockT>::Hash>;
    }
}
