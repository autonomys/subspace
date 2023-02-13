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

pub mod bundle_election;
pub mod fraud_proof;
pub mod transaction;

use crate::fraud_proof::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use schnorrkel::vrf::{VRF_OUTPUT_LENGTH, VRF_PROOF_LENGTH};
use sp_core::crypto::KeyTypeId;
use sp_core::H256;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT, NumberFor};
use sp_runtime::OpaqueExtrinsic;
use sp_std::borrow::Cow;
use sp_std::vec::Vec;
use sp_trie::StorageProof;
use subspace_core_primitives::{Blake2b256Hash, BlockNumber, Randomness};

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
pub type ExecutorPublicKey = app::Public;

/// A type that implements `BoundToRuntimeAppPublic`, used for executor signing key.
pub struct ExecutorKey;

impl sp_runtime::BoundToRuntimeAppPublic for ExecutorKey {
    type Public = ExecutorPublicKey;
}

/// Stake weight in the domain bundle election.
///
/// Derived from the Balance and can't be smaller than u128.
pub type StakeWeight = u128;

/// Unique identifier of a domain.
#[derive(
    Clone, Copy, Debug, Hash, Default, Eq, PartialEq, Ord, PartialOrd, Encode, Decode, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct DomainId(u32);

impl From<u32> for DomainId {
    fn from(x: u32) -> Self {
        Self(x)
    }
}

impl From<DomainId> for u32 {
    fn from(domain_id: DomainId) -> Self {
        domain_id.0
    }
}

impl core::ops::Add<u32> for DomainId {
    type Output = Self;

    fn add(self, other: u32) -> Self {
        Self(self.0 + other)
    }
}

impl core::ops::Sub<u32> for DomainId {
    type Output = Self;

    fn sub(self, other: u32) -> Self {
        Self(self.0 - other)
    }
}

const OPEN_DOMAIN_ID_START: u32 = 100;

impl DomainId {
    pub const SYSTEM: Self = Self::new(0);

    pub const CORE_DOMAIN_ID_START: Self = Self::new(1);

    pub const CORE_PAYMENTS: Self = Self::new(1);

    /// Creates a [`DomainId`].
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns `true` if a domain is a system domain.
    pub fn is_system(&self) -> bool {
        self.0 == Self::SYSTEM.0
    }

    /// Returns `true` if a domain is a core domain.
    pub fn is_core(&self) -> bool {
        self.0 >= Self::CORE_DOMAIN_ID_START.0 && self.0 < OPEN_DOMAIN_ID_START
    }

    /// Returns `true` if a domain is an open domain.
    pub fn is_open(&self) -> bool {
        self.0 >= OPEN_DOMAIN_ID_START
    }

    /// Converts the inner integer to little-endian bytes.
    pub fn to_le_bytes(&self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    /// Returns the section name when a core domain wasm blob is embedded into the system domain
    /// runtime via the `link_section` attribute.
    #[cfg(feature = "std")]
    pub fn link_section_name(&self) -> String {
        format!("runtime_blob_{}", self.0)
    }
}

/// Domain configuration.
#[derive(Debug, Encode, Decode, TypeInfo, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct DomainConfig<Hash, Balance, Weight> {
    /// Hash of the domain wasm runtime blob.
    pub wasm_runtime_hash: Hash,

    // May be supported later.
    //pub upgrade_keys: Vec<AccountId>,
    /// Slot probability
    pub bundle_slot_probability: (u64, u64),

    /// Maximum domain bundle size in bytes.
    pub max_bundle_size: u32,

    /// Maximum domain bundle weight.
    pub max_bundle_weight: Weight,

    /// Minimum executor stake value to be an operator on this domain.
    pub min_operator_stake: Balance,
}

/// Header of bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleHeader<Number, Hash> {
    /// The block number of primary block at which the bundle was created.
    pub primary_number: Number,
    /// The hash of primary block at which the bundle was created.
    pub primary_hash: Hash,
    /// The slot number.
    pub slot_number: u64,
    /// The merkle root of the extrinsics.
    pub extrinsics_root: H256,
}

impl<Number: Encode, Hash: Encode> BundleHeader<Number, Hash> {
    /// Returns the hash of this header.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct ProofOfElection<DomainHash> {
    /// Domain id.
    pub domain_id: DomainId,
    /// VRF output.
    pub vrf_output: [u8; VRF_OUTPUT_LENGTH],
    /// VRF proof.
    pub vrf_proof: [u8; VRF_PROOF_LENGTH],
    /// VRF public key.
    pub executor_public_key: ExecutorPublicKey,
    /// Global challenge.
    pub global_challenge: Blake2b256Hash,
    /// State root corresponding to the storage proof above.
    pub state_root: DomainHash,
    /// Storage proof for the bundle election state.
    pub storage_proof: StorageProof,
    /// Number of the system domain block at which the proof of election was created.
    pub block_number: BlockNumber,
    /// Block hash corresponding to the `block_number` above.
    pub block_hash: DomainHash,
}

impl<DomainHash: Default> ProofOfElection<DomainHash> {
    #[cfg(feature = "std")]
    pub fn dummy(domain_id: DomainId, executor_public_key: ExecutorPublicKey) -> Self {
        Self {
            domain_id,
            vrf_output: [0u8; VRF_OUTPUT_LENGTH],
            vrf_proof: [0u8; VRF_PROOF_LENGTH],
            executor_public_key,
            global_challenge: Blake2b256Hash::default(),
            state_root: Default::default(),
            storage_proof: StorageProof::empty(),
            block_number: Default::default(),
            block_hash: Default::default(),
        }
    }
}

/// Domain bundle election solution.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum BundleSolution<DomainHash> {
    /// System domain bundle election.
    System(ProofOfElection<DomainHash>),
    /// Core domain bundle election.
    Core {
        /// Proof of election.
        proof_of_election: ProofOfElection<DomainHash>,
        /// Number of the core domain block at which the proof of election was created.
        core_block_number: BlockNumber,
        /// Block hash corresponding to the `core_block_number` above.
        core_block_hash: DomainHash,
        /// Core domain state root corresponding to the `core_block_hash` above.
        core_state_root: DomainHash,
    },
}

impl<DomainHash> BundleSolution<DomainHash> {
    pub fn proof_of_election(&self) -> &ProofOfElection<DomainHash> {
        match self {
            Self::System(proof_of_election)
            | Self::Core {
                proof_of_election, ..
            } => proof_of_election,
        }
    }
}

/// Domain bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct Bundle<Extrinsic, Number, Hash, DomainHash> {
    /// The bundle header.
    pub header: BundleHeader<Number, Hash>,
    /// Expected receipts by the primay chain when the bundle was created.
    ///
    /// NOTE: It's fine to `Vec` instead of `BoundedVec` as each bundle is
    /// wrapped in an unsigned extrinsic, therefore the number of receipts
    /// in a bundle is inherently constrained by the max extrinsic size limit.
    pub receipts: Vec<ExecutionReceipt<Number, Hash, DomainHash>>,
    /// The accompanying extrinsics.
    pub extrinsics: Vec<Extrinsic>,
}

impl<Extrinsic: Encode, Number: Encode, Hash: Encode, DomainHash: Encode>
    Bundle<Extrinsic, Number, Hash, DomainHash>
{
    /// Returns the hash of this bundle.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

/// Bundle with opaque extrinsics.
pub type OpaqueBundle<Number, Hash, DomainHash> = Bundle<OpaqueExtrinsic, Number, Hash, DomainHash>;

impl<Extrinsic: Encode, Number, Hash, DomainHash> Bundle<Extrinsic, Number, Hash, DomainHash> {
    /// Convert a bundle with generic extrinsic to a bundle with opaque extrinsic.
    pub fn into_opaque_bundle(self) -> OpaqueBundle<Number, Hash, DomainHash> {
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
pub struct SignedBundle<Extrinsic, Number, Hash, DomainHash> {
    /// The bundle header.
    pub bundle: Bundle<Extrinsic, Number, Hash, DomainHash>,
    /// Solution of the bundle election.
    pub bundle_solution: BundleSolution<DomainHash>,
    /// Signature of the bundle.
    pub signature: ExecutorSignature,
}

/// [`SignedBundle`] with opaque extrinsic.
pub type SignedOpaqueBundle<Number, Hash, DomainHash> =
    SignedBundle<OpaqueExtrinsic, Number, Hash, DomainHash>;

impl<Extrinsic: Encode, Number: Encode, Hash: Encode, DomainHash: Encode>
    SignedBundle<Extrinsic, Number, Hash, DomainHash>
{
    /// Returns the hash of signed bundle.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }

    /// Returns the domain_id of this bundle.
    pub fn domain_id(&self) -> DomainId {
        self.bundle_solution.proof_of_election().domain_id
    }
}

impl<Extrinsic: Encode, Number, Hash, DomainHash>
    SignedBundle<Extrinsic, Number, Hash, DomainHash>
{
    /// Convert a signed bundle with generic extrinsic to a signed bundle with opaque extrinsic.
    pub fn into_signed_opaque_bundle(self) -> SignedOpaqueBundle<Number, Hash, DomainHash> {
        SignedOpaqueBundle {
            bundle: self.bundle.into_opaque_bundle(),
            bundle_solution: self.bundle_solution,
            signature: self.signature,
        }
    }
}

impl<Extrinsic, Number, Hash, DomainHash> SignedBundle<Extrinsic, Number, Hash, DomainHash> {
    /// Consumes [`SignedBundle`] to extract the inner executor public key.
    pub fn into_executor_public_key(self) -> ExecutorPublicKey {
        match self.bundle_solution {
            BundleSolution::System(proof_of_election)
            | BundleSolution::Core {
                proof_of_election, ..
            } => proof_of_election.executor_public_key,
        }
    }
}

/// Receipt of a domain block execution.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct ExecutionReceipt<Number, Hash, DomainHash> {
    /// Primary block number.
    pub primary_number: Number,
    /// Hash of the origin primary block this receipt corresponds to.
    pub primary_hash: Hash,
    /// Hash of the domain block this receipt points to.
    pub domain_hash: DomainHash,
    /// List of storage roots collected during the domain block execution.
    pub trace: Vec<DomainHash>,
    /// The merkle root of `trace`.
    pub trace_root: Blake2b256Hash,
}

impl<Number: Encode, Hash: Encode, DomainHash: Encode> ExecutionReceipt<Number, Hash, DomainHash> {
    /// Returns the hash of this execution receipt.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

/// List of [`OpaqueBundle`].
pub type OpaqueBundles<Block, DomainHash> =
    Vec<OpaqueBundle<NumberFor<Block>, <Block as BlockT>::Hash, DomainHash>>;

/// List of [`SignedOpaqueBundle`].
pub type SignedOpaqueBundles<Block, DomainHash> =
    Vec<SignedOpaqueBundle<NumberFor<Block>, <Block as BlockT>::Hash, DomainHash>>;

sp_api::decl_runtime_apis! {
    /// API necessary for executor pallet.
    pub trait ExecutorApi<DomainHash: Encode + Decode> {
        /// Submits the transaction bundle via an unsigned extrinsic.
        fn submit_bundle_unsigned(opaque_bundle: SignedOpaqueBundle<NumberFor<Block>, Block::Hash, DomainHash>);

        /// Submits the fraud proof via an unsigned extrinsic.
        fn submit_fraud_proof_unsigned(fraud_proof: FraudProof);

        /// Submits the bundle equivocation proof via an unsigned extrinsic.
        fn submit_bundle_equivocation_proof_unsigned(
            bundle_equivocation_proof: BundleEquivocationProof<NumberFor<Block>, Block::Hash>,
        );

        /// Submits the invalid transaction proof via an unsigned extrinsic.
        fn submit_invalid_transaction_proof_unsigned(
            invalid_transaction_proof: InvalidTransactionProof,
        );

        /// Extract the system bundles from the given extrinsics.
        fn extract_system_bundles(
            extrinsics: Vec<Block::Extrinsic>,
        ) -> (OpaqueBundles<Block, DomainHash>, SignedOpaqueBundles<Block, DomainHash>);

        /// Extract the core bundles from the given extrinsics.
        fn extract_core_bundles(
            extrinsics: Vec<Block::Extrinsic>,
            domain_id: DomainId,
        ) -> OpaqueBundles<Block, DomainHash>;

        /// Extract the receipts from the given extrinsics.
        fn extract_receipts(
            extrinsics: Vec<Block::Extrinsic>,
            domain_id: DomainId,
        ) -> Vec<ExecutionReceipt<NumberFor<Block>, Block::Hash, DomainHash>>;

        /// Extract the fraud proofs from the given extrinsics.
        fn extract_fraud_proofs(extrinsics: Vec<Block::Extrinsic>, domain_id: DomainId) -> Vec<FraudProof>;

        /// Generates a randomness seed for extrinsics shuffling.
        fn extrinsics_shuffling_seed(header: Block::Header) -> Randomness;

        /// WASM bundle for system domain runtime.
        fn system_domain_wasm_bundle() -> Cow<'static, [u8]>;

        /// Returns the best execution chain number.
        fn head_receipt_number() -> NumberFor<Block>;

        /// Returns the block number of oldest execution receipt.
        fn oldest_receipt_number() -> NumberFor<Block>;

        /// Returns the maximum receipt drift.
        fn maximum_receipt_drift() -> NumberFor<Block>;
    }
}
