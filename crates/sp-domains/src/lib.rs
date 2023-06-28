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
pub mod merkle_tree;
pub mod transaction;

use bundle_election::VrfProofError;
use merkle_tree::Witness;
#[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
use parity_scale_codec::MaxEncodedLen;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_api::RuntimeVersion;
use sp_core::crypto::KeyTypeId;
use sp_core::sr25519::vrf::{VrfOutput, VrfProof, VrfSignature};
use sp_core::H256;
use sp_runtime::generic::OpaqueDigestItemId;
use sp_runtime::traits::{
    BlakeTwo256, Block as BlockT, CheckedAdd, Hash as HashT, NumberFor, Zero,
};
use sp_runtime::{DigestItem, OpaqueExtrinsic, RuntimeAppPublic};
use sp_std::vec::Vec;
use sp_trie::StorageProof;
use subspace_core_primitives::crypto::blake2b_256_hash;
use subspace_core_primitives::{Blake2b256Hash, BlockNumber, Randomness, U256};
use subspace_runtime_primitives::Moment;

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
    Clone,
    Copy,
    Debug,
    Hash,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Encode,
    Decode,
    TypeInfo,
    Serialize,
    Deserialize,
)]
pub struct DomainId(u32);

impl From<u32> for DomainId {
    #[inline]
    fn from(x: u32) -> Self {
        Self(x)
    }
}

impl From<DomainId> for u32 {
    #[inline]
    fn from(domain_id: DomainId) -> Self {
        domain_id.0
    }
}

impl core::ops::Add<DomainId> for DomainId {
    type Output = Self;

    fn add(self, other: DomainId) -> Self {
        Self(self.0 + other.0)
    }
}

impl core::ops::Sub<DomainId> for DomainId {
    type Output = Self;

    fn sub(self, other: DomainId) -> Self {
        Self(self.0 - other.0)
    }
}

impl CheckedAdd for DomainId {
    fn checked_add(&self, rhs: &Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }
}

impl DomainId {
    /// Creates a [`DomainId`].
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Converts the inner integer to little-endian bytes.
    pub fn to_le_bytes(&self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

/// Domain configuration.
#[derive(Debug, Encode, Decode, TypeInfo, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

/// Unsealed header of bundle.
///
/// Domain operator needs to sign the hash of [`BundleHeader`] and uses the signature to
/// assemble the final [`SealedBundleHeader`].
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleHeader<Number, Hash, DomainHash> {
    /// The block number of primary block at which the bundle was created.
    pub primary_number: Number,
    /// The hash of primary block at which the bundle was created.
    pub primary_hash: Hash,
    /// The slot number.
    pub slot_number: u64,
    /// The merkle root of the extrinsics.
    pub extrinsics_root: H256,
    /// Solution of the bundle election.
    pub bundle_solution: BundleSolution<DomainHash>,
}

impl<Number: Encode, Hash: Encode, DomainHash: Encode> BundleHeader<Number, Hash, DomainHash> {
    /// Returns the hash of this header.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

/// Header of bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct SealedBundleHeader<Number, Hash, DomainHash> {
    /// Unsealed header.
    pub header: BundleHeader<Number, Hash, DomainHash>,
    /// Signature of the bundle.
    pub signature: ExecutorSignature,
}

impl<Number: Encode, Hash: Encode, DomainHash: Encode>
    SealedBundleHeader<Number, Hash, DomainHash>
{
    /// Constructs a new instance of [`SealedBundleHeader`].
    pub fn new(
        header: BundleHeader<Number, Hash, DomainHash>,
        signature: ExecutorSignature,
    ) -> Self {
        Self { header, signature }
    }

    /// Returns the hash of the inner unsealed header.
    pub fn pre_hash(&self) -> H256 {
        self.header.hash()
    }

    /// Returns the hash of this header.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }

    /// Returns whether the signature is valid.
    pub fn verify_signature(&self) -> bool {
        self.header
            .bundle_solution
            .proof_of_election()
            .executor_public_key
            .verify(&self.pre_hash(), &self.signature)
    }
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct ProofOfElection<DomainHash> {
    /// Domain id.
    pub domain_id: DomainId,
    /// VRF output.
    pub vrf_output: VrfOutput,
    /// VRF proof.
    pub vrf_proof: VrfProof,
    /// VRF public key.
    pub executor_public_key: ExecutorPublicKey,
    /// Global challenge.
    pub global_challenge: Blake2b256Hash,
    /// Storage proof containing the partial state for verifying the bundle election.
    pub storage_proof: StorageProof,
    /// State root corresponding to the storage proof above.
    pub system_state_root: DomainHash,
    /// Number of the system domain block at which the proof of election was created.
    pub system_block_number: BlockNumber,
    /// Block hash corresponding to the `block_number` above.
    pub system_block_hash: DomainHash,
}

impl<DomainHash> ProofOfElection<DomainHash> {
    pub fn verify_vrf_proof(&self) -> Result<(), VrfProofError> {
        bundle_election::verify_vrf_proof(
            &self.executor_public_key,
            // TODO: Maybe we want to store signature in the struct rather than separate fields,
            //  such that we don't need to clone here?
            &VrfSignature {
                output: self.vrf_output.clone(),
                proof: self.vrf_proof.clone(),
            },
            &self.global_challenge,
        )
    }

    /// Computes the VRF hash.
    pub fn vrf_hash(&self) -> Blake2b256Hash {
        let mut bytes = self.vrf_output.encode();
        bytes.append(&mut self.vrf_proof.encode());
        blake2b_256_hash(&bytes)
    }
}

impl<DomainHash: Default> ProofOfElection<DomainHash> {
    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy(domain_id: DomainId, executor_public_key: ExecutorPublicKey) -> Self {
        let output_bytes = vec![0u8; VrfOutput::max_encoded_len()];
        let proof_bytes = vec![0u8; VrfProof::max_encoded_len()];
        Self {
            domain_id,
            vrf_output: VrfOutput::decode(&mut output_bytes.as_slice()).unwrap(),
            vrf_proof: VrfProof::decode(&mut proof_bytes.as_slice()).unwrap(),
            executor_public_key,
            global_challenge: Blake2b256Hash::default(),
            storage_proof: StorageProof::empty(),
            system_state_root: Default::default(),
            system_block_number: Default::default(),
            system_block_hash: Default::default(),
        }
    }
}

/// Domain bundle election solution.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleSolution<DomainHash> {
    /// Authority's stake weight.
    authority_stake_weight: StakeWeight,
    /// Authority membership witness.
    authority_witness: Witness,
    /// Proof of election
    proof_of_election: ProofOfElection<DomainHash>,
}

impl<DomainHash> BundleSolution<DomainHash> {
    pub fn proof_of_election(&self) -> &ProofOfElection<DomainHash> {
        &self.proof_of_election
    }

    /// Returns the hash of the block on top of which the solution was created.
    pub fn creation_block_hash(&self) -> &DomainHash {
        &self.proof_of_election.system_block_hash
    }
}

impl<DomainHash: Default> BundleSolution<DomainHash> {
    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy(domain_id: DomainId, executor_public_key: ExecutorPublicKey) -> Self {
        let proof_of_election = ProofOfElection::dummy(domain_id, executor_public_key);

        Self {
            authority_stake_weight: Default::default(),
            authority_witness: Default::default(),
            proof_of_election,
        }
    }
}

/// Domain bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct Bundle<Extrinsic, Number, Hash, DomainHash> {
    /// Sealed bundle header.
    pub sealed_header: SealedBundleHeader<Number, Hash, DomainHash>,
    /// Execution receipt that should extend the receipt chain or add confirmations
    /// to the head receipt.
    pub receipt: ExecutionReceipt<Number, Hash, DomainHash>,
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

    /// Returns the domain_id of this bundle.
    pub fn domain_id(&self) -> DomainId {
        self.sealed_header
            .header
            .bundle_solution
            .proof_of_election()
            .domain_id
    }

    /// Consumes [`Bundle`] to extract the inner executor public key.
    pub fn into_executor_public_key(self) -> ExecutorPublicKey {
        self.sealed_header
            .header
            .bundle_solution
            .proof_of_election
            .executor_public_key
    }
}

/// Bundle with opaque extrinsics.
pub type OpaqueBundle<Number, Hash, DomainHash> = Bundle<OpaqueExtrinsic, Number, Hash, DomainHash>;

impl<Extrinsic: Encode, Number, Hash, DomainHash> Bundle<Extrinsic, Number, Hash, DomainHash> {
    /// Convert a bundle with generic extrinsic to a bundle with opaque extrinsic.
    pub fn into_opaque_bundle(self) -> OpaqueBundle<Number, Hash, DomainHash> {
        let Bundle {
            sealed_header,
            receipt,
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
            sealed_header,
            receipt,
            extrinsics: opaque_extrinsics,
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

impl<Number: Zero, Hash, DomainHash: Default> ExecutionReceipt<Number, Hash, DomainHash> {
    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy(
        primary_number: Number,
        primary_hash: Hash,
    ) -> ExecutionReceipt<Number, Hash, DomainHash> {
        let trace = if primary_number.is_zero() {
            Vec::new()
        } else {
            sp_std::vec![Default::default(), Default::default()]
        };
        ExecutionReceipt {
            primary_number,
            primary_hash,
            domain_hash: Default::default(),
            trace,
            trace_root: Default::default(),
        }
    }
}

/// List of [`OpaqueBundle`].
pub type OpaqueBundles<Block, DomainHash> =
    Vec<OpaqueBundle<NumberFor<Block>, <Block as BlockT>::Hash, DomainHash>>;

#[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
pub fn create_dummy_bundle_with_receipts_generic<BlockNumber, Hash, DomainHash>(
    domain_id: DomainId,
    primary_number: BlockNumber,
    primary_hash: Hash,
    receipt: ExecutionReceipt<BlockNumber, Hash, DomainHash>,
) -> OpaqueBundle<BlockNumber, Hash, DomainHash>
where
    BlockNumber: Encode + Default,
    Hash: Encode + Default,
    DomainHash: Encode + Default,
{
    use sp_core::crypto::UncheckedFrom;

    let sealed_header = SealedBundleHeader {
        header: BundleHeader {
            primary_number,
            primary_hash,
            slot_number: 0u64,
            extrinsics_root: Default::default(),
            bundle_solution: BundleSolution::dummy(
                domain_id,
                ExecutorPublicKey::unchecked_from([0u8; 32]),
            ),
        },
        signature: ExecutorSignature::unchecked_from([0u8; 64]),
    };

    OpaqueBundle {
        sealed_header,
        receipt,
        extrinsics: Vec::new(),
    }
}

#[derive(Serialize, Deserialize)]
pub struct GenesisDomainRuntime {
    pub name: Vec<u8>,
    pub runtime_type: RuntimeType,
    pub runtime_version: RuntimeVersion,
    pub code: Vec<u8>,
}

/// Types of runtime pallet domains currently supports
#[derive(
    TypeInfo, Debug, Default, Encode, Decode, Clone, PartialEq, Eq, Serialize, Deserialize,
)]
pub enum RuntimeType {
    #[default]
    Evm,
}

/// Type representing the runtime ID.
pub type RuntimeId = u32;

/// Domains specific digest item.
#[derive(PartialEq, Eq, Clone, Encode, Decode, TypeInfo)]
pub enum DomainDigestItem {
    DomainRuntimeUpgraded(RuntimeId),
}

/// Domains specific digest items.
pub trait DomainsDigestItem {
    fn domain_runtime_upgrade(runtime_id: RuntimeId) -> Self;
    fn as_domain_runtime_upgrade(&self) -> Option<RuntimeId>;
}

impl DomainsDigestItem for DigestItem {
    fn domain_runtime_upgrade(runtime_id: RuntimeId) -> Self {
        Self::Other(DomainDigestItem::DomainRuntimeUpgraded(runtime_id).encode())
    }

    fn as_domain_runtime_upgrade(&self) -> Option<RuntimeId> {
        match self.try_to::<DomainDigestItem>(OpaqueDigestItemId::Other) {
            None => None,
            Some(domain_digest_item) => match domain_digest_item {
                DomainDigestItem::DomainRuntimeUpgraded(runtime_id) => Some(runtime_id),
            },
        }
    }
}

sp_api::decl_runtime_apis! {
    /// API necessary for executor pallet.
    pub trait ExecutorApi<DomainHash: Encode + Decode> {
        /// Submits the transaction bundle via an unsigned extrinsic.
        fn submit_bundle_unsigned(opaque_bundle: OpaqueBundle<NumberFor<Block>, Block::Hash, DomainHash>);

        /// Extract the bundles stored successfully from the given extrinsics.
        fn extract_successful_bundles(
            extrinsics: Vec<Block::Extrinsic>,
        ) -> OpaqueBundles<Block, DomainHash>;

        /// Returns the hash of successfully submitted bundles.
        fn successful_bundle_hashes() -> Vec<H256>;

        /// Generates a randomness seed for extrinsics shuffling.
        fn extrinsics_shuffling_seed(header: Block::Header) -> Randomness;

        /// Returns the WASM bundle for given `domain_id`.
        fn domain_runtime_code(domain_id: DomainId) -> Option<Vec<u8>>;

        /// Returns the current timestamp at given height.
        fn timestamp() -> Moment;

        /// Returns the current Tx range for the given domain Id.
        fn domain_tx_range(domain_id: DomainId) -> U256;
    }
}
