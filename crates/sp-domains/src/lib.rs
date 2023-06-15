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
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use schnorrkel::vrf::{VRF_OUTPUT_LENGTH, VRF_PROOF_LENGTH};
use sp_core::crypto::KeyTypeId;
use sp_core::H256;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT, NumberFor, Zero};
use sp_runtime::{OpaqueExtrinsic, RuntimeAppPublic};
use sp_std::borrow::Cow;
use sp_std::vec::Vec;
use sp_trie::StorageProof;
use subspace_core_primitives::crypto::blake2b_256_hash;
use subspace_core_primitives::{Blake2b256Hash, BlockNumber, Randomness};
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
    Clone, Copy, Debug, Hash, Default, Eq, PartialEq, Ord, PartialOrd, Encode, Decode, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
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

    pub const CORE_ETH_RELAY: Self = Self::new(2);

    pub const CORE_EVM: Self = Self::new(3);

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
    pub vrf_output: [u8; VRF_OUTPUT_LENGTH],
    /// VRF proof.
    pub vrf_proof: [u8; VRF_PROOF_LENGTH],
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
            &self.vrf_output,
            &self.vrf_proof,
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
        Self {
            domain_id,
            vrf_output: [0u8; VRF_OUTPUT_LENGTH],
            vrf_proof: [0u8; VRF_PROOF_LENGTH],
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
pub enum BundleSolution<DomainHash> {
    /// System domain bundle election.
    System {
        /// Authority's stake weight.
        authority_stake_weight: StakeWeight,
        /// Authority membership witness.
        authority_witness: Witness,
        /// Proof of election
        proof_of_election: ProofOfElection<DomainHash>,
    },
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
            Self::System {
                proof_of_election, ..
            }
            | Self::Core {
                proof_of_election, ..
            } => proof_of_election,
        }
    }

    /// Returns the hash of the block on top of which the solution was created.
    pub fn creation_block_hash(&self) -> &DomainHash {
        match self {
            Self::System {
                proof_of_election, ..
            } => &proof_of_election.system_block_hash,
            Self::Core {
                core_block_hash, ..
            } => core_block_hash,
        }
    }
}

impl<DomainHash: Default> BundleSolution<DomainHash> {
    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy(domain_id: DomainId, executor_public_key: ExecutorPublicKey) -> Self {
        let proof_of_election = ProofOfElection::dummy(domain_id, executor_public_key);

        if domain_id.is_system() {
            Self::System {
                authority_stake_weight: Default::default(),
                authority_witness: Default::default(),
                proof_of_election,
            }
        } else if domain_id.is_core() {
            Self::Core {
                proof_of_election,
                core_block_number: Default::default(),
                core_block_hash: Default::default(),
                core_state_root: Default::default(),
            }
        } else {
            panic!("Open domain unsupported");
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
        match self.sealed_header.header.bundle_solution {
            BundleSolution::System {
                proof_of_election, ..
            }
            | BundleSolution::Core {
                proof_of_election, ..
            } => proof_of_election.executor_public_key,
        }
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

sp_api::decl_runtime_apis! {
    /// API necessary for executor pallet.
    pub trait ExecutorApi<DomainHash: Encode + Decode> {
        /// Submits the transaction bundle via an unsigned extrinsic.
        fn submit_bundle_unsigned(opaque_bundle: OpaqueBundle<NumberFor<Block>, Block::Hash, DomainHash>);

        /// Extract the system bundles from the given extrinsics.
        fn extract_system_bundles(
            extrinsics: Vec<Block::Extrinsic>,
        ) -> (OpaqueBundles<Block, DomainHash>, OpaqueBundles<Block, DomainHash>);

        /// Extract the core bundles from the given extrinsics.
        fn extract_core_bundles(
            extrinsics: Vec<Block::Extrinsic>,
            domain_id: DomainId,
        ) -> OpaqueBundles<Block, DomainHash>;

        /// Returns the hash of successfully submitted bundles.
        fn successful_bundle_hashes() -> Vec<H256>;

        /// Generates a randomness seed for extrinsics shuffling.
        fn extrinsics_shuffling_seed(header: Block::Header) -> Randomness;

        /// WASM bundle for system domain runtime.
        fn system_domain_wasm_bundle() -> Cow<'static, [u8]>;

        // Returns the current timestamp at given height
        fn timestamp() -> Moment;
    }
}
