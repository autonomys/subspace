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

//! Primitives for domains pallet.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod bundle_producer_election;
pub mod fraud_proof;
pub mod merkle_tree;
#[cfg(test)]
mod tests;
pub mod transaction;
pub mod valued_trie_root;
pub mod verification;

use bundle_producer_election::{BundleProducerElectionParams, VrfProofError};
use hexlit::hex;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_api::RuntimeVersion;
use sp_core::crypto::KeyTypeId;
use sp_core::sr25519::vrf::VrfSignature;
#[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
use sp_core::sr25519::vrf::{VrfOutput, VrfProof};
use sp_core::H256;
use sp_runtime::generic::OpaqueDigestItemId;
use sp_runtime::traits::{
    BlakeTwo256, Block as BlockT, CheckedAdd, Hash as HashT, NumberFor, Zero,
};
use sp_runtime::{DigestItem, OpaqueExtrinsic, Percent};
use sp_runtime_interface::pass_by::PassBy;
use sp_runtime_interface::{pass_by, runtime_interface};
use sp_std::vec::Vec;
use sp_weights::Weight;
use subspace_core_primitives::crypto::blake2b_256_hash;
use subspace_core_primitives::{bidirectional_distance, Blake2b256Hash, Randomness, U256};
use subspace_runtime_primitives::{Balance, Moment};

/// Key type for Operator.
const KEY_TYPE: KeyTypeId = KeyTypeId(*b"oper");

/// Extrinsics shuffling seed
pub const EXTRINSICS_SHUFFLING_SEED: &[u8] = b"extrinsics-shuffling-seed";

mod app {
    use super::KEY_TYPE;
    use sp_application_crypto::{app_crypto, sr25519};

    app_crypto!(sr25519, KEY_TYPE);
}

/// An operator authority signature.
pub type OperatorSignature = app::Signature;

/// An operator authority keypair. Necessarily equivalent to the schnorrkel public key used in
/// the main executor module. If that ever changes, then this must, too.
#[cfg(feature = "std")]
pub type OperatorPair = app::Pair;

/// An operator authority identifier.
pub type OperatorPublicKey = app::Public;

/// A type that implements `BoundToRuntimeAppPublic`, used for operator signing key.
pub struct OperatorKey;

impl sp_runtime::BoundToRuntimeAppPublic for OperatorKey {
    type Public = OperatorPublicKey;
}

/// Stake weight in the domain bundle election.
///
/// Derived from the Balance and can't be smaller than u128.
pub type StakeWeight = u128;

/// The hash of a execution receipt.
pub type ReceiptHash = H256;

/// The Merkle root of all extrinsics included in a bundle.
pub type ExtrinsicsRoot = H256;

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
    MaxEncodedLen,
)]
pub struct DomainId(u32);

impl PassBy for DomainId {
    type PassBy = pass_by::Codec<Self>;
}

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

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleHeader<Number, Hash, DomainNumber, DomainHash, Balance> {
    /// Proof of bundle producer election.
    pub proof_of_election: ProofOfElection,
    /// Execution receipt that should extend the receipt chain or add confirmations
    /// to the head receipt.
    pub receipt: ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>,
    /// The size of the bundle body in bytes.
    ///
    /// Used to calculate the storage cost.
    pub bundle_size: u32,
    /// The total (estimated) weight of all extrinsics in the bundle.
    ///
    /// Used to prevent overloading the bundle with compute.
    pub estimated_bundle_weight: Weight,
    /// The Merkle root of all new extrinsics included in this bundle.
    pub bundle_extrinsics_root: ExtrinsicsRoot,
}

impl<Number: Encode, Hash: Encode, DomainNumber: Encode, DomainHash: Encode, Balance: Encode>
    BundleHeader<Number, Hash, DomainNumber, DomainHash, Balance>
{
    /// Returns the hash of this header.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

/// Header of bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct SealedBundleHeader<Number, Hash, DomainNumber, DomainHash, Balance> {
    /// Unsealed header.
    pub header: BundleHeader<Number, Hash, DomainNumber, DomainHash, Balance>,
    /// Signature of the bundle.
    pub signature: OperatorSignature,
}

impl<Number: Encode, Hash: Encode, DomainNumber: Encode, DomainHash: Encode, Balance: Encode>
    SealedBundleHeader<Number, Hash, DomainNumber, DomainHash, Balance>
{
    /// Constructs a new instance of [`SealedBundleHeader`].
    pub fn new(
        header: BundleHeader<Number, Hash, DomainNumber, DomainHash, Balance>,
        signature: OperatorSignature,
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

    pub fn slot_number(&self) -> u64 {
        self.header.proof_of_election.slot_number
    }
}

/// Domain bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct Bundle<Extrinsic, Number, Hash, DomainNumber, DomainHash, Balance> {
    /// Sealed bundle header.
    pub sealed_header: SealedBundleHeader<Number, Hash, DomainNumber, DomainHash, Balance>,
    /// The accompanying extrinsics.
    pub extrinsics: Vec<Extrinsic>,
}

impl<
        Extrinsic: Encode,
        Number: Encode,
        Hash: Encode,
        DomainNumber: Encode,
        DomainHash: Encode,
        Balance: Encode,
    > Bundle<Extrinsic, Number, Hash, DomainNumber, DomainHash, Balance>
{
    /// Returns the hash of this bundle.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }

    /// Returns the domain_id of this bundle.
    pub fn domain_id(&self) -> DomainId {
        self.sealed_header.header.proof_of_election.domain_id
    }

    /// Return the `bundle_extrinsics_root`
    pub fn extrinsics_root(&self) -> ExtrinsicsRoot {
        self.sealed_header.header.bundle_extrinsics_root
    }

    /// Return the `operator_id`
    pub fn operator_id(&self) -> OperatorId {
        self.sealed_header.header.proof_of_election.operator_id
    }

    /// Return a reference of the execution receipt.
    pub fn receipt(&self) -> &ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance> {
        &self.sealed_header.header.receipt
    }

    /// Consumes [`Bundle`] to extract the execution receipt.
    pub fn into_receipt(self) -> ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance> {
        self.sealed_header.header.receipt
    }
}

/// Bundle with opaque extrinsics.
pub type OpaqueBundle<Number, Hash, DomainNumber, DomainHash, Balance> =
    Bundle<OpaqueExtrinsic, Number, Hash, DomainNumber, DomainHash, Balance>;

/// List of [`OpaqueBundle`].
pub type OpaqueBundles<Block, DomainNumber, DomainHash, Balance> =
    Vec<OpaqueBundle<NumberFor<Block>, <Block as BlockT>::Hash, DomainNumber, DomainHash, Balance>>;

impl<Extrinsic: Encode, Number, Hash, DomainNumber, DomainHash, Balance>
    Bundle<Extrinsic, Number, Hash, DomainNumber, DomainHash, Balance>
{
    /// Convert a bundle with generic extrinsic to a bundle with opaque extrinsic.
    pub fn into_opaque_bundle(
        self,
    ) -> OpaqueBundle<Number, Hash, DomainNumber, DomainHash, Balance> {
        let Bundle {
            sealed_header,
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
            extrinsics: opaque_extrinsics,
        }
    }
}

#[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
pub fn dummy_opaque_bundle<
    Number: Encode,
    Hash: Encode,
    DomainNumber: Encode,
    DomainHash: Encode,
    Balance: Encode,
>(
    domain_id: DomainId,
    operator_id: OperatorId,
    receipt: ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>,
) -> OpaqueBundle<Number, Hash, DomainNumber, DomainHash, Balance> {
    use sp_core::crypto::UncheckedFrom;

    let header = BundleHeader {
        proof_of_election: ProofOfElection::dummy(domain_id, operator_id),
        receipt,
        bundle_size: 0u32,
        estimated_bundle_weight: Default::default(),
        bundle_extrinsics_root: Default::default(),
    };
    let signature = OperatorSignature::unchecked_from([0u8; 64]);

    OpaqueBundle {
        sealed_header: SealedBundleHeader::new(header, signature),
        extrinsics: Vec::new(),
    }
}

/// A digest of the bundle
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleDigest {
    /// The hash of the bundle header
    pub header_hash: H256,
    /// The Merkle root of all new extrinsics included in this bundle.
    pub extrinsics_root: ExtrinsicsRoot,
}

/// Receipt of a domain block execution.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance> {
    /// The index of the current domain block that forms the basis of this ER.
    pub domain_block_number: DomainNumber,
    /// The block hash corresponding to `domain_block_number`.
    pub domain_block_hash: DomainHash,
    /// Extrinsic root field of the header of domain block referenced by this ER.
    pub domain_block_extrinsic_root: H256,
    /// The hash of the ER for the last domain block.
    pub parent_domain_block_receipt_hash: ReceiptHash,
    /// A pointer to the consensus block index which contains all of the bundles that were used to derive and
    /// order all extrinsics executed by the current domain block for this ER.
    pub consensus_block_number: Number,
    /// The block hash corresponding to `consensus_block_number`.
    pub consensus_block_hash: Hash,
    /// All the bundles that are included in the domain block building.
    pub valid_bundles: Vec<ValidBundle>,
    /// Potential bundles that are excluded from the domain block building.
    pub invalid_bundles: Vec<InvalidBundle>,
    /// All `extrinsics_roots` for all bundles being executed by this block.
    ///
    /// Used to ensure these are contained within the state of the `execution_inbox`.
    pub block_extrinsics_roots: Vec<ExtrinsicsRoot>,
    /// The final state root for the current domain block reflected by this ER.
    ///
    /// Used for verifying storage proofs for domains.
    pub final_state_root: DomainHash,
    /// List of storage roots collected during the domain block execution.
    pub execution_trace: Vec<DomainHash>,
    /// The Merkle root of the execution trace for the current domain block.
    ///
    /// Used for verifying fraud proofs.
    pub execution_trace_root: H256,
    /// All SSC rewards for this ER to be shared across operators.
    pub total_rewards: Balance,
}

impl<
        Number: Encode + Zero,
        Hash: Encode + Default,
        DomainNumber: Encode + Zero,
        DomainHash: Clone + Encode + Default,
        Balance: Encode + Zero,
    > ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>
{
    /// Returns the hash of this execution receipt.
    pub fn hash(&self) -> ReceiptHash {
        BlakeTwo256::hash_of(self)
    }

    pub fn genesis(consensus_genesis_hash: Hash, genesis_state_root: DomainHash) -> Self {
        ExecutionReceipt {
            domain_block_number: Zero::zero(),
            domain_block_hash: Default::default(),
            domain_block_extrinsic_root: Default::default(),
            parent_domain_block_receipt_hash: Default::default(),
            consensus_block_hash: consensus_genesis_hash,
            consensus_block_number: Zero::zero(),
            valid_bundles: Vec::new(),
            invalid_bundles: Vec::new(),
            block_extrinsics_roots: sp_std::vec![],
            final_state_root: genesis_state_root.clone(),
            execution_trace: sp_std::vec![genesis_state_root],
            execution_trace_root: Default::default(),
            total_rewards: Zero::zero(),
        }
    }

    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy(
        consensus_block_number: Number,
        consensus_block_hash: Hash,
        domain_block_number: DomainNumber,
        parent_domain_block_receipt_hash: ReceiptHash,
    ) -> ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance> {
        let execution_trace = sp_std::vec![Default::default(), Default::default()];
        let execution_trace_root = {
            let trace: Vec<[u8; 32]> = execution_trace
                .iter()
                .map(|r: &DomainHash| r.encode().try_into().expect("H256 must fit into [u8; 32]"))
                .collect();
            crate::merkle_tree::MerkleTree::from_leaves(trace.as_slice())
                .root()
                .expect("Compute merkle root of trace should success")
                .into()
        };
        ExecutionReceipt {
            domain_block_number,
            domain_block_hash: Default::default(),
            domain_block_extrinsic_root: Default::default(),
            parent_domain_block_receipt_hash,
            consensus_block_number,
            consensus_block_hash,
            valid_bundles: Vec::new(),
            invalid_bundles: Vec::new(),
            block_extrinsics_roots: sp_std::vec![Default::default()],
            final_state_root: Default::default(),
            execution_trace,
            execution_trace_root,
            total_rewards: Zero::zero(),
        }
    }
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct ProofOfElection {
    /// Domain id.
    pub domain_id: DomainId,
    /// The slot number.
    pub slot_number: u64,
    /// Global randomness.
    pub global_randomness: Randomness,
    /// VRF signature.
    pub vrf_signature: VrfSignature,
    /// Operator index in the OperatorRegistry.
    pub operator_id: OperatorId,
}

impl ProofOfElection {
    pub fn verify_vrf_signature(
        &self,
        operator_signing_key: &OperatorPublicKey,
    ) -> Result<(), VrfProofError> {
        let global_challenge = self
            .global_randomness
            .derive_global_challenge(self.slot_number);
        bundle_producer_election::verify_vrf_signature(
            self.domain_id,
            operator_signing_key,
            &self.vrf_signature,
            &global_challenge,
        )
    }

    /// Computes the VRF hash.
    pub fn vrf_hash(&self) -> Blake2b256Hash {
        let mut bytes = self.vrf_signature.output.encode();
        bytes.append(&mut self.vrf_signature.proof.encode());
        blake2b_256_hash(&bytes)
    }
}

impl ProofOfElection {
    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy(domain_id: DomainId, operator_id: OperatorId) -> Self {
        let output_bytes = sp_std::vec![0u8; VrfOutput::max_encoded_len()];
        let proof_bytes = sp_std::vec![0u8; VrfProof::max_encoded_len()];
        let vrf_signature = VrfSignature {
            output: VrfOutput::decode(&mut output_bytes.as_slice()).unwrap(),
            proof: VrfProof::decode(&mut proof_bytes.as_slice()).unwrap(),
        };
        Self {
            domain_id,
            slot_number: 0u64,
            global_randomness: Randomness::default(),
            vrf_signature,
            operator_id,
        }
    }
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisDomain<AccountId> {
    // Domain runtime items
    pub runtime_name: Vec<u8>,
    pub runtime_type: RuntimeType,
    pub runtime_version: RuntimeVersion,
    pub code: Vec<u8>,

    // Domain config items
    pub owner_account_id: AccountId,
    pub domain_name: Vec<u8>,
    pub max_block_size: u32,
    pub max_block_weight: Weight,
    pub bundle_slot_probability: (u64, u64),
    pub target_bundles_per_block: u32,
    pub raw_genesis_config: Vec<u8>,

    // Genesis operator
    pub signing_key: OperatorPublicKey,
    pub minimum_nominator_stake: Balance,
    pub nomination_tax: Percent,
}

/// Types of runtime pallet domains currently supports
#[derive(
    TypeInfo, Debug, Default, Encode, Decode, Clone, PartialEq, Eq, Serialize, Deserialize,
)]
pub enum RuntimeType {
    #[default]
    Evm,
}

impl PassBy for RuntimeType {
    type PassBy = pass_by::Codec<Self>;
}

/// Type representing the runtime ID.
pub type RuntimeId = u32;

/// Type representing domain epoch.
pub type EpochIndex = u32;

/// Type representing operator ID
pub type OperatorId = u64;

/// Staking specific hold identifier
#[derive(
    PartialEq, Eq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Ord, PartialOrd, Copy, Debug,
)]
pub enum StakingHoldIdentifier {
    /// Holds all the pending deposits to an Operator.
    PendingDeposit(OperatorId),
    /// Holds all the currently staked funds to an Operator.
    Staked(OperatorId),
    /// Holds all the currently unlocking funds.
    PendingUnlock(OperatorId),
}

/// Domains specific Identifier for Balances holds.
#[derive(
    PartialEq, Eq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Ord, PartialOrd, Copy, Debug,
)]
pub enum DomainsHoldIdentifier {
    Staking(StakingHoldIdentifier),
    DomainInstantiation(DomainId),
}

/// Domains specific digest item.
#[derive(PartialEq, Eq, Clone, Encode, Decode, TypeInfo)]
pub enum DomainDigestItem {
    DomainRuntimeUpgraded(RuntimeId),
    DomainInstantiated(DomainId),
}

/// Domains specific digest items.
pub trait DomainsDigestItem {
    fn domain_runtime_upgrade(runtime_id: RuntimeId) -> Self;
    fn as_domain_runtime_upgrade(&self) -> Option<RuntimeId>;

    fn domain_instantiation(domain_id: DomainId) -> Self;
    fn as_domain_instantiation(&self) -> Option<DomainId>;
}

impl DomainsDigestItem for DigestItem {
    fn domain_runtime_upgrade(runtime_id: RuntimeId) -> Self {
        Self::Other(DomainDigestItem::DomainRuntimeUpgraded(runtime_id).encode())
    }

    fn as_domain_runtime_upgrade(&self) -> Option<RuntimeId> {
        match self.try_to::<DomainDigestItem>(OpaqueDigestItemId::Other) {
            Some(DomainDigestItem::DomainRuntimeUpgraded(runtime_id)) => Some(runtime_id),
            _ => None,
        }
    }

    fn domain_instantiation(domain_id: DomainId) -> Self {
        Self::Other(DomainDigestItem::DomainInstantiated(domain_id).encode())
    }

    fn as_domain_instantiation(&self) -> Option<DomainId> {
        match self.try_to::<DomainDigestItem>(OpaqueDigestItemId::Other) {
            Some(DomainDigestItem::DomainInstantiated(domain_id)) => Some(domain_id),
            _ => None,
        }
    }
}

/// `DomainInstanceData` is used to construct `RuntimeGenesisConfig` which will be further used
/// to construct the genesis block
#[derive(PartialEq, Eq, Clone, Encode, Decode, TypeInfo)]
pub struct DomainInstanceData {
    pub runtime_type: RuntimeType,
    pub runtime_code: Vec<u8>,
    // The genesis config of the domain, encoded in json format.
    //
    // NOTE: the WASM code in the `system-pallet` genesis config should be empty to avoid
    // redundancy with the `runtime_code` field.
    pub raw_genesis_config: Option<Vec<u8>>,
}

impl PassBy for DomainInstanceData {
    type PassBy = pass_by::Codec<Self>;
}

#[cfg(feature = "std")]
pub trait GenerateGenesisStateRoot: Send + Sync {
    /// Returns the state root of genesis block built from the runtime genesis config on success.
    fn generate_genesis_state_root(
        &self,
        domain_id: DomainId,
        domain_instance_data: DomainInstanceData,
    ) -> Option<H256>;
}

#[cfg(feature = "std")]
sp_externalities::decl_extension! {
    /// A domain genesis receipt extension.
    pub struct GenesisReceiptExtension(std::sync::Arc<dyn GenerateGenesisStateRoot>);
}

#[cfg(feature = "std")]
impl GenesisReceiptExtension {
    /// Create a new instance of [`GenesisReceiptExtension`].
    pub fn new(inner: std::sync::Arc<dyn GenerateGenesisStateRoot>) -> Self {
        Self(inner)
    }
}

/// Domain-related runtime interface
#[runtime_interface]
pub trait Domain {
    fn generate_genesis_state_root(
        &mut self,
        domain_id: DomainId,
        domain_instance_data: DomainInstanceData,
    ) -> Option<H256> {
        use sp_externalities::ExternalitiesExt;

        self.extension::<GenesisReceiptExtension>()
            .expect("No `GenesisReceiptExtension` associated for the current context!")
            .generate_genesis_state_root(domain_id, domain_instance_data)
    }
}

#[derive(Debug, Decode, Encode, TypeInfo, Clone)]
pub struct DomainBlockLimit {
    /// The max block size for the domain.
    pub max_block_size: u32,
    /// The max block weight for the domain.
    pub max_block_weight: Weight,
}

/// Checks if the signer Id hash is within the tx range
pub fn signer_in_tx_range(bundle_vrf_hash: &U256, signer_id_hash: &U256, tx_range: &U256) -> bool {
    let distance_from_vrf_hash = bidirectional_distance(bundle_vrf_hash, signer_id_hash);
    distance_from_vrf_hash <= (*tx_range / 2)
}

/// Receipt invalidity type.
#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
pub enum InvalidReceipt {
    /// The field `invalid_bundles` in [`ExecutionReceipt`] is invalid.
    InvalidBundles,
}

#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
pub enum ReceiptValidity {
    Valid,
    Invalid(InvalidReceipt),
}

/// Bundle invalidity type.
#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
pub enum InvalidBundleType {
    /// Failed to decode the opaque extrinsic.
    UndecodableTx,
    /// Transaction is out of the tx range.
    OutOfRangeTx,
    /// Transaction is illegal (unable to pay the fee, etc).
    IllegalTx,
    /// Transaction is an invalid XDM
    InvalidXDM,
    /// Receipt is invalid.
    InvalidReceipt(InvalidReceipt),
}

/// [`InvalidBundle`] represents a bundle that was originally included in the consensus
/// block but subsequently excluded from the corresponding domain block by operator due
/// to being flagged as invalid.
#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
pub struct InvalidBundle {
    /// Index of this bundle in the original list of bundles in the consensus block.
    pub bundle_index: u32,
    /// Specific type of invalidity.
    pub invalid_bundle_type: InvalidBundleType,
}

/// [`ValidBundle`] represents a bundle that was used when building the domain block.
#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
pub struct ValidBundle {
    /// Index of this bundle in the original list of bundles in the consensus block.
    pub bundle_index: u32,
    /// Hash of `Vec<(tx_signer, tx_hash)>` of all domain extrinsic being included in the bundle.
    pub bundle_digest: H256,
}

#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
pub enum BundleValidity<Extrinsic> {
    Valid(Vec<Extrinsic>),
    Invalid(InvalidBundleType),
}

/// Empty extrinsics root
pub const EMPTY_EXTRINSIC_ROOT: ExtrinsicsRoot = ExtrinsicsRoot {
    0: hex!("03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314"),
};

sp_api::decl_runtime_apis! {
    /// API necessary for domains pallet.
    pub trait DomainsApi<DomainNumber: Encode + Decode, DomainHash: Encode + Decode> {
        /// Submits the transaction bundle via an unsigned extrinsic.
        fn submit_bundle_unsigned(opaque_bundle: OpaqueBundle<NumberFor<Block>, Block::Hash, DomainNumber, DomainHash, Balance>);

        /// Extract the bundles stored successfully from the given extrinsics.
        fn extract_successful_bundles(
            domain_id: DomainId,
            extrinsics: Vec<Block::Extrinsic>,
        ) -> OpaqueBundles<Block, DomainNumber, DomainHash, Balance>;

        /// Generates a randomness seed for extrinsics shuffling.
        fn extrinsics_shuffling_seed() -> Randomness;

        /// Returns the WASM bundle for given `domain_id`.
        fn domain_runtime_code(domain_id: DomainId) -> Option<Vec<u8>>;

        /// Returns the runtime id for given `domain_id`.
        fn runtime_id(domain_id: DomainId) -> Option<RuntimeId>;

        /// Returns the domain instance data for given `domain_id`.
        fn domain_instance_data(domain_id: DomainId) -> Option<(DomainInstanceData, NumberFor<Block>)>;

        /// Returns the current timestamp at given height.
        fn timestamp() -> Moment;

        /// Returns the current Tx range for the given domain Id.
        fn domain_tx_range(domain_id: DomainId) -> U256;

        /// Return the genesis state root if not pruned
        fn genesis_state_root(domain_id: DomainId) -> Option<H256>;

        /// Returns the best execution chain number.
        fn head_receipt_number(domain_id: DomainId) -> NumberFor<Block>;

        /// Returns the block number of oldest execution receipt.
        fn oldest_receipt_number(domain_id: DomainId) -> NumberFor<Block>;

        /// Returns the block tree pruning depth.
        fn block_tree_pruning_depth() -> NumberFor<Block>;

        /// Returns the domain block limit of the given domain.
        fn domain_block_limit(domain_id: DomainId) -> Option<DomainBlockLimit>;

        /// Returns true if there are any ERs in the challenge period with non empty extrinsics.
        fn non_empty_er_exists(domain_id: DomainId) -> bool;

        /// Returns the current best number of the domain.
        fn domain_best_number(domain_id: DomainId) -> Option<DomainNumber>;

        /// Returns the chain state root at the given block.
        fn domain_state_root(domain_id: DomainId, number: DomainNumber, hash: DomainHash) -> Option<DomainHash>;
    }

    pub trait BundleProducerElectionApi<Balance: Encode + Decode> {
        fn bundle_producer_election_params(domain_id: DomainId) -> Option<BundleProducerElectionParams<Balance>>;

        fn operator(operator_id: OperatorId) -> Option<(OperatorPublicKey, Balance)>;
    }
}
