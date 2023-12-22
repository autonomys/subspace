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
pub mod extrinsics;
pub mod merkle_tree;
pub mod proof_provider_and_verifier;
pub mod storage;
#[cfg(test)]
mod tests;
pub mod valued_trie;

extern crate alloc;

use crate::storage::{RawGenesis, StorageKey};
use alloc::string::String;
use bundle_producer_election::{BundleProducerElectionParams, ProofOfElectionError};
use hexlit::hex;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_api::RuntimeVersion;
use sp_application_crypto::sr25519;
use sp_core::crypto::KeyTypeId;
use sp_core::sr25519::vrf::VrfSignature;
#[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
use sp_core::sr25519::vrf::{VrfOutput, VrfProof};
use sp_core::H256;
use sp_runtime::generic::OpaqueDigestItemId;
use sp_runtime::traits::{
    BlakeTwo256, Block as BlockT, CheckedAdd, Hash as HashT, Header as HeaderT, NumberFor, Zero,
};
use sp_runtime::{Digest, DigestItem, OpaqueExtrinsic, Percent};
use sp_runtime_interface::pass_by;
use sp_runtime_interface::pass_by::PassBy;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::btree_set::BTreeSet;
use sp_std::fmt::{Display, Formatter};
use sp_std::vec::Vec;
use sp_trie::TrieLayout;
use sp_weights::Weight;
use subspace_core_primitives::crypto::blake3_hash;
use subspace_core_primitives::{bidirectional_distance, Blake3Hash, Randomness, U256};
use subspace_runtime_primitives::{Balance, Moment};

/// Key type for Operator.
const KEY_TYPE: KeyTypeId = KeyTypeId(*b"oper");

/// Extrinsics shuffling seed
pub const DOMAIN_EXTRINSICS_SHUFFLING_SEED_SUBJECT: &[u8] = b"extrinsics-shuffling-seed";

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

/// The Trie root of all extrinsics included in a bundle.
pub type ExtrinsicsRoot = H256;

/// Type alias for Header Hashing.
pub type HeaderHashingFor<Header> = <Header as HeaderT>::Hashing;
/// Type alias for Header number.
pub type HeaderNumberFor<Header> = <Header as HeaderT>::Number;
/// Type alias for Header hash.
pub type HeaderHashFor<Header> = <Header as HeaderT>::Hash;

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

impl Display for DomainId {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl PassBy for DomainId {
    type PassBy = pass_by::Codec<Self>;
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleHeader<Number, Hash, DomainHeader: HeaderT, Balance> {
    /// Proof of bundle producer election.
    pub proof_of_election: ProofOfElection<Hash>,
    /// Execution receipt that should extend the receipt chain or add confirmations
    /// to the head receipt.
    pub receipt: ExecutionReceipt<
        Number,
        Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
    /// The size of the bundle body in bytes.
    ///
    /// Used to calculate the storage cost.
    pub bundle_size: u32,
    /// The total (estimated) weight of all extrinsics in the bundle.
    ///
    /// Used to prevent overloading the bundle with compute.
    pub estimated_bundle_weight: Weight,
    /// The Merkle root of all new extrinsics included in this bundle.
    pub bundle_extrinsics_root: HeaderHashFor<DomainHeader>,
}

impl<Number: Encode, Hash: Encode, DomainHeader: HeaderT, Balance: Encode>
    BundleHeader<Number, Hash, DomainHeader, Balance>
{
    /// Returns the hash of this header.
    pub fn hash(&self) -> HeaderHashFor<DomainHeader> {
        HeaderHashingFor::<DomainHeader>::hash_of(self)
    }
}

/// Header of bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct SealedBundleHeader<Number, Hash, DomainHeader: HeaderT, Balance> {
    /// Unsealed header.
    pub header: BundleHeader<Number, Hash, DomainHeader, Balance>,
    /// Signature of the bundle.
    pub signature: OperatorSignature,
}

impl<Number: Encode, Hash: Encode, DomainHeader: HeaderT, Balance: Encode>
    SealedBundleHeader<Number, Hash, DomainHeader, Balance>
{
    /// Constructs a new instance of [`SealedBundleHeader`].
    pub fn new(
        header: BundleHeader<Number, Hash, DomainHeader, Balance>,
        signature: OperatorSignature,
    ) -> Self {
        Self { header, signature }
    }

    /// Returns the hash of the inner unsealed header.
    pub fn pre_hash(&self) -> HeaderHashFor<DomainHeader> {
        self.header.hash()
    }

    /// Returns the hash of this header.
    pub fn hash(&self) -> HeaderHashFor<DomainHeader> {
        HeaderHashingFor::<DomainHeader>::hash_of(self)
    }

    pub fn slot_number(&self) -> u64 {
        self.header.proof_of_election.slot_number
    }
}

/// Domain bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct Bundle<Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance> {
    /// Sealed bundle header.
    pub sealed_header: SealedBundleHeader<Number, Hash, DomainHeader, Balance>,
    /// The accompanying extrinsics.
    pub extrinsics: Vec<Extrinsic>,
}

impl<Extrinsic: Encode, Number: Encode, Hash: Encode, DomainHeader: HeaderT, Balance: Encode>
    Bundle<Extrinsic, Number, Hash, DomainHeader, Balance>
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
    pub fn extrinsics_root(&self) -> HeaderHashFor<DomainHeader> {
        self.sealed_header.header.bundle_extrinsics_root
    }

    /// Return the `operator_id`
    pub fn operator_id(&self) -> OperatorId {
        self.sealed_header.header.proof_of_election.operator_id
    }

    /// Return a reference of the execution receipt.
    pub fn receipt(
        &self,
    ) -> &ExecutionReceipt<
        Number,
        Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    > {
        &self.sealed_header.header.receipt
    }

    /// Consumes [`Bundle`] to extract the execution receipt.
    pub fn into_receipt(
        self,
    ) -> ExecutionReceipt<
        Number,
        Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    > {
        self.sealed_header.header.receipt
    }
}

/// Bundle with opaque extrinsics.
pub type OpaqueBundle<Number, Hash, DomainHeader, Balance> =
    Bundle<OpaqueExtrinsic, Number, Hash, DomainHeader, Balance>;

/// List of [`OpaqueBundle`].
pub type OpaqueBundles<Block, DomainHeader, Balance> =
    Vec<OpaqueBundle<NumberFor<Block>, <Block as BlockT>::Hash, DomainHeader, Balance>>;

impl<Extrinsic: Encode, Number, Hash, DomainHeader: HeaderT, Balance>
    Bundle<Extrinsic, Number, Hash, DomainHeader, Balance>
{
    /// Convert a bundle with generic extrinsic to a bundle with opaque extrinsic.
    pub fn into_opaque_bundle(self) -> OpaqueBundle<Number, Hash, DomainHeader, Balance> {
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
    Hash: Default + Encode,
    DomainHeader: HeaderT,
    Balance: Encode,
>(
    domain_id: DomainId,
    operator_id: OperatorId,
    receipt: ExecutionReceipt<
        Number,
        Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
) -> OpaqueBundle<Number, Hash, DomainHeader, Balance> {
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
pub struct BundleDigest<Hash> {
    /// The hash of the bundle header
    pub header_hash: Hash,
    /// The Merkle root of all new extrinsics included in this bundle.
    pub extrinsics_root: Hash,
}

/// Receipt of a domain block execution.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance> {
    /// The index of the current domain block that forms the basis of this ER.
    pub domain_block_number: DomainNumber,
    /// The block hash corresponding to `domain_block_number`.
    pub domain_block_hash: DomainHash,
    /// Extrinsic root field of the header of domain block referenced by this ER.
    pub domain_block_extrinsic_root: DomainHash,
    /// The hash of the ER for the last domain block.
    pub parent_domain_block_receipt_hash: DomainHash,
    /// A pointer to the consensus block index which contains all of the bundles that were used to derive and
    /// order all extrinsics executed by the current domain block for this ER.
    pub consensus_block_number: Number,
    /// The block hash corresponding to `consensus_block_number`.
    pub consensus_block_hash: Hash,
    /// All the bundles that being included in the consensus block.
    pub inboxed_bundles: Vec<InboxedBundle<DomainHash>>,
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

impl<Number, Hash, DomainNumber, DomainHash, Balance>
    ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>
{
    pub fn bundles_extrinsics_roots(&self) -> Vec<&DomainHash> {
        self.inboxed_bundles
            .iter()
            .map(|b| &b.extrinsics_root)
            .collect()
    }

    pub fn valid_bundle_digest_at(&self, index: usize) -> Option<DomainHash>
    where
        DomainHash: Copy,
    {
        match self.inboxed_bundles.get(index).map(|ib| &ib.bundle) {
            Some(BundleValidity::Valid(bundle_digest_hash)) => Some(*bundle_digest_hash),
            _ => None,
        }
    }

    pub fn valid_bundle_digests(&self) -> Vec<DomainHash>
    where
        DomainHash: Copy,
    {
        self.inboxed_bundles
            .iter()
            .filter_map(|b| match b.bundle {
                BundleValidity::Valid(bundle_digest_hash) => Some(bundle_digest_hash),
                BundleValidity::Invalid(_) => None,
            })
            .collect()
    }

    pub fn valid_bundle_indexes(&self) -> Vec<u32> {
        self.inboxed_bundles
            .iter()
            .enumerate()
            .filter_map(|(index, b)| match b.bundle {
                BundleValidity::Valid(_) => Some(index as u32),
                BundleValidity::Invalid(_) => None,
            })
            .collect()
    }
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
    pub fn hash<DomainHashing: HashT<Output = DomainHash>>(&self) -> DomainHash {
        DomainHashing::hash_of(self)
    }

    pub fn genesis(
        genesis_state_root: DomainHash,
        genesis_extrinsic_root: DomainHash,
        genesis_domain_block_hash: DomainHash,
    ) -> Self {
        ExecutionReceipt {
            domain_block_number: Zero::zero(),
            domain_block_hash: genesis_domain_block_hash,
            domain_block_extrinsic_root: genesis_extrinsic_root,
            parent_domain_block_receipt_hash: Default::default(),
            consensus_block_hash: Default::default(),
            consensus_block_number: Zero::zero(),
            inboxed_bundles: Vec::new(),
            final_state_root: genesis_state_root.clone(),
            execution_trace: sp_std::vec![genesis_state_root],
            execution_trace_root: Default::default(),
            total_rewards: Zero::zero(),
        }
    }

    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy<DomainHashing>(
        consensus_block_number: Number,
        consensus_block_hash: Hash,
        domain_block_number: DomainNumber,
        parent_domain_block_receipt_hash: DomainHash,
    ) -> ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>
    where
        DomainHashing: HashT<Output = DomainHash>,
    {
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
            inboxed_bundles: sp_std::vec![InboxedBundle::dummy(Default::default())],
            final_state_root: Default::default(),
            execution_trace,
            execution_trace_root,
            total_rewards: Zero::zero(),
        }
    }
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct ProofOfElection<CHash> {
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
    /// Consensus block hash at which proof of election was derived.
    pub consensus_block_hash: CHash,
}

impl<CHash> ProofOfElection<CHash> {
    pub fn verify_vrf_signature(
        &self,
        operator_signing_key: &OperatorPublicKey,
    ) -> Result<(), ProofOfElectionError> {
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
    pub fn vrf_hash(&self) -> Blake3Hash {
        let mut bytes = self.vrf_signature.output.encode();
        bytes.append(&mut self.vrf_signature.proof.encode());
        blake3_hash(&bytes)
    }
}

impl<CHash: Default> ProofOfElection<CHash> {
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
            consensus_block_hash: Default::default(),
        }
    }
}

/// Type that represents an operator allow list for Domains.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorAllowList<AccountId: Ord> {
    /// Anyone can operate for this domain.
    Anyone,
    /// Only the specific operators are allowed to operate the domain.
    /// This essentially makes the domain permissioned.
    Operators(BTreeSet<AccountId>),
}

impl<AccountId: Ord> OperatorAllowList<AccountId> {
    /// Returns true if the allow list is either `Anyone` or the operator is part of the allowed operator list.
    pub fn is_operator_allowed(&self, operator: &AccountId) -> bool {
        match self {
            OperatorAllowList::Anyone => true,
            OperatorAllowList::Operators(allowed_operators) => allowed_operators.contains(operator),
        }
    }
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisDomain<AccountId: Ord> {
    // Domain runtime items
    pub runtime_name: String,
    pub runtime_type: RuntimeType,
    pub runtime_version: RuntimeVersion,
    pub raw_genesis_storage: Vec<u8>,

    // Domain config items
    pub owner_account_id: AccountId,
    pub domain_name: String,
    pub max_block_size: u32,
    pub max_block_weight: Weight,
    pub bundle_slot_probability: (u64, u64),
    pub target_bundles_per_block: u32,
    pub operator_allow_list: OperatorAllowList<AccountId>,

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

/// EVM chain Id storage key.
///
/// This and next function should ideally use Host function to fetch the storage key
/// from the domain runtime. But since the Host function is not available at Genesis, we have to
/// assume the storage keys.
/// TODO: once the chain is launched in mainnet, we should use the Host function for all domain instances.  
pub(crate) fn evm_chain_id_storage_key() -> StorageKey {
    StorageKey(
        frame_support::storage::storage_prefix(
            // This is the name used for the `pallet_evm_chain_id` in the `construct_runtime` macro
            // i.e. `EVMChainId: pallet_evm_chain_id = 82,`
            "EVMChainId".as_bytes(),
            // This is the storage item name used inside the `pallet_evm_chain_id`
            "ChainId".as_bytes(),
        )
        .to_vec(),
    )
}

/// The storage key of the `SelfDomainId` storage item in the `pallet-domain-id`
///
/// Any change to the storage item name or the `pallet-domain-id` name used in the `construct_runtime`
/// macro must be reflected here.
pub fn self_domain_id_storage_key() -> StorageKey {
    StorageKey(
        frame_support::storage::storage_prefix(
            // This is the name used for the `pallet-domain-id` in the `construct_runtime` macro
            // i.e. `SelfDomainId: pallet_domain_id = 90`
            "SelfDomainId".as_bytes(),
            // This is the storage item name used inside the `pallet-domain-id`
            "SelfDomainId".as_bytes(),
        )
        .to_vec(),
    )
}

/// `DomainInstanceData` is used to construct the genesis storage of domain instance chain
#[derive(PartialEq, Eq, Clone, Encode, Decode, TypeInfo)]
pub struct DomainInstanceData {
    pub runtime_type: RuntimeType,
    pub raw_genesis: RawGenesis,
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

/// Bundle invalidity type
///
/// Each type contains the index of the first invalid extrinsic within the bundle
#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
pub enum InvalidBundleType {
    /// Failed to decode the opaque extrinsic.
    UndecodableTx(u32),
    /// Transaction is out of the tx range.
    OutOfRangeTx(u32),
    /// Transaction is illegal (unable to pay the fee, etc).
    IllegalTx(u32),
    /// Transaction is an invalid XDM
    InvalidXDM(u32),
    /// Transaction is an inherent extrinsic.
    InherentExtrinsic(u32),
}

impl InvalidBundleType {
    // Return the checking order of the invalid type
    pub fn checking_order(&self) -> u8 {
        // Use explicit number as the order instead of the enum discriminant
        // to avoid changing the order accidentally
        match self {
            Self::UndecodableTx(_) => 1,
            Self::OutOfRangeTx(_) => 2,
            Self::InherentExtrinsic(_) => 3,
            Self::IllegalTx(_) => 4,
            Self::InvalidXDM(_) => 5,
        }
    }

    pub fn extrinsic_index(&self) -> u32 {
        match self {
            Self::UndecodableTx(i) => *i,
            Self::OutOfRangeTx(i) => *i,
            Self::IllegalTx(i) => *i,
            Self::InvalidXDM(i) => *i,
            Self::InherentExtrinsic(i) => *i,
        }
    }
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum BundleValidity<Hash> {
    // The invalid bundle was originally included in the consensus block but subsequently
    // excluded from execution as invalid and holds the `InvalidBundleType`
    Invalid(InvalidBundleType),
    // The valid bundle's hash of `Vec<(tx_signer, tx_hash)>` of all domain extrinsic being
    // included in the bundle.
    // TODO remove this and use host function to fetch above mentioned data
    Valid(Hash),
}

/// [`InboxedBundle`] represents a bundle that was successfully submitted to the consensus chain
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct InboxedBundle<Hash> {
    pub bundle: BundleValidity<Hash>,
    // TODO remove this as the root is already present in the `ExecutionInbox` storage
    pub extrinsics_root: Hash,
}

impl<Hash> InboxedBundle<Hash> {
    pub fn valid(bundle_digest_hash: Hash, extrinsics_root: Hash) -> Self {
        InboxedBundle {
            bundle: BundleValidity::Valid(bundle_digest_hash),
            extrinsics_root,
        }
    }

    pub fn invalid(invalid_bundle_type: InvalidBundleType, extrinsics_root: Hash) -> Self {
        InboxedBundle {
            bundle: BundleValidity::Invalid(invalid_bundle_type),
            extrinsics_root,
        }
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self.bundle, BundleValidity::Invalid(_))
    }

    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy(extrinsics_root: Hash) -> Self
    where
        Hash: Default,
    {
        InboxedBundle {
            bundle: BundleValidity::Valid(Hash::default()),
            extrinsics_root,
        }
    }
}

/// Empty extrinsics root.
pub const EMPTY_EXTRINSIC_ROOT: ExtrinsicsRoot = ExtrinsicsRoot {
    0: hex!("03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314"),
};

/// Zero operator signing key.
pub const ZERO_OPERATOR_SIGNING_KEY: sr25519::Public = sr25519::Public(hex!(
    "0000000000000000000000000000000000000000000000000000000000000000"
));

pub fn derive_domain_block_hash<DomainHeader: HeaderT>(
    domain_block_number: DomainHeader::Number,
    extrinsics_root: DomainHeader::Hash,
    state_root: DomainHeader::Hash,
    parent_domain_block_hash: DomainHeader::Hash,
    digest: Digest,
) -> DomainHeader::Hash {
    let domain_header = DomainHeader::new(
        domain_block_number,
        extrinsics_root,
        state_root,
        parent_domain_block_hash,
        digest,
    );

    domain_header.hash()
}

/// Represents the extrinsic either as full data or hash of the data.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub enum ExtrinsicDigest {
    /// Actual extrinsic data that is inlined since it is less than 33 bytes.
    Data(Vec<u8>),
    /// Extrinsic Hash.
    Hash(H256),
}

impl ExtrinsicDigest {
    pub fn new<Layout: TrieLayout>(ext: Vec<u8>) -> Self
    where
        Layout::Hash: HashT,
        <Layout::Hash as HashT>::Output: Into<H256>,
    {
        if let Some(threshold) = Layout::MAX_INLINE_VALUE {
            if ext.len() >= threshold as usize {
                ExtrinsicDigest::Hash(Layout::Hash::hash(&ext).into())
            } else {
                ExtrinsicDigest::Data(ext)
            }
        } else {
            ExtrinsicDigest::Data(ext)
        }
    }
}

pub type ExecutionReceiptFor<DomainHeader, CBlock, Balance> = ExecutionReceipt<
    NumberFor<CBlock>,
    <CBlock as BlockT>::Hash,
    <DomainHeader as HeaderT>::Number,
    <DomainHeader as HeaderT>::Hash,
    Balance,
>;

sp_api::decl_runtime_apis! {
    /// API necessary for domains pallet.
    pub trait DomainsApi<DomainHeader: HeaderT> {
        /// Submits the transaction bundle via an unsigned extrinsic.
        fn submit_bundle_unsigned(opaque_bundle: OpaqueBundle<NumberFor<Block>, Block::Hash, DomainHeader, Balance>);

        /// Extract the bundles stored successfully from the given extrinsics.
        fn extract_successful_bundles(
            domain_id: DomainId,
            extrinsics: Vec<Block::Extrinsic>,
        ) -> OpaqueBundles<Block, DomainHeader, Balance>;

        /// Extract bundle from the extrinsic if the extrinsic is `submit_bundle`.
        fn extract_bundle(extrinsic: Block::Extrinsic) -> Option<OpaqueBundle<NumberFor<Block>, Block::Hash, DomainHeader, Balance>>;

        /// Extract the execution receipt stored successfully from the given extrinsics.
        fn extract_receipts(
            domain_id: DomainId,
            extrinsics: Vec<Block::Extrinsic>,
        ) -> Vec<ExecutionReceiptFor<DomainHeader, Block, Balance>>;

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
        fn head_receipt_number(domain_id: DomainId) -> HeaderNumberFor<DomainHeader>;

        /// Returns the block number of oldest execution receipt.
        fn oldest_receipt_number(domain_id: DomainId) -> HeaderNumberFor<DomainHeader>;

        /// Returns the block tree pruning depth.
        fn block_tree_pruning_depth() -> HeaderNumberFor<DomainHeader>;

        /// Returns the domain block limit of the given domain.
        fn domain_block_limit(domain_id: DomainId) -> Option<DomainBlockLimit>;

        /// Returns true if there are any ERs in the challenge period with non empty extrinsics.
        fn non_empty_er_exists(domain_id: DomainId) -> bool;

        /// Returns the current best number of the domain.
        fn domain_best_number(domain_id: DomainId) -> Option<HeaderNumberFor<DomainHeader>>;

        /// Returns the chain state root at the given block.
        fn domain_state_root(
            domain_id: DomainId,
            number: HeaderNumberFor<DomainHeader>,
            hash: HeaderHashFor<DomainHeader>) -> Option<HeaderHashFor<DomainHeader>>;

        /// Returns the execution receipt
        fn execution_receipt(receipt_hash: HeaderHashFor<DomainHeader>) -> Option<ExecutionReceiptFor<DomainHeader, Block, Balance>>;

        /// Returns the current epoch and the next epoch operators of the given domain
        fn domain_operators(domain_id: DomainId) -> Option<(BTreeMap<OperatorId, Balance>, Vec<OperatorId>)>;

        /// Get operator id by signing key
        fn operator_id_by_signing_key(signing_key: OperatorPublicKey) -> Option<OperatorId>;

        /// Get the consensus chain sudo account id, currently only used in the intentional malicious operator
        fn sudo_account_id() -> subspace_runtime_primitives::AccountId;

        /// Returns the execution receipt hash of the given domain and domain block number
        fn receipt_hash(domain_id: DomainId, domain_number: HeaderNumberFor<DomainHeader>) -> Option<HeaderHashFor<DomainHeader>>;
    }

    pub trait BundleProducerElectionApi<Balance: Encode + Decode> {
        fn bundle_producer_election_params(domain_id: DomainId) -> Option<BundleProducerElectionParams<Balance>>;

        fn operator(operator_id: OperatorId) -> Option<(OperatorPublicKey, Balance)>;
    }
}
