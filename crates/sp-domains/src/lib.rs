//! Primitives for domains pallet.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod bundle;
pub mod bundle_producer_election;
pub mod core_api;
pub mod execution_receipt;
pub mod extrinsics;
pub mod merkle_tree;
pub mod proof_provider_and_verifier;
pub mod storage;
#[cfg(test)]
mod tests;
pub mod valued_trie;

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bundle::{BundleVersion, OpaqueBundle, OpaqueBundles};
use crate::execution_receipt::ExecutionReceiptVersion;
use crate::storage::{RawGenesis, StorageKey};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bundle_producer_election::{BundleProducerElectionParams, ProofOfElectionError};
use core::num::ParseIntError;
use core::ops::{Add, Sub};
use core::str::FromStr;
use domain_runtime_primitives::{EVMChainId, EthereumAccountId, MultiAccountId};
use execution_receipt::{ExecutionReceiptFor, SealedSingletonReceipt};
use frame_support::storage::storage_prefix;
use frame_support::{Blake2_128Concat, StorageHasher};
use hex_literal::hex;
use parity_scale_codec::{Codec, Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_core::H256;
use sp_core::crypto::KeyTypeId;
use sp_core::sr25519::vrf::VrfSignature;
#[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
use sp_core::sr25519::vrf::{VrfPreOutput, VrfProof};
use sp_runtime::generic::OpaqueDigestItemId;
use sp_runtime::traits::{CheckedAdd, Hash as HashT, Header as HeaderT, NumberFor};
use sp_runtime::{Digest, DigestItem, Percent};
use sp_runtime_interface::pass_by;
use sp_runtime_interface::pass_by::PassBy;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::fmt::{Display, Formatter};
use sp_trie::TrieLayout;
use sp_version::RuntimeVersion;
use sp_weights::Weight;
#[cfg(feature = "std")]
use std::collections::BTreeSet;
use subspace_core_primitives::hashes::{Blake3Hash, blake3_hash};
use subspace_core_primitives::pot::PotOutput;
use subspace_core_primitives::solutions::bidirectional_distance;
use subspace_core_primitives::{Randomness, U256};
use subspace_runtime_primitives::{Balance, Moment};

/// Key type for Operator.
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"oper");

/// Extrinsics shuffling seed
pub const DOMAIN_EXTRINSICS_SHUFFLING_SEED_SUBJECT: &[u8] = b"extrinsics-shuffling-seed";

mod app {
    use super::KEY_TYPE;
    use sp_application_crypto::{app_crypto, sr25519};

    app_crypto!(sr25519, KEY_TYPE);
}

// TODO: this runtime constant is not support to update, see https://github.com/autonomys/subspace/issues/2712
// for more detail about the problem and what we need to do to support it.
//
// The domain storage fee multiplier used to charge a higher storage fee to the domain
// transaction to even out the duplicated/illegal domain transaction storage cost, which
// can not be eliminated right now.
pub const DOMAIN_STORAGE_FEE_MULTIPLIER: Balance = 3;

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

impl FromStr for DomainId {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u32>().map(Into::into)
    }
}

impl Add<DomainId> for DomainId {
    type Output = Self;

    fn add(self, other: DomainId) -> Self {
        Self(self.0 + other.0)
    }
}

impl Sub<DomainId> for DomainId {
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

/// Identifier of a chain.
#[derive(
    Clone,
    Copy,
    Debug,
    Hash,
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
pub enum ChainId {
    Consensus,
    Domain(DomainId),
}

impl ChainId {
    #[inline]
    pub fn consensus_chain_id() -> Self {
        Self::Consensus
    }

    #[inline]
    pub fn is_consensus_chain(&self) -> bool {
        match self {
            ChainId::Consensus => true,
            ChainId::Domain(_) => false,
        }
    }

    #[inline]
    pub fn maybe_domain_chain(&self) -> Option<DomainId> {
        match self {
            ChainId::Consensus => None,
            ChainId::Domain(domain_id) => Some(*domain_id),
        }
    }
}

impl From<u32> for ChainId {
    #[inline]
    fn from(x: u32) -> Self {
        Self::Domain(DomainId::new(x))
    }
}

impl From<DomainId> for ChainId {
    #[inline]
    fn from(x: DomainId) -> Self {
        Self::Domain(x)
    }
}

// TODO: this runtime constant is not support to update, see https://github.com/autonomys/subspace/issues/2712
// for more detail about the problem and what we need to do to support it.
//
/// Initial tx range = U256::MAX / INITIAL_DOMAIN_TX_RANGE.
pub const INITIAL_DOMAIN_TX_RANGE: u64 = 3;

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct ProofOfElection {
    /// Domain id.
    pub domain_id: DomainId,
    /// The slot number.
    pub slot_number: u64,
    /// The PoT output for `slot_number`.
    pub proof_of_time: PotOutput,
    /// VRF signature.
    pub vrf_signature: VrfSignature,
    /// Operator index in the OperatorRegistry.
    pub operator_id: OperatorId,
}

impl ProofOfElection {
    pub fn verify_vrf_signature(
        &self,
        operator_signing_key: &OperatorPublicKey,
    ) -> Result<(), ProofOfElectionError> {
        let global_challenge = self
            .proof_of_time
            .derive_global_randomness()
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
        let mut bytes = self.vrf_signature.pre_output.encode();
        bytes.append(&mut self.vrf_signature.proof.encode());
        blake3_hash(&bytes)
    }

    pub fn slot_number(&self) -> u64 {
        self.slot_number
    }
}

impl ProofOfElection {
    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy(domain_id: DomainId, operator_id: OperatorId) -> Self {
        let output_bytes = sp_std::vec![0u8; VrfPreOutput::max_encoded_len()];
        let proof_bytes = sp_std::vec![0u8; VrfProof::max_encoded_len()];
        let vrf_signature = VrfSignature {
            pre_output: VrfPreOutput::decode(&mut output_bytes.as_slice()).unwrap(),
            proof: VrfProof::decode(&mut proof_bytes.as_slice()).unwrap(),
        };
        Self {
            domain_id,
            slot_number: 0u64,
            proof_of_time: PotOutput::default(),
            vrf_signature,
            operator_id,
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

/// Permissioned actions allowed by either specific accounts or anyone.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionedActionAllowedBy<AccountId: Codec + Clone> {
    Accounts(Vec<AccountId>),
    Anyone,
}

impl<AccountId: Codec + PartialEq + Clone> PermissionedActionAllowedBy<AccountId> {
    pub fn is_allowed(&self, who: &AccountId) -> bool {
        match self {
            PermissionedActionAllowedBy::Accounts(accounts) => accounts.contains(who),
            PermissionedActionAllowedBy::Anyone => true,
        }
    }

    pub fn is_anyone_allowed(&self) -> bool {
        matches!(self, PermissionedActionAllowedBy::Anyone)
    }
}

/// EVM-specific domain type (and associated data).
#[derive(
    TypeInfo, Debug, Default, Encode, Decode, Clone, PartialEq, Eq, Serialize, Deserialize,
)]
pub enum EvmType {
    #[default]
    /// An EVM domain where any account can create contracts.
    Public,
    /// An EVM domain with a contract creation allow list.
    Private {
        /// Accounts initially allowed to create contracts on a private EVM domain.
        /// The domain owner can update this list using a pallet-domains call (or there's a sudo call).
        initial_contract_creation_allow_list: PermissionedActionAllowedBy<EthereumAccountId>,
    },
}

impl EvmType {
    /// Returns the initial contract creation allow list, or `None` if this is a public EVM domain.
    pub fn initial_contract_creation_allow_list(
        &self,
    ) -> Option<&PermissionedActionAllowedBy<EthereumAccountId>> {
        match self {
            EvmType::Public => None,
            EvmType::Private {
                initial_contract_creation_allow_list,
            } => Some(initial_contract_creation_allow_list),
        }
    }

    /// Returns true if the EVM domain is public.
    pub fn is_public_evm_domain(&self) -> bool {
        matches!(self, EvmType::Public)
    }

    /// Returns true if the EVM domain is private.
    pub fn is_private_evm_domain(&self) -> bool {
        matches!(self, EvmType::Private { .. })
    }
}

/// EVM-specific domain runtime config.
#[derive(
    TypeInfo, Debug, Default, Encode, Decode, Clone, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct EvmDomainRuntimeConfig {
    pub evm_type: EvmType,
}

/// AutoId-specific domain runtime config.
#[derive(
    TypeInfo, Debug, Default, Encode, Decode, Clone, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct AutoIdDomainRuntimeConfig {
    // Currently, there is no specific configuration for AutoId.
}

/// Domain runtime specific information to create domain raw genesis.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainRuntimeInfo {
    Evm {
        /// The EVM chain id for this domain.
        chain_id: EVMChainId,
        /// The EVM-specific domain runtime config.
        domain_runtime_config: EvmDomainRuntimeConfig,
    },
    AutoId {
        /// The AutoId-specific domain runtime config.
        domain_runtime_config: AutoIdDomainRuntimeConfig,
    },
}

impl From<(EVMChainId, EvmDomainRuntimeConfig)> for DomainRuntimeInfo {
    fn from(v: (EVMChainId, EvmDomainRuntimeConfig)) -> Self {
        DomainRuntimeInfo::Evm {
            chain_id: v.0,
            domain_runtime_config: v.1,
        }
    }
}

impl From<AutoIdDomainRuntimeConfig> for DomainRuntimeInfo {
    fn from(auto_id_config: AutoIdDomainRuntimeConfig) -> Self {
        DomainRuntimeInfo::AutoId {
            domain_runtime_config: auto_id_config,
        }
    }
}

impl DomainRuntimeInfo {
    pub fn evm(&self) -> Option<&EvmDomainRuntimeConfig> {
        match self {
            DomainRuntimeInfo::Evm {
                domain_runtime_config,
                ..
            } => Some(domain_runtime_config),
            _ => None,
        }
    }

    pub fn initial_contract_creation_allow_list(
        &self,
    ) -> Option<&PermissionedActionAllowedBy<EthereumAccountId>> {
        self.evm()
            .and_then(|evm_config| evm_config.evm_type.initial_contract_creation_allow_list())
    }

    pub fn auto_id(&self) -> Option<&AutoIdDomainRuntimeConfig> {
        match self {
            DomainRuntimeInfo::AutoId {
                domain_runtime_config,
            } => Some(domain_runtime_config),
            _ => None,
        }
    }

    /// If this is an EVM runtime, returns the chain id.
    pub fn evm_chain_id(&self) -> Option<EVMChainId> {
        match self {
            Self::Evm { chain_id, .. } => Some(*chain_id),
            _ => None,
        }
    }

    pub fn is_evm_domain(&self) -> bool {
        matches!(self, Self::Evm { .. })
    }

    /// Returns true if the domain is configured as a private EVM domain.
    /// Returns false for public EVM domains and non-EVM domains.
    pub fn is_private_evm_domain(&self) -> bool {
        if let Self::Evm {
            domain_runtime_config,
            ..
        } = self
        {
            domain_runtime_config.evm_type.is_private_evm_domain()
        } else {
            false
        }
    }

    pub fn is_auto_id(&self) -> bool {
        matches!(self, Self::AutoId { .. })
    }
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisDomain<AccountId: Ord, Balance> {
    // Domain runtime items
    pub runtime_name: String,
    pub runtime_type: RuntimeType,
    pub runtime_version: RuntimeVersion,
    pub raw_genesis_storage: Vec<u8>,

    // Domain config items
    pub owner_account_id: AccountId,
    pub domain_name: String,
    pub bundle_slot_probability: (u64, u64),
    pub operator_allow_list: OperatorAllowList<AccountId>,
    /// Configurations for a specific type of domain runtime, for example, EVM.
    pub domain_runtime_info: DomainRuntimeInfo,

    // Genesis operator
    pub signing_key: OperatorPublicKey,
    pub minimum_nominator_stake: Balance,
    pub nomination_tax: Percent,

    // initial balances
    pub initial_balances: Vec<(MultiAccountId, Balance)>,
}

/// Types of runtime pallet domains currently supports
#[derive(
    Debug, Default, Encode, Decode, TypeInfo, Copy, Clone, PartialEq, Eq, Serialize, Deserialize,
)]
pub enum RuntimeType {
    #[default]
    Evm,
    AutoId,
}

/// Type representing the runtime ID.
pub type RuntimeId = u32;

/// Type representing domain epoch.
pub type EpochIndex = u32;

/// Type representing operator ID
pub type OperatorId = u64;

/// Channel identity.
pub type ChannelId = sp_core::U256;

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
/// This function should ideally use a Host function to fetch the storage key
/// from the domain runtime. But since the Host function is not available at Genesis, we have to
/// assume the storage keys.
/// TODO: once the chain is launched in mainnet, we should use the Host function for all domain instances.
pub(crate) fn evm_chain_id_storage_key() -> StorageKey {
    StorageKey(
        storage_prefix(
            // This is the name used for `pallet_evm_chain_id` in the `construct_runtime` macro
            // i.e. `EVMChainId: pallet_evm_chain_id = 82,`
            "EVMChainId".as_bytes(),
            // This is the storage item name used inside `pallet_evm_chain_id`
            "ChainId".as_bytes(),
        )
        .to_vec(),
    )
}

/// EVM contract creation allow list storage key.
///
/// This function should ideally use a Host function to fetch the storage key
/// from the domain runtime. But since the Host function is not available at Genesis, we have to
/// assume the storage keys.
/// TODO: once the chain is launched in mainnet, we should use the Host function for all domain instances.
pub(crate) fn evm_contract_creation_allowed_by_storage_key() -> StorageKey {
    StorageKey(
        storage_prefix(
            // This is the name used for `pallet_evm_tracker` in the `construct_runtime` macro
            // i.e. `EVMNoncetracker: pallet_evm_tracker = 84,`
            "EVMNoncetracker".as_bytes(),
            // This is the storage item name used inside `pallet_evm_tracker`
            "ContractCreationAllowedBy".as_bytes(),
        )
        .to_vec(),
    )
}

/// Total issuance storage key for Domains.
///
/// This function should ideally use a Host function to fetch the storage key
/// from the domain runtime. But since the Host function is not available at Genesis, we have to
/// assume the storage keys.
/// TODO: once the chain is launched in mainnet, we should use the Host function for all domain instances.
pub fn domain_total_issuance_storage_key() -> StorageKey {
    StorageKey(
        storage_prefix(
            // This is the name used for `pallet_balances` in the `construct_runtime` macro
            "Balances".as_bytes(),
            // This is the storage item name used inside `pallet_balances`
            "TotalIssuance".as_bytes(),
        )
        .to_vec(),
    )
}

/// Account info on frame_system on Domains
///
/// This function should ideally use a Host function to fetch the storage key
/// from the domain runtime. But since the Host function is not available at Genesis, we have to
/// assume the storage keys.
/// TODO: once the chain is launched in mainnet, we should use the Host function for all domain instances.
pub fn domain_account_storage_key<AccountId: Encode>(who: AccountId) -> StorageKey {
    let storage_prefix = storage_prefix("System".as_bytes(), "Account".as_bytes());
    let key_hashed = who.using_encoded(Blake2_128Concat::hash);

    let mut final_key = Vec::with_capacity(storage_prefix.len() + key_hashed.len());

    final_key.extend_from_slice(&storage_prefix);
    final_key.extend_from_slice(key_hashed.as_ref());

    StorageKey(final_key)
}

/// The storage key of the `SelfDomainId` storage item in `pallet-domain-id`
///
/// Any change to the storage item name or `pallet-domain-id` name used in the `construct_runtime`
/// macro must be reflected here.
pub fn self_domain_id_storage_key() -> StorageKey {
    StorageKey(
        frame_support::storage::storage_prefix(
            // This is the name used for `pallet-domain-id` in the `construct_runtime` macro
            // i.e. `SelfDomainId: pallet_domain_id = 90`
            "SelfDomainId".as_bytes(),
            // This is the storage item name used inside `pallet-domain-id`
            "SelfDomainId".as_bytes(),
        )
        .to_vec(),
    )
}

/// `DomainInstanceData` is used to construct the genesis storage of domain instance chain
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode, TypeInfo)]
pub struct DomainInstanceData {
    pub runtime_type: RuntimeType,
    pub raw_genesis: RawGenesis,
}

#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
pub struct DomainBundleLimit {
    /// The max bundle size for the domain.
    pub max_bundle_size: u32,
    /// The max bundle weight for the domain.
    pub max_bundle_weight: Weight,
}

/// Calculates the max bundle weight and size
// See https://forum.subspace.network/t/on-bundle-weight-limits-sum/2277 for more details
// about the formula
pub fn calculate_max_bundle_weight_and_size(
    max_domain_block_size: u32,
    max_domain_block_weight: Weight,
    consensus_slot_probability: (u64, u64),
    bundle_slot_probability: (u64, u64),
) -> Option<DomainBundleLimit> {
    // (n1 / d1) / (n2 / d2) is equal to (n1 * d2) / (d1 * n2)
    // This represents: bundle_slot_probability/SLOT_PROBABILITY
    let expected_bundles_per_block = bundle_slot_probability
        .0
        .checked_mul(consensus_slot_probability.1)?
        .checked_div(
            bundle_slot_probability
                .1
                .checked_mul(consensus_slot_probability.0)?,
        )?;

    // set the proof size for bundle to be proof size of max domain weight
    // so that each domain extrinsic can use the full proof size if required
    let max_proof_size = max_domain_block_weight.proof_size();
    let max_bundle_weight = max_domain_block_weight
        .checked_div(expected_bundles_per_block)?
        .set_proof_size(max_proof_size);

    let max_bundle_size =
        (max_domain_block_size as u64).checked_div(expected_bundles_per_block)? as u32;

    Some(DomainBundleLimit {
        max_bundle_size,
        max_bundle_weight,
    })
}

/// Checks if the signer Id hash is within the tx range
pub fn signer_in_tx_range(bundle_vrf_hash: &U256, signer_id_hash: &U256, tx_range: &U256) -> bool {
    let distance_from_vrf_hash = bidirectional_distance(bundle_vrf_hash, signer_id_hash);
    distance_from_vrf_hash <= (*tx_range / 2)
}

/// Receipt invalidity type.
#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
pub enum InvalidReceipt {
    /// The field `invalid_bundles` in [`ExecutionReceiptFor`] is invalid.
    InvalidBundles,
}

#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
pub enum ReceiptValidity {
    Valid,
    Invalid(InvalidReceipt),
}

/// Empty extrinsics root.
pub const EMPTY_EXTRINSIC_ROOT: ExtrinsicsRoot = ExtrinsicsRoot {
    0: hex!("03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314"),
};

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

/// Trait that tracks the balances on Domains.
pub trait DomainsTransfersTracker<Balance> {
    type Error;

    /// Initializes the domain balance
    fn initialize_domain_balance(domain_id: DomainId, amount: Balance) -> Result<(), Self::Error>;

    /// Notes a transfer between chains.
    /// Balance on from_chain_id is reduced if it is a domain chain
    fn note_transfer(
        from_chain_id: ChainId,
        to_chain_id: ChainId,
        amount: Balance,
    ) -> Result<(), Self::Error>;

    /// Confirms a transfer between chains.
    fn confirm_transfer(
        from_chain_id: ChainId,
        to_chain_id: ChainId,
        amount: Balance,
    ) -> Result<(), Self::Error>;

    /// Claims a rejected transfer between chains.
    fn claim_rejected_transfer(
        from_chain_id: ChainId,
        to_chain_id: ChainId,
        amount: Balance,
    ) -> Result<(), Self::Error>;

    /// Rejects a initiated transfer between chains.
    fn reject_transfer(
        from_chain_id: ChainId,
        to_chain_id: ChainId,
        amount: Balance,
    ) -> Result<(), Self::Error>;

    /// Reduces a given amount from the domain balance
    fn reduce_domain_balance(domain_id: DomainId, amount: Balance) -> Result<(), Self::Error>;
}

/// Trait to check domain owner.
pub trait DomainOwner<AccountId> {
    /// Returns true if the account is the domain owner.
    fn is_domain_owner(domain_id: DomainId, acc: AccountId) -> bool;
}

impl<AccountId> DomainOwner<AccountId> for () {
    fn is_domain_owner(_domain_id: DomainId, _acc: AccountId) -> bool {
        false
    }
}

/// Post hook to know if the domain had bundle submitted in the previous block.
pub trait DomainBundleSubmitted {
    /// Called in the next block initialisation if there was a domain bundle in the previous block.
    /// This hook if called for domain represents that there is a new domain block for parent consensus block.
    fn domain_bundle_submitted(domain_id: DomainId);
}

impl DomainBundleSubmitted for () {
    fn domain_bundle_submitted(_domain_id: DomainId) {}
}

/// A hook to call after a domain is instantiated
pub trait OnDomainInstantiated {
    fn on_domain_instantiated(domain_id: DomainId);
}

impl OnDomainInstantiated for () {
    fn on_domain_instantiated(_domain_id: DomainId) {}
}

/// Domain chains allowlist updates.
#[derive(Default, Debug, Encode, Decode, PartialEq, Eq, Clone, TypeInfo)]
pub struct DomainAllowlistUpdates {
    /// Chains that are allowed to open a channel with this chain.
    pub allow_chains: BTreeSet<ChainId>,
    /// Chains that are not allowed to open a channel with this chain.
    pub remove_chains: BTreeSet<ChainId>,
}

impl DomainAllowlistUpdates {
    pub fn is_empty(&self) -> bool {
        self.allow_chains.is_empty() && self.remove_chains.is_empty()
    }

    pub fn clear(&mut self) {
        self.allow_chains.clear();
        self.remove_chains.clear();
    }
}

/// Domain Sudo runtime call.
///
/// This structure exists because we need to generate a storage proof for FP
/// and Storage shouldn't be None. So each domain must always hold this value even if
/// there is an empty runtime call inside
#[derive(Default, Debug, Encode, Decode, PartialEq, Eq, Clone, TypeInfo)]
pub struct DomainSudoCall {
    pub maybe_call: Option<Vec<u8>>,
}

impl DomainSudoCall {
    pub fn clear(&mut self) {
        self.maybe_call.take();
    }
}

/// EVM Domain "update contract creation allowed by" runtime call.
///
/// This structure exists because we need to generate a storage proof for FP
/// and Storage shouldn't be None. So each domain must always hold this value even if
/// there is an empty runtime call inside
#[derive(Default, Debug, Encode, Decode, PartialEq, Eq, Clone, TypeInfo)]
pub struct EvmDomainContractCreationAllowedByCall {
    pub maybe_call: Option<PermissionedActionAllowedBy<EthereumAccountId>>,
}

impl EvmDomainContractCreationAllowedByCall {
    pub fn clear(&mut self) {
        self.maybe_call.take();
    }
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct RuntimeObject<Number, Hash> {
    pub runtime_name: String,
    pub runtime_type: RuntimeType,
    pub runtime_upgrades: u32,
    pub instance_count: u32,
    pub hash: Hash,
    // The raw genesis storage that contains the runtime code.
    // NOTE: don't use this field directly but `into_complete_raw_genesis` instead
    pub raw_genesis: RawGenesis,
    pub version: RuntimeVersion,
    pub created_at: Number,
    pub updated_at: Number,
}

/// Digest storage key in frame_system.
/// Unfortunately, the digest storage is private and not possible to derive the key from it directly.
pub fn system_digest_final_key() -> Vec<u8> {
    frame_support::storage::storage_prefix("System".as_ref(), "Digest".as_ref()).to_vec()
}

/// Hook to handle chain rewards.
pub trait OnChainRewards<Balance> {
    fn on_chain_rewards(chain_id: ChainId, reward: Balance);
}

impl<Balance> OnChainRewards<Balance> for () {
    fn on_chain_rewards(_chain_id: ChainId, _reward: Balance) {}
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum OperatorRewardSource<Number> {
    Bundle {
        at_block_number: Number,
    },
    XDMProtocolFees,
    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    Dummy,
}

/// Bundle and Execution Versions.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, Copy)]
pub struct BundleAndExecutionReceiptVersion {
    pub bundle_version: BundleVersion,
    pub execution_receipt_version: ExecutionReceiptVersion,
}

/// Represents a nominator's storage fee deposit information
#[derive(Debug, Encode, Decode, TypeInfo, Clone, PartialEq, Eq)]
pub struct StorageFeeDeposit<Balance> {
    /// Original amount contributed to storage fees
    pub total_deposited: Balance,
    /// Current value adjusted for fund performance (gains/losses)
    pub current_value: Balance,
}

/// Represents a nominator's pending deposit that hasn't been converted to shares yet
#[derive(Debug, Encode, Decode, TypeInfo, Clone, PartialEq, Eq)]
pub struct PendingDeposit<Balance> {
    /// The amount of the pending deposit
    pub amount: Balance,
    /// The epoch when this deposit will become effective
    pub effective_epoch: EpochIndex,
}

/// Represents a nominator's pending withdrawal with unlock timing
#[derive(Debug, Encode, Decode, TypeInfo, Clone, PartialEq, Eq)]
pub struct PendingWithdrawal<Balance, DomainBlockNumber> {
    /// The amount of stake that will be withdrawn
    pub stake_withdrawal_amount: Balance,
    /// The amount of storage fee deposit that will be refunded
    pub storage_fee_refund: Balance,
    /// The domain block number when this withdrawal can be unlocked
    pub unlock_at_block: DomainBlockNumber,
}

/// Complete nominator position information for a specific operator
#[derive(Debug, Encode, Decode, TypeInfo, Clone, PartialEq, Eq)]
pub struct NominatorPosition<Balance, DomainBlockNumber, Share> {
    /// Current value of the nominator's position (shares converted to balance using current share price)
    pub current_staked_value: Balance,
    /// Total shares owned by nominator
    pub total_shares: Share,
    /// Storage fee deposit information (original and current adjusted values)
    pub storage_fee_deposit: StorageFeeDeposit<Balance>,
    /// Pending deposit not yet converted to shares
    pub pending_deposit: Option<PendingDeposit<Balance>>,
    /// Pending withdrawals with unlock timing
    pub pending_withdrawals: Vec<PendingWithdrawal<Balance, DomainBlockNumber>>,
}

sp_api::decl_runtime_apis! {
    /// APIs used to access the domains pallet.
    // When updating this version, document new APIs with "Only present in API versions" comments.
    #[api_version(6)]
    pub trait DomainsApi<DomainHeader: HeaderT> {
        /// Submits the transaction bundle via an unsigned extrinsic.
        fn submit_bundle_unsigned(opaque_bundle: OpaqueBundle<NumberFor<Block>, Block::Hash, DomainHeader, Balance>);

        /// Submits a singleton receipt via an unsigned extrinsic.
        fn submit_receipt_unsigned(singleton_receipt: SealedSingletonReceipt<NumberFor<Block>, Block::Hash, DomainHeader, Balance>);

        /// Extracts the bundles successfully stored from the given extrinsics.
        fn extract_successful_bundles(
            domain_id: DomainId,
            extrinsics: Vec<Block::Extrinsic>,
        ) -> OpaqueBundles<Block, DomainHeader, Balance>;

        /// Generates a randomness seed for extrinsics shuffling.
        fn extrinsics_shuffling_seed() -> Randomness;

        /// Returns the current WASM bundle for the given `domain_id`.
        fn domain_runtime_code(domain_id: DomainId) -> Option<Vec<u8>>;

        /// Returns the runtime id for the given `domain_id`.
        fn runtime_id(domain_id: DomainId) -> Option<RuntimeId>;

        /// Returns the list of runtime upgrades in the current block.
        fn runtime_upgrades() -> Vec<RuntimeId>;

        /// Returns the domain instance data for the given `domain_id`.
        fn domain_instance_data(domain_id: DomainId) -> Option<(DomainInstanceData, NumberFor<Block>)>;

        /// Returns the current timestamp at the current height.
        fn domain_timestamp() -> Moment;

        /// Returns the consensus transaction byte fee that will used to charge the domain
        /// transaction for consensus chain storage fees.
        fn consensus_transaction_byte_fee() -> Balance;

        /// Returns the current Tx range for the given domain Id.
        fn domain_tx_range(domain_id: DomainId) -> U256;

        /// Returns the genesis state root if not pruned.
        fn genesis_state_root(domain_id: DomainId) -> Option<H256>;

        /// Returns the best execution chain number.
        fn head_receipt_number(domain_id: DomainId) -> HeaderNumberFor<DomainHeader>;

        /// Returns the block number of oldest unconfirmed execution receipt.
        fn oldest_unconfirmed_receipt_number(domain_id: DomainId) -> Option<HeaderNumberFor<DomainHeader>>;

        /// Returns the domain bundle limit of the given domain.
        fn domain_bundle_limit(domain_id: DomainId) -> Option<DomainBundleLimit>;

        /// Returns true if there are any ERs in the challenge period with non empty extrinsics.
        fn non_empty_er_exists(domain_id: DomainId) -> bool;

        /// Returns the current best block number for the domain.
        fn domain_best_number(domain_id: DomainId) -> Option<HeaderNumberFor<DomainHeader>>;

        /// Returns the execution receipt with the given hash.
        fn execution_receipt(receipt_hash: HeaderHashFor<DomainHeader>) -> Option<ExecutionReceiptFor<DomainHeader, Block, Balance>>;

        /// Returns the current epoch and the next epoch operators of the given domain.
        fn domain_operators(domain_id: DomainId) -> Option<(BTreeMap<OperatorId, Balance>, Vec<OperatorId>)>;

        /// Returns the execution receipt hash of the given domain and domain block number.
        fn receipt_hash(domain_id: DomainId, domain_number: HeaderNumberFor<DomainHeader>) -> Option<HeaderHashFor<DomainHeader>>;

        /// Returns the latest confirmed domain block number and hash.
        fn latest_confirmed_domain_block(domain_id: DomainId) -> Option<(HeaderNumberFor<DomainHeader>, HeaderHashFor<DomainHeader>)>;

        /// Returns true if the receipt exists and is going to be pruned
        fn is_bad_er_pending_to_prune(domain_id: DomainId, receipt_hash: HeaderHashFor<DomainHeader>) -> bool;

        /// Returns the balance of the storage fund account.
        fn storage_fund_account_balance(operator_id: OperatorId) -> Balance;

        /// Returns true if the given domain's runtime code has been upgraded since `at`.
        fn is_domain_runtime_upgraded_since(domain_id: DomainId, at: NumberFor<Block>) -> Option<bool>;

        /// Returns the domain sudo call for the given domain, if any.
        fn domain_sudo_call(domain_id: DomainId) -> Option<Vec<u8>>;

        /// Returns the "set contract creation allowed by" call for the given EVM domain, if any.
        fn evm_domain_contract_creation_allowed_by_call(domain_id: DomainId) -> Option<PermissionedActionAllowedBy<EthereumAccountId>>;

        /// Returns the last confirmed domain block execution receipt.
        fn last_confirmed_domain_block_receipt(domain_id: DomainId) -> Option<ExecutionReceiptFor<DomainHeader, Block, Balance>>;

        /// Returns the current bundle version that is accepted by runtime.
        fn current_bundle_and_execution_receipt_version() -> BundleAndExecutionReceiptVersion;

        /// Returns genesis execution receipt for domains.
        fn genesis_execution_receipt(domain_id: DomainId) -> Option<ExecutionReceiptFor<DomainHeader, Block, Balance>>;

        /// Returns the complete nominator position for a given operator and account.
        ///
        /// This calculates the total position including:
        /// - Current stake value (converted from shares using current share price)
        /// - Total storage fee deposits (known + pending)
        /// - Pending deposits (not yet converted to shares)
        /// - Pending withdrawals (with unlock timing)
        ///
        fn nominator_position(
            operator_id: OperatorId,
            nominator_account: sp_runtime::AccountId32,
        ) -> Option<NominatorPosition<Balance, HeaderNumberFor<DomainHeader>, Balance>>;

        /// Returns the block pruning depth for domains
        /// Available from Api version 6.
        fn block_pruning_depth() -> NumberFor<Block>;
    }

    pub trait BundleProducerElectionApi<Balance: Encode + Decode> {
        fn bundle_producer_election_params(domain_id: DomainId) -> Option<BundleProducerElectionParams<Balance>>;

        fn operator(operator_id: OperatorId) -> Option<(OperatorPublicKey, Balance)>;
    }
}
