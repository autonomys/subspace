use crate::{DomainId, SealedBundleHeader};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_consensus_slots::Slot;
use sp_core::H256;
use sp_runtime::traits::{BlakeTwo256, Hash as HashT, Header as HeaderT};
use sp_std::vec::Vec;
use sp_trie::StorageProof;
use subspace_core_primitives::BlockNumber;
use subspace_runtime_primitives::AccountId;

/// A phase of a block's execution, carrying necessary information needed for verifying the
/// invalid state transition proof.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum ExecutionPhase {
    /// Executes the `initialize_block` hook.
    InitializeBlock { domain_parent_hash: H256 },
    /// Executes some extrinsic.
    ApplyExtrinsic(u32),
    /// Executes the `finalize_block` hook.
    FinalizeBlock { total_extrinsics: u32 },
}

impl ExecutionPhase {
    /// Returns the method for generating the proof.
    pub fn proving_method(&self) -> &'static str {
        match self {
            // TODO: Replace `DomainCoreApi_initialize_block_with_post_state_root` with `Core_initalize_block`
            // Should be a same issue with https://github.com/paritytech/substrate/pull/10922#issuecomment-1068997467
            Self::InitializeBlock { .. } => "DomainCoreApi_initialize_block_with_post_state_root",
            Self::ApplyExtrinsic(_) => "BlockBuilder_apply_extrinsic",
            Self::FinalizeBlock { .. } => "BlockBuilder_finalize_block",
        }
    }

    /// Returns the method for verifying the proof.
    ///
    /// The difference with [`Self::proving_method`] is that the return value of verifying method
    /// must contain the post state root info so that it can be used to compare whether the
    /// result of execution reported in [`FraudProof`] is expected or not.
    pub fn verifying_method(&self) -> &'static str {
        match self {
            Self::InitializeBlock { .. } => "DomainCoreApi_initialize_block_with_post_state_root",
            Self::ApplyExtrinsic(_) => "DomainCoreApi_apply_extrinsic_with_post_state_root",
            Self::FinalizeBlock { .. } => "BlockBuilder_finalize_block",
        }
    }

    /// Returns the post state root for the given execution result.
    pub fn decode_execution_result<Header: HeaderT>(
        &self,
        execution_result: Vec<u8>,
    ) -> Result<Header::Hash, VerificationError> {
        match self {
            Self::InitializeBlock { .. } | Self::ApplyExtrinsic(_) => {
                let encoded_storage_root = Vec::<u8>::decode(&mut execution_result.as_slice())
                    .map_err(VerificationError::InitializeBlockOrApplyExtrinsicDecode)?;
                Header::Hash::decode(&mut encoded_storage_root.as_slice())
                    .map_err(VerificationError::StorageRootDecode)
            }
            Self::FinalizeBlock { .. } => {
                let new_header = Header::decode(&mut execution_result.as_slice())
                    .map_err(VerificationError::HeaderDecode)?;
                Ok(*new_header.state_root())
            }
        }
    }
}

/// Error type of fraud proof verification on consensus node.
#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum VerificationError {
    /// `pre_state_root` in the invalid state transition proof is invalid.
    #[cfg_attr(feature = "thiserror", error("invalid `pre_state_root`"))]
    InvalidPreStateRoot,
    /// Hash of the consensus block being challenged not found.
    #[cfg_attr(feature = "thiserror", error("consensus block hash not found"))]
    ConsensusBlockHashNotFound,
    /// `post_state_root` not found in the state.
    #[cfg_attr(feature = "thiserror", error("`post_state_root` not found"))]
    PostStateRootNotFound,
    /// `post_state_root` is same as the one stored on chain.
    #[cfg_attr(
        feature = "thiserror",
        error("`post_state_root` is same as the one on chain")
    )]
    SamePostStateRoot,
    /// Domain extrinsic at given index not found.
    #[cfg_attr(
        feature = "thiserror",
        error("Domain extrinsic at index {0} not found")
    )]
    DomainExtrinsicNotFound(u32),
    /// Error occurred while building the domain extrinsics.
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to rebuild the domain extrinsic list")
    )]
    FailedToBuildDomainExtrinsics,
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
    /// Transaction validity check passes.
    #[cfg_attr(feature = "thiserror", error("Valid transaction"))]
    ValidTransaction,
    /// State not found in the storage proof.
    #[cfg_attr(
        feature = "thiserror",
        error("State under storage key ({0:?}) not found in the storage proof")
    )]
    StateNotFound(Vec<u8>),
    /// Decode error.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "thiserror", error("Decode error: {0}"))]
    Decode(#[from] parity_scale_codec::Error),
    /// Runtime api error.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "thiserror", error("Runtime api error: {0}"))]
    RuntimeApi(#[from] sp_api::ApiError),
    /// Runtime api error.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "thiserror", error("Client error: {0}"))]
    Client(#[from] sp_blockchain::Error),
    /// Invalid storage proof.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "thiserror", error("Invalid stroage proof"))]
    InvalidStorageProof,
    /// Can not find signer from the domain extrinsic.
    #[cfg_attr(
        feature = "thiserror",
        error("Can not find signer from the domain extrinsic")
    )]
    SignerNotFound,
    /// Domain state root not found.
    #[cfg_attr(feature = "thiserror", error("Domain state root not found"))]
    DomainStateRootNotFound,
    /// Fail to get runtime code.
    // The `String` here actually repersenting the `sc_executor_common::error::WasmError`
    // error, but it will be improper to use `WasmError` directly here since it will make
    // `sp-domain` (a runtime crate) depend on `sc_executor_common` (a client crate).
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "thiserror", error("Failed to get runtime code: {0}"))]
    RuntimeCode(String),
    #[cfg(feature = "std")]
    #[cfg_attr(
        feature = "thiserror",
        error("Oneshot error when verifying fraud proof in tx pool: {0}")
    )]
    Oneshot(String),
}

/// Fraud proof.
// TODO: Revisit when fraud proof v2 is implemented.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum FraudProof<Number, Hash> {
    InvalidStateTransition(InvalidStateTransitionProof),
    InvalidTransaction(InvalidTransactionProof),
    BundleEquivocation(BundleEquivocationProof<Number, Hash>),
    ImproperTransactionSortition(ImproperTransactionSortitionProof),
}

impl<Number, Hash> FraudProof<Number, Hash> {
    pub fn domain_id(&self) -> DomainId {
        match self {
            Self::InvalidStateTransition(proof) => proof.domain_id,
            Self::InvalidTransaction(proof) => proof.domain_id,
            Self::BundleEquivocation(proof) => proof.domain_id,
            Self::ImproperTransactionSortition(proof) => proof.domain_id,
        }
    }
}

impl<Number, Hash> FraudProof<Number, Hash>
where
    Number: Encode,
    Hash: Encode,
{
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash(&self.encode())
    }
}

/// Proves an invalid state transition by challenging the trace at specific index in a bad receipt.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct InvalidStateTransitionProof {
    /// The id of the domain this fraud proof targeted
    pub domain_id: DomainId,
    /// Hash of the bad receipt in which an invalid trace occurred.
    pub bad_receipt_hash: H256,
    /// Parent number.
    pub parent_number: BlockNumber,
    /// Hash of the consensus block corresponding to `parent_number`.
    ///
    /// Runtime code for the execution of the domain block that is being challenged
    /// is retrieved on top of the consensus parent block from the consensus chain.
    pub consensus_parent_hash: H256,
    /// State root before the fraudulent transaction.
    pub pre_state_root: H256,
    /// State root after the fraudulent transaction.
    pub post_state_root: H256,
    /// Proof recorded during the computation.
    pub proof: StorageProof,
    /// Execution phase.
    pub execution_phase: ExecutionPhase,
}

pub fn dummy_invalid_state_transition_proof(
    domain_id: DomainId,
    parent_number: u32,
) -> InvalidStateTransitionProof {
    InvalidStateTransitionProof {
        domain_id,
        bad_receipt_hash: H256::default(),
        parent_number,
        consensus_parent_hash: H256::default(),
        pre_state_root: H256::default(),
        post_state_root: H256::default(),
        proof: StorageProof::empty(),
        execution_phase: ExecutionPhase::ApplyExtrinsic(0),
    }
}

/// Represents a bundle equivocation proof. An equivocation happens when an executor
/// produces more than one bundle on the same slot. The proof of equivocation
/// are the given distinct bundle headers that were signed by the validator and which
/// include the slot number.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleEquivocationProof<Number, Hash> {
    /// The id of the domain this fraud proof targeted
    pub domain_id: DomainId,
    /// The authority id of the equivocator.
    pub offender: AccountId,
    /// The slot at which the equivocation happened.
    pub slot: Slot,
    // TODO: Make H256 a generic when bundle equivocation is implemented properly.
    /// The first header involved in the equivocation.
    pub first_header: SealedBundleHeader<Number, Hash, H256>,
    /// The second header involved in the equivocation.
    pub second_header: SealedBundleHeader<Number, Hash, H256>,
}

impl<Number: Clone + From<u32> + Encode, Hash: Clone + Default + Encode>
    BundleEquivocationProof<Number, Hash>
{
    /// Returns the hash of this bundle equivocation proof.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

/// Represents an invalid transaction proof.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidTransactionProof {
    /// The id of the domain this fraud proof targeted
    pub domain_id: DomainId,
    /// Number of the block at which the invalid transaction occurred.
    pub block_number: u32,
    /// Hash of the domain block corresponding to `block_number`.
    pub domain_block_hash: H256,
    // TODO: Verifiable invalid extrinsic.
    pub invalid_extrinsic: Vec<u8>,
    /// Storage witness needed for verifying this proof.
    pub storage_proof: StorageProof,
}

/// Represents an invalid transaction proof.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct ImproperTransactionSortitionProof {
    /// The id of the domain this fraud proof targeted
    pub domain_id: DomainId,
}
