use crate::{BundleHeader, DomainId};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_consensus_slots::Slot;
use sp_core::H256;
use sp_runtime::traits::{BlakeTwo256, Hash as HashT, Header as HeaderT};
use sp_std::vec::Vec;
use sp_trie::StorageProof;
use subspace_core_primitives::BlockNumber;
use subspace_runtime_primitives::AccountId;

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
            // TODO: Replace `DomainCoreApi_initialize_block_with_post_state_root` with `Core_initalize_block`
            // Should be a same issue with https://github.com/paritytech/substrate/pull/10922#issuecomment-1068997467
            Self::InitializeBlock { .. } => "DomainCoreApi_initialize_block_with_post_state_root",
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
            Self::InitializeBlock { .. } => "DomainCoreApi_initialize_block_with_post_state_root",
            Self::ApplyExtrinsic { .. } => "DomainCoreApi_apply_extrinsic_with_post_state_root",
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
    /// The id of the domain this fraud proof targetted
    pub domain_id: DomainId,
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
