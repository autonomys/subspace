#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::storage_proof::{self, *};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use frame_support::pallet_prelude::Zero;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_domain_digests::AsPredigest;
use sp_domains::ExtrinsicDigest;
use sp_domains::bundle::{BundleValidity, InvalidBundleType};
use sp_domains::execution_receipt::ExecutionReceiptFor;
use sp_domains::proof_provider_and_verifier::StorageProofVerifier;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use sp_runtime::{Digest, DigestItem};
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use sp_trie::StorageProof;

pub mod fraud_proof_v0;
pub mod fraud_proof_v1;

/// Mismatch type possible for ApplyExtrinsic execution phase
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum ApplyExtrinsicMismatch {
    StateRoot(u32),
    Shorter,
}

/// Mismatch type possible for FinalizBlock execution phase
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum FinalizeBlockMismatch {
    StateRoot,
    Longer(u32),
}

/// A phase of a block's execution, carrying necessary information needed for verifying the
/// invalid state transition proof.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum ExecutionPhase {
    /// Executes the `initialize_block` hook.
    InitializeBlock,
    /// Executes some extrinsic.
    ApplyExtrinsic {
        extrinsic_proof: StorageProof,
        mismatch: ApplyExtrinsicMismatch,
    },
    /// Executes the `finalize_block` hook.
    FinalizeBlock { mismatch: FinalizeBlockMismatch },
}

impl ExecutionPhase {
    /// Returns the method for generating the proof.
    pub fn execution_method(&self) -> &'static str {
        match self {
            // TODO: Replace `DomainCoreApi_initialize_block_with_post_state_root` with `Core_initalize_block`
            // Should be a same issue with https://github.com/paritytech/substrate/pull/10922#issuecomment-1068997467
            Self::InitializeBlock => "DomainCoreApi_initialize_block_with_post_state_root",
            Self::ApplyExtrinsic { .. } => "DomainCoreApi_apply_extrinsic_with_post_state_root",
            Self::FinalizeBlock { .. } => "BlockBuilder_finalize_block",
        }
    }

    /// Returns true if execution phase refers to mismatch between state roots
    /// false otherwise.
    pub fn is_state_root_mismatch(&self) -> bool {
        matches!(
            self,
            ExecutionPhase::InitializeBlock
                | ExecutionPhase::ApplyExtrinsic {
                    mismatch: ApplyExtrinsicMismatch::StateRoot(_),
                    extrinsic_proof: _,
                }
                | ExecutionPhase::FinalizeBlock {
                    mismatch: FinalizeBlockMismatch::StateRoot,
                }
        )
    }
    /// Returns the post state root for the given execution result.
    pub fn decode_execution_result<Header: HeaderT>(
        &self,
        execution_result: Vec<u8>,
    ) -> Result<Header::Hash, VerificationError<Header::Hash>> {
        match self {
            Self::InitializeBlock | Self::ApplyExtrinsic { .. } => {
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

    pub fn pre_post_state_root<CBlock, DomainHeader, Balance>(
        &self,
        bad_receipt: &ExecutionReceiptFor<DomainHeader, CBlock, Balance>,
        bad_receipt_parent: &ExecutionReceiptFor<DomainHeader, CBlock, Balance>,
    ) -> Result<(H256, H256), VerificationError<DomainHeader::Hash>>
    where
        CBlock: BlockT,
        DomainHeader: HeaderT,
        DomainHeader::Hash: Into<H256>,
        Balance: Encode + Zero + Default,
    {
        if bad_receipt.execution_traces().len() < 2 {
            return Err(VerificationError::InvalidExecutionTrace);
        }
        let (pre, post) = match self {
            ExecutionPhase::InitializeBlock => (
                *bad_receipt_parent.final_state_root(),
                bad_receipt.execution_traces()[0],
            ),
            ExecutionPhase::ApplyExtrinsic {
                mismatch: ApplyExtrinsicMismatch::StateRoot(mismatch_index),
                ..
            } => {
                if *mismatch_index == 0
                    || *mismatch_index >= bad_receipt.execution_traces().len() as u32 - 1
                {
                    return Err(VerificationError::InvalidApplyExtrinsicTraceIndex);
                }
                (
                    bad_receipt.execution_traces()[*mismatch_index as usize - 1],
                    bad_receipt.execution_traces()[*mismatch_index as usize],
                )
            }
            ExecutionPhase::ApplyExtrinsic {
                mismatch: ApplyExtrinsicMismatch::Shorter,
                ..
            } => {
                let mismatch_index = bad_receipt.execution_traces().len() - 1;
                (
                    bad_receipt.execution_traces()[mismatch_index - 1],
                    bad_receipt.execution_traces()[mismatch_index],
                )
            }
            ExecutionPhase::FinalizeBlock {
                mismatch: FinalizeBlockMismatch::StateRoot,
            } => {
                let mismatch_index = bad_receipt.execution_traces().len() - 1;
                (
                    bad_receipt.execution_traces()[mismatch_index - 1],
                    bad_receipt.execution_traces()[mismatch_index],
                )
            }
            ExecutionPhase::FinalizeBlock {
                mismatch: FinalizeBlockMismatch::Longer(mismatch_index),
            } => {
                if *mismatch_index == 0
                    || *mismatch_index >= bad_receipt.execution_traces().len() as u32 - 1
                {
                    return Err(VerificationError::InvalidLongerMismatchTraceIndex);
                }
                (
                    bad_receipt.execution_traces()[(*mismatch_index - 1) as usize],
                    bad_receipt.execution_traces()[*mismatch_index as usize],
                )
            }
        };
        Ok((pre.into(), post.into()))
    }

    pub fn call_data<CBlock, DomainHeader, Balance>(
        &self,
        bad_receipt: &ExecutionReceiptFor<DomainHeader, CBlock, Balance>,
        bad_receipt_parent: &ExecutionReceiptFor<DomainHeader, CBlock, Balance>,
    ) -> Result<Vec<u8>, VerificationError<DomainHeader::Hash>>
    where
        CBlock: BlockT,
        DomainHeader: HeaderT,
        Balance: Encode + Zero + Default,
    {
        Ok(match self {
            ExecutionPhase::InitializeBlock => {
                let inherent_digests = Digest {
                    logs: sp_std::vec![DigestItem::consensus_block_info(
                        bad_receipt.consensus_block_hash(),
                    )],
                };

                let new_header = DomainHeader::new(
                    *bad_receipt.domain_block_number(),
                    Default::default(),
                    Default::default(),
                    *bad_receipt_parent.domain_block_hash(),
                    inherent_digests,
                );
                new_header.encode()
            }
            ExecutionPhase::ApplyExtrinsic {
                extrinsic_proof: proof_of_inclusion,
                mismatch,
            } => {
                let mismatch_index = match mismatch {
                    ApplyExtrinsicMismatch::StateRoot(mismatch_index) => *mismatch_index,
                    ApplyExtrinsicMismatch::Shorter => {
                        (bad_receipt.execution_traces().len() - 1) as u32
                    }
                };
                // There is a trace root of the `initialize_block` in the head of the trace so we
                // need to minus one to get the correct `extrinsic_index`
                let extrinsic_index: u32 = mismatch_index - 1;

                let storage_key =
                    StorageProofVerifier::<DomainHeader::Hashing>::enumerated_storage_key(
                        extrinsic_index,
                    );

                StorageProofVerifier::<DomainHeader::Hashing>::get_bare_value(
                    bad_receipt.domain_block_extrinsics_root(),
                    proof_of_inclusion.clone(),
                    storage_key,
                )
                .map_err(|_| VerificationError::InvalidApplyExtrinsicCallData)?
            }
            ExecutionPhase::FinalizeBlock { .. } => Vec::new(),
        })
    }
}

/// Error type of fraud proof verification on consensus node.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError<DomainHash> {
    /// Failed to pass the execution proof check.
    #[error("Failed to pass the execution proof check")]
    BadExecutionProof,
    /// The fraud proof prove nothing invalid
    #[error("The fraud proof prove nothing invalid")]
    InvalidProof,
    /// Failed to decode the return value of `initialize_block` and `apply_extrinsic`.
    #[error("Failed to decode the return value of `initialize_block` and `apply_extrinsic`: {0}")]
    InitializeBlockOrApplyExtrinsicDecode(parity_scale_codec::Error),
    /// Failed to decode the storage root produced by verifying `initialize_block` or `apply_extrinsic`.
    #[error(
        "Failed to decode the storage root from verifying `initialize_block` and `apply_extrinsic`: {0}"
    )]
    StorageRootDecode(parity_scale_codec::Error),
    /// Failed to decode the header produced by `finalize_block`.
    #[error("Failed to decode the header from verifying `finalize_block`: {0}")]
    HeaderDecode(parity_scale_codec::Error),
    #[error("The receipt's execution_traces have less than 2 traces")]
    InvalidExecutionTrace,
    #[error("Invalid ApplyExtrinsic trace index")]
    InvalidApplyExtrinsicTraceIndex,
    #[error("Invalid longer mismatch trace index")]
    InvalidLongerMismatchTraceIndex,
    #[error("Invalid ApplyExtrinsic call data")]
    InvalidApplyExtrinsicCallData,
    /// Invalid bundle digest
    #[error("Invalid Bundle Digest")]
    InvalidBundleDigest,
    /// Bundle with requested index not found in execution receipt
    #[error("Bundle with requested index not found in execution receipt")]
    BundleNotFound,
    /// Invalid bundle entry in bad receipt was expected to be valid but instead found invalid entry
    #[error(
        "Unexpected bundle entry at {bundle_index} in bad receipt found: \
        {targeted_entry_bundle:?} with fraud proof's type of proof: \
        {fraud_proof_invalid_type_of_proof:?}"
    )]
    UnexpectedTargetedBundleEntry {
        bundle_index: u32,
        fraud_proof_invalid_type_of_proof: InvalidBundleType,
        targeted_entry_bundle: BundleValidity<DomainHash>,
    },
    /// Failed to derive bundle digest
    #[error("Failed to derive bundle digest")]
    FailedToDeriveBundleDigest,
    /// The target valid bundle not found from the target bad receipt
    #[error("The target valid bundle not found from the target bad receipt")]
    TargetValidBundleNotFound,
    /// Failed to check extrinsics in single context
    #[error("Failed to check extrinsics in single context")]
    FailedToCheckExtrinsicsInSingleContext,
    #[error(
        "Bad MMR proof, the proof is probably expired or is generated against a different fork"
    )]
    BadMmrProof,
    #[error("Unexpected MMR proof")]
    UnexpectedMmrProof,
    #[error("Failed to verify storage proof")]
    StorageProof(storage_proof::VerificationError),
    /// Failed to derive domain inherent extrinsic
    #[error("Failed to derive domain inherent extrinsic")]
    FailedToDeriveDomainInherentExtrinsic,
    /// Failed to derive domain storage key
    #[error("Failed to derive domain storage key")]
    FailedToGetDomainStorageKey,
    /// Unexpected invalid bundle proof data
    #[error("Unexpected invalid bundle proof data")]
    UnexpectedInvalidBundleProofData,
    /// Extrinsic with requested index not found in bundle
    #[error("Extrinsic with requested index not found in bundle")]
    ExtrinsicNotFound,
    /// Failed to get domain runtime call response
    #[error("Failed to get domain runtime call response")]
    FailedToGetDomainRuntimeCallResponse,
    /// Failed to get bundle weight
    #[error("Failed to get bundle weight")]
    FailedToGetBundleWeight,
    #[error("Failed to extract xdm mmr proof")]
    FailedToGetExtractXdmMmrProof,
    #[error("Failed to decode xdm mmr proof")]
    FailedToDecodeXdmMmrProof,
}

impl<DomainHash> From<storage_proof::VerificationError> for VerificationError<DomainHash> {
    fn from(err: storage_proof::VerificationError) -> Self {
        Self::StorageProof(err)
    }
}

/// Represents a valid bundle index and all the extrinsics within that bundle.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct ValidBundleDigest {
    /// Index of this bundle in the original list of bundles in the consensus block.
    pub bundle_index: u32,
    /// `Vec<(tx_signer, tx_hash)>` of all extrinsics
    pub bundle_digest: Vec<(
        Option<domain_runtime_primitives::opaque::AccountId>,
        ExtrinsicDigest,
    )>,
}

// Domain runtime code at a specific block
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct DomainRuntimeCodeAt<Number, Hash, MmrHash> {
    pub mmr_proof: ConsensusChainMmrLeafProof<Number, Hash, MmrHash>,
    pub domain_runtime_code_proof: DomainRuntimeCodeProof,
}

/// Proves an invalid state transition by challenging the trace at specific index in a bad receipt.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct InvalidStateTransitionProof {
    /// Proof recorded during the computation.
    pub execution_proof: StorageProof,
    /// Execution phase.
    pub execution_phase: ExecutionPhase,
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidExtrinsicsRootProof {
    /// Valid Bundle digests
    pub valid_bundle_digests: Vec<ValidBundleDigest>,

    /// The combined storage proofs used during verification
    pub invalid_inherent_extrinsic_proofs: InvalidInherentExtrinsicDataProof,

    /// A single domain runtime code upgrade (or "not upgraded") storage proof
    pub maybe_domain_runtime_upgraded_proof: MaybeDomainRuntimeUpgradedProof,

    /// Storage proof for a change to the chains that are allowed to open a channel with each domain
    pub domain_chain_allowlist_proof: DomainChainsAllowlistUpdateStorageProof,

    /// Optional sudo extrinsic call storage proof
    pub domain_sudo_call_proof: DomainSudoCallStorageProof,

    /// Optional EVM domain "set contract creation allowed by" extrinsic call storage proof
    pub evm_domain_contract_creation_allowed_by_call_proof:
        EvmDomainContractCreationAllowedByCallStorageProof,
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct MmrRootProof<Number, Hash, MmrHash> {
    pub mmr_proof: ConsensusChainMmrLeafProof<Number, Hash, MmrHash>,
    pub mmr_root_storage_proof: MmrRootStorageProof<MmrHash>,
}

/// Represents an invalid block fees proof.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidBlockFeesProof {
    /// Storage witness needed for verifying this proof.
    pub storage_proof: StorageProof,
}

/// Represents an invalid transfers proof.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidTransfersProof {
    /// Storage witness needed for verifying this proof.
    pub storage_proof: StorageProof,
}

/// Represents an invalid domain block hash fraud proof.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidDomainBlockHashProof {
    /// Digests storage proof that is used to derive Domain block hash.
    pub digest_storage_proof: StorageProof,
}
