use crate::verification::InvalidBundleEquivocationError;
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_consensus_slots::Slot;
use sp_core::H256;
use sp_domain_digests::AsPredigest;
use sp_domains::proof_provider_and_verifier::StorageProofVerifier;
use sp_domains::{
    BundleValidity, DomainId, ExecutionReceiptFor, ExtrinsicDigest, HeaderHashFor,
    HeaderHashingFor, InvalidBundleType, OperatorId, SealedBundleHeader,
};
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use sp_runtime::{Digest, DigestItem};
use sp_std::vec::Vec;
use sp_trie::StorageProof;
use subspace_runtime_primitives::Balance;

/// A phase of a block's execution, carrying necessary information needed for verifying the
/// invalid state transition proof.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum ExecutionPhase {
    /// Executes the `initialize_block` hook.
    InitializeBlock,
    /// Executes some extrinsic.
    ApplyExtrinsic {
        extrinsic_proof: StorageProof,
        mismatch_index: u32,
    },
    /// Executes the `finalize_block` hook.
    FinalizeBlock,
}

impl ExecutionPhase {
    /// Returns the method for generating the proof.
    pub fn proving_method(&self) -> &'static str {
        match self {
            // TODO: Replace `DomainCoreApi_initialize_block_with_post_state_root` with `Core_initalize_block`
            // Should be a same issue with https://github.com/paritytech/substrate/pull/10922#issuecomment-1068997467
            Self::InitializeBlock => "DomainCoreApi_initialize_block_with_post_state_root",
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
            Self::InitializeBlock => "DomainCoreApi_initialize_block_with_post_state_root",
            Self::ApplyExtrinsic { .. } => "DomainCoreApi_apply_extrinsic_with_post_state_root",
            Self::FinalizeBlock => "BlockBuilder_finalize_block",
        }
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
            Self::FinalizeBlock => {
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
    {
        if bad_receipt.execution_trace.len() < 2 {
            return Err(VerificationError::InvalidExecutionTrace);
        }
        let (pre, post) = match self {
            ExecutionPhase::InitializeBlock => (
                bad_receipt_parent.final_state_root,
                bad_receipt.execution_trace[0],
            ),
            ExecutionPhase::ApplyExtrinsic { mismatch_index, .. } => {
                if *mismatch_index == 0
                    || *mismatch_index >= bad_receipt.execution_trace.len() as u32 - 1
                {
                    return Err(VerificationError::InvalidApplyExtrinsicTraceIndex);
                }
                (
                    bad_receipt.execution_trace[*mismatch_index as usize - 1],
                    bad_receipt.execution_trace[*mismatch_index as usize],
                )
            }
            ExecutionPhase::FinalizeBlock => {
                let mismatch_index = bad_receipt.execution_trace.len() - 1;
                (
                    bad_receipt.execution_trace[mismatch_index - 1],
                    bad_receipt.execution_trace[mismatch_index],
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
    {
        Ok(match self {
            ExecutionPhase::InitializeBlock => {
                let inherent_digests = Digest {
                    logs: sp_std::vec![DigestItem::consensus_block_info(
                        bad_receipt.consensus_block_hash,
                    )],
                };

                let new_header = DomainHeader::new(
                    bad_receipt.domain_block_number,
                    Default::default(),
                    Default::default(),
                    bad_receipt_parent.domain_block_hash,
                    inherent_digests,
                );
                new_header.encode()
            }
            ExecutionPhase::ApplyExtrinsic {
                extrinsic_proof: proof_of_inclusion,
                mismatch_index,
            } => {
                // There is a trace root of the `initialize_block` in the head of the trace so we
                // need to minus one to get the correct `extrinsic_index`
                let extrinsic_index = *mismatch_index - 1;
                let storage_key =
                    StorageProofVerifier::<DomainHeader::Hashing>::enumerated_storage_key(
                        extrinsic_index,
                    );

                StorageProofVerifier::<DomainHeader::Hashing>::get_bare_value(
                    &bad_receipt.domain_block_extrinsic_root,
                    proof_of_inclusion.clone(),
                    storage_key,
                )
                .map_err(|_| VerificationError::InvalidApplyExtrinsicCallData)?
            }
            ExecutionPhase::FinalizeBlock => Vec::new(),
        })
    }
}

/// Error type of fraud proof verification on consensus node.
#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum VerificationError<DomainHash> {
    /// Hash of the consensus block being challenged not found.
    #[cfg_attr(feature = "thiserror", error("consensus block hash not found"))]
    ConsensusBlockHashNotFound,
    /// Failed to pass the execution proof check.
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to pass the execution proof check")
    )]
    BadExecutionProof,
    /// The fraud proof prove nothing invalid
    #[cfg_attr(feature = "thiserror", error("The fraud proof prove nothing invalid"))]
    InvalidProof,
    /// Failed to decode the return value of `initialize_block` and `apply_extrinsic`.
    #[cfg_attr(
        feature = "thiserror",
        error(
            "Failed to decode the return value of `initialize_block` and `apply_extrinsic`: {0}"
        )
    )]
    InitializeBlockOrApplyExtrinsicDecode(codec::Error),
    /// Failed to decode the storage root produced by verifying `initialize_block` or `apply_extrinsic`.
    #[cfg_attr(
        feature = "thiserror",
        error(
            "Failed to decode the storage root from verifying `initialize_block` and `apply_extrinsic`: {0}"
        )
    )]
    StorageRootDecode(codec::Error),
    /// Failed to decode the header produced by `finalize_block`.
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to decode the header from verifying `finalize_block`: {0}")
    )]
    HeaderDecode(codec::Error),
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
    Decode(#[from] codec::Error),
    /// Runtime api error.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "thiserror", error("Runtime api error: {0}"))]
    RuntimeApi(#[from] sp_api::ApiError),
    /// Runtime api error.
    #[cfg(feature = "std")]
    #[cfg_attr(feature = "thiserror", error("Client error: {0}"))]
    Client(#[from] sp_blockchain::Error),
    /// Invalid storage proof.
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
    #[cfg_attr(feature = "thiserror", error("Failed to get domain runtime code"))]
    FailedToGetDomainRuntimeCode,
    #[cfg(feature = "std")]
    #[cfg_attr(
        feature = "thiserror",
        error("Oneshot error when verifying fraud proof in tx pool: {0}")
    )]
    Oneshot(String),
    #[cfg_attr(
        feature = "thiserror",
        error("The receipt's execution_trace have less than 2 traces")
    )]
    InvalidExecutionTrace,
    #[cfg_attr(feature = "thiserror", error("Invalid ApplyExtrinsic trace index"))]
    InvalidApplyExtrinsicTraceIndex,
    #[cfg_attr(feature = "thiserror", error("Invalid ApplyExtrinsic call data"))]
    InvalidApplyExtrinsicCallData,
    /// Invalid bundle digest
    #[cfg_attr(feature = "thiserror", error("Invalid Bundle Digest"))]
    InvalidBundleDigest,
    /// Failed to get block randomness
    #[cfg_attr(feature = "thiserror", error("Failed to get block randomness"))]
    FailedToGetBlockRandomness,
    /// Failed to derive domain timestamp extrinsic
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to derive domain timestamp extrinsic")
    )]
    FailedToDeriveDomainTimestampExtrinsic,
    /// Failed to derive domain set code extrinsic
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to derive domain set code extrinsic")
    )]
    FailedToDeriveDomainSetCodeExtrinsic,
    /// Bundle with requested index not found in execution receipt
    #[cfg_attr(
        feature = "thiserror",
        error("Bundle with requested index not found in execution receipt")
    )]
    BundleNotFound,
    /// Invalid bundle entry in bad receipt was expected to be valid but instead found invalid entry
    #[cfg_attr(
        feature = "thiserror",
        error("Unexpected bundle entry at {bundle_index} in bad receipt found: {targeted_entry_bundle:?} with fraud proof's type of proof: {fraud_proof_invalid_type_of_proof:?}")
    )]
    UnexpectedTargetedBundleEntry {
        bundle_index: u32,
        fraud_proof_invalid_type_of_proof: InvalidBundleType,
        targeted_entry_bundle: BundleValidity<DomainHash>,
    },
    /// Tx range host function did not return response (returned None)
    #[cfg_attr(
        feature = "thiserror",
        error("Tx range host function did not return a response (returned None)")
    )]
    FailedToGetResponseFromTxRangeHostFn,
    /// Failed to get the bundle body
    #[cfg_attr(feature = "thiserror", error("Failed to get the bundle body"))]
    FailedToGetDomainBundleBody,
    /// Failed to derive bundle digest
    #[cfg_attr(feature = "thiserror", error("Failed to derive bundle digest"))]
    FailedToDeriveBundleDigest,
    /// The target valid bundle not found from the target bad receipt
    #[cfg_attr(
        feature = "thiserror",
        error("The target valid bundle not found from the target bad receipt")
    )]
    TargetValidBundleNotFound,
    /// Failed to check if a given extrinsic is inherent or not.
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to check if a given extrinsic is inherent or not")
    )]
    FailedToCheckInherentExtrinsic,
    /// Invalid bundle equivocation fraud proof.
    #[cfg_attr(
        feature = "thiserror",
        error("Invalid bundle equivocation fraud proof: {0}")
    )]
    InvalidBundleEquivocationFraudProof(InvalidBundleEquivocationError),
    /// Failed to check extrinsics in single context
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to check extrinsics in single context")
    )]
    FailedToCheckExtrinsicsInSingleContext,
}

impl<DomainHash> From<InvalidBundleEquivocationError> for VerificationError<DomainHash> {
    fn from(err: InvalidBundleEquivocationError) -> Self {
        Self::InvalidBundleEquivocationFraudProof(err)
    }
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct InvalidBundlesFraudProof<ReceiptHash> {
    pub bad_receipt_hash: ReceiptHash,
    pub domain_id: DomainId,
    pub bundle_index: u32,
    pub invalid_bundle_type: InvalidBundleType,
    pub proof_data: StorageProof,
    pub is_true_invalid_fraud_proof: bool,
}

impl<ReceiptHash> InvalidBundlesFraudProof<ReceiptHash> {
    pub fn new(
        bad_receipt_hash: ReceiptHash,
        domain_id: DomainId,
        bundle_index: u32,
        invalid_bundle_type: InvalidBundleType,
        proof_data: StorageProof,
        is_true_invalid_fraud_proof: bool,
    ) -> Self {
        Self {
            bad_receipt_hash,
            domain_id,
            bundle_index,
            invalid_bundle_type,
            proof_data,
            is_true_invalid_fraud_proof,
        }
    }
}

/// Fraud proof.
// TODO: Revisit when fraud proof v2 is implemented.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum FraudProof<Number, Hash, DomainHeader: HeaderT> {
    InvalidStateTransition(InvalidStateTransitionProof<HeaderHashFor<DomainHeader>>),
    InvalidTransaction(InvalidTransactionProof<HeaderHashFor<DomainHeader>>),
    BundleEquivocation(BundleEquivocationProof<Number, Hash, DomainHeader>),
    ImproperTransactionSortition(ImproperTransactionSortitionProof<HeaderHashFor<DomainHeader>>),
    InvalidTotalRewards(InvalidTotalRewardsProof<HeaderHashFor<DomainHeader>>),
    InvalidExtrinsicsRoot(InvalidExtrinsicsRootProof<HeaderHashFor<DomainHeader>>),
    ValidBundle(ValidBundleProof<HeaderHashFor<DomainHeader>>),
    InvalidDomainBlockHash(InvalidDomainBlockHashProof<HeaderHashFor<DomainHeader>>),
    InvalidBundles(InvalidBundlesFraudProof<HeaderHashFor<DomainHeader>>),
    // Dummy fraud proof only used in test and benchmark
    //
    // NOTE: the `Dummy` must be the last variant, because the `#[cfg(..)]` will apply to
    // all the variants after it.
    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    Dummy {
        /// Id of the domain this fraud proof targeted
        domain_id: DomainId,
        /// Hash of the bad receipt this fraud proof targeted
        bad_receipt_hash: HeaderHashFor<DomainHeader>,
    },
}

impl<Number, Hash, DomainHeader: HeaderT> FraudProof<Number, Hash, DomainHeader> {
    pub fn domain_id(&self) -> DomainId {
        match self {
            Self::InvalidStateTransition(proof) => proof.domain_id,
            Self::InvalidTransaction(proof) => proof.domain_id,
            Self::BundleEquivocation(proof) => proof.domain_id,
            Self::ImproperTransactionSortition(proof) => proof.domain_id,
            #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
            Self::Dummy { domain_id, .. } => *domain_id,
            Self::InvalidTotalRewards(proof) => proof.domain_id(),
            Self::InvalidExtrinsicsRoot(proof) => proof.domain_id,
            Self::InvalidBundles(proof) => proof.domain_id,
            Self::ValidBundle(proof) => proof.domain_id,
            Self::InvalidDomainBlockHash(proof) => proof.domain_id,
        }
    }

    pub fn targeted_bad_receipt_hash(&self) -> Option<HeaderHashFor<DomainHeader>> {
        match self {
            Self::InvalidStateTransition(proof) => Some(proof.bad_receipt_hash),
            Self::InvalidTransaction(proof) => Some(proof.bad_receipt_hash),
            Self::ImproperTransactionSortition(proof) => Some(proof.bad_receipt_hash),
            Self::BundleEquivocation(_) => None,
            #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
            Self::Dummy {
                bad_receipt_hash, ..
            } => Some(*bad_receipt_hash),
            Self::InvalidExtrinsicsRoot(proof) => Some(proof.bad_receipt_hash),
            Self::InvalidTotalRewards(proof) => Some(proof.bad_receipt_hash()),
            Self::ValidBundle(proof) => Some(proof.bad_receipt_hash),
            Self::InvalidBundles(proof) => Some(proof.bad_receipt_hash),
            Self::InvalidDomainBlockHash(proof) => Some(proof.bad_receipt_hash),
        }
    }

    pub fn targeted_bad_operator_and_slot_for_bundle_equivocation(
        &self,
    ) -> Option<(OperatorId, Slot)> {
        match self {
            Self::BundleEquivocation(proof) => Some((
                proof.first_header.header.proof_of_election.operator_id,
                proof.slot,
            )),
            _ => None,
        }
    }

    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy_fraud_proof(
        domain_id: DomainId,
        bad_receipt_hash: HeaderHashFor<DomainHeader>,
    ) -> FraudProof<Number, Hash, DomainHeader> {
        FraudProof::Dummy {
            domain_id,
            bad_receipt_hash,
        }
    }
}

impl<Number, Hash, DomainHeader: HeaderT> FraudProof<Number, Hash, DomainHeader>
where
    Number: Encode,
    Hash: Encode,
{
    pub fn hash(&self) -> HeaderHashFor<DomainHeader> {
        HeaderHashingFor::<DomainHeader>::hash(&self.encode())
    }
}

/// Proves an invalid state transition by challenging the trace at specific index in a bad receipt.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct InvalidStateTransitionProof<ReceiptHash> {
    /// The id of the domain this fraud proof targeted
    pub domain_id: DomainId,
    /// Hash of the bad receipt in which an invalid trace occurred.
    pub bad_receipt_hash: ReceiptHash,
    /// Proof recorded during the computation.
    pub proof: StorageProof,
    /// Execution phase.
    pub execution_phase: ExecutionPhase,
}

pub fn dummy_invalid_state_transition_proof<ReceiptHash: Default>(
    domain_id: DomainId,
) -> InvalidStateTransitionProof<ReceiptHash> {
    InvalidStateTransitionProof {
        domain_id,
        bad_receipt_hash: ReceiptHash::default(),
        proof: StorageProof::empty(),
        execution_phase: ExecutionPhase::FinalizeBlock,
    }
}

/// Represents a bundle equivocation proof. An equivocation happens when an executor
/// produces more than one bundle on the same slot. The proof of equivocation
/// are the given distinct bundle headers that were signed by the validator and which
/// include the slot number.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleEquivocationProof<Number, Hash, DomainHeader: HeaderT> {
    /// The id of the domain this fraud proof targeted
    pub domain_id: DomainId,
    /// The slot at which the equivocation happened.
    pub slot: Slot,
    // TODO: The generic type should be `<Number, Hash, DomainNumber, DomainHash, Balance>`
    // TODO: `SealedBundleHeader` contains `ExecutionReceipt` which make the size of the proof
    // large, revisit when proceeding to fraud proof v2.
    /// The first header involved in the equivocation.
    pub first_header: SealedBundleHeader<Number, Hash, DomainHeader, Balance>,
    /// The second header involved in the equivocation.
    pub second_header: SealedBundleHeader<Number, Hash, DomainHeader, Balance>,
}

impl<Number, Hash, DomainHeader> BundleEquivocationProof<Number, Hash, DomainHeader>
where
    Number: Clone + From<u32> + Encode,
    Hash: Clone + Default + Encode,
    DomainHeader: HeaderT,
{
    /// Returns the hash of this bundle equivocation proof.
    pub fn hash(&self) -> HeaderHashFor<DomainHeader> {
        HeaderHashingFor::<DomainHeader>::hash_of(self)
    }
}

/// Represents an invalid transaction proof.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidTransactionProof<DomainHash> {
    /// The id of the domain this fraud proof targeted
    pub domain_id: DomainId,
    /// Hash of the bad receipt this fraud proof targeted
    pub bad_receipt_hash: DomainHash,
    /// Number of the block at which the invalid transaction occurred.
    pub domain_block_number: u32,
    /// Hash of the domain block corresponding to `block_number`.
    pub domain_block_hash: DomainHash,
    // TODO: Verifiable invalid extrinsic.
    pub invalid_extrinsic: Vec<u8>,
    /// Storage witness needed for verifying this proof.
    pub storage_proof: StorageProof,
}

/// Represents an invalid transaction proof.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct ImproperTransactionSortitionProof<ReceiptHash> {
    /// The id of the domain this fraud proof targeted
    pub domain_id: DomainId,
    /// Hash of the bad receipt this fraud proof targeted
    pub bad_receipt_hash: ReceiptHash,
}

/// Represents an invalid total rewards proof.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidTotalRewardsProof<ReceiptHash> {
    /// The id of the domain this fraud proof targeted
    pub domain_id: DomainId,
    /// Hash of the bad receipt this fraud proof targeted
    pub bad_receipt_hash: ReceiptHash,
    /// Storage witness needed for verifying this proof.
    pub storage_proof: StorageProof,
}

/// Represents an invalid domain block hash fraud proof.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidDomainBlockHashProof<ReceiptHash> {
    /// The id of the domain this fraud proof targeted
    pub domain_id: DomainId,
    /// Hash of the bad receipt this fraud proof targeted
    pub bad_receipt_hash: ReceiptHash,
    /// Digests storage proof that is used to derive Domain block hash.
    pub digest_storage_proof: StorageProof,
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

/// Represents an Invalid domain extrinsics root proof with necessary info for verification.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidExtrinsicsRootProof<ReceiptHash> {
    /// The id of the domain this fraud proof targeted
    pub domain_id: DomainId,
    /// Hash of the bad receipt this fraud proof targeted
    pub bad_receipt_hash: ReceiptHash,
    /// Valid Bundle digests
    pub valid_bundle_digests: Vec<ValidBundleDigest>,
}

impl<ReceiptHash: Copy> InvalidTotalRewardsProof<ReceiptHash> {
    pub(crate) fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    pub(crate) fn bad_receipt_hash(&self) -> ReceiptHash {
        self.bad_receipt_hash
    }
}

//TODO: remove there key generations from here and instead use the fraud proof host function to fetch them

/// This is a representation of actual Block Rewards storage in pallet-operator-rewards.
/// Any change in key or value there should be changed here accordingly.
pub fn operator_block_rewards_final_key() -> Vec<u8> {
    frame_support::storage::storage_prefix("OperatorRewards".as_ref(), "BlockRewards".as_ref())
        .to_vec()
}

/// Fraud proof for the valid bundles in `ExecutionReceipt::inboxed_bundles`
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct ValidBundleProof<ReceiptHash> {
    /// The id of the domain this fraud proof targeted
    pub domain_id: DomainId,
    /// The targetted bad receipt
    pub bad_receipt_hash: ReceiptHash,
    /// The index of the targetted bundle
    pub bundle_index: u32,
}

/// Digest storage key in frame_system.
/// Unfortunately, the digest storage is private and not possible to derive the key from it directly.
pub fn system_digest_final_key() -> Vec<u8> {
    frame_support::storage::storage_prefix("System".as_ref(), "Digest".as_ref()).to_vec()
}
