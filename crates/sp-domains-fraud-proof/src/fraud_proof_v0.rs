#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::fraud_proof::{
    DomainRuntimeCodeAt, InvalidBlockFeesProof, InvalidDomainBlockHashProof,
    InvalidExtrinsicsRootProof, InvalidStateTransitionProof, InvalidTransfersProof, MmrRootProof,
};
use crate::storage_proof::*;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::fmt;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_domains::{DomainId, HeaderHashFor, HeaderHashingFor, InvalidBundleType};
use sp_runtime::traits::{Hash as HashT, Header as HeaderT};
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use sp_trie::StorageProof;
use subspace_runtime_primitives::Balance;

/// A V0 version of Fraud proof.
#[derive(Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct FraudProofV0<Number, Hash, DomainHeader: HeaderT, MmrHash> {
    pub domain_id: DomainId,
    /// Hash of the bad receipt this fraud proof targeted
    pub bad_receipt_hash: HeaderHashFor<DomainHeader>,
    /// The MMR proof for the consensus state root that is used to verify the storage proof
    ///
    /// It is set `None` if the specific fraud proof variant doesn't contain a storage proof
    pub maybe_mmr_proof: Option<ConsensusChainMmrLeafProof<Number, Hash, MmrHash>>,
    /// The domain runtime code storage proof
    ///
    /// It is set `None` if the specific fraud proof variant doesn't require domain runtime code
    /// or the required domain runtime code is available from the current runtime state.
    pub maybe_domain_runtime_code_proof: Option<DomainRuntimeCodeAt<Number, Hash, MmrHash>>,
    /// The specific fraud proof variant
    pub proof: FraudProofVariantV0<Number, Hash, MmrHash, DomainHeader>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum FraudProofVariantV0<Number, Hash, MmrHash, DomainHeader: HeaderT> {
    #[codec(index = 0)]
    InvalidStateTransition(InvalidStateTransitionProof),
    #[codec(index = 1)]
    ValidBundle(ValidBundleV0Proof<Number, Hash, DomainHeader>),
    #[codec(index = 2)]
    InvalidExtrinsicsRoot(InvalidExtrinsicsRootProof),
    #[codec(index = 3)]
    InvalidBundles(InvalidBundlesV0Proof<Number, Hash, MmrHash, DomainHeader>),
    #[codec(index = 4)]
    InvalidDomainBlockHash(InvalidDomainBlockHashProof),
    #[codec(index = 5)]
    InvalidBlockFees(InvalidBlockFeesProof),
    #[codec(index = 6)]
    InvalidTransfers(InvalidTransfersProof),
    /// Dummy fraud proof only used in tests and benchmarks
    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    #[codec(index = 100)]
    Dummy,
}

impl<Number, Hash, MmrHash, DomainHeader: HeaderT>
    FraudProofV0<Number, Hash, DomainHeader, MmrHash>
{
    pub fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    pub fn targeted_bad_receipt_hash(&self) -> HeaderHashFor<DomainHeader> {
        self.bad_receipt_hash
    }

    pub fn is_unexpected_domain_runtime_code_proof(&self) -> bool {
        // The invalid domain block hash fraud proof doesn't use the domain runtime code
        // during its verification so it is unexpected to see `maybe_domain_runtime_code_proof`
        // set to `Some`
        self.maybe_domain_runtime_code_proof.is_some()
            && matches!(self.proof, FraudProofVariantV0::InvalidDomainBlockHash(_))
    }

    pub fn is_unexpected_mmr_proof(&self) -> bool {
        if self.maybe_mmr_proof.is_none() {
            return false;
        }
        // Only the `InvalidExtrinsicsRoot`, `InvalidBundles` and `ValidBundle` fraud proof
        // are using the MMR proof during verifiction, for other fraud proofs it is unexpected
        // to see `maybe_mmr_proof` set to `Some`
        !matches!(
            self.proof,
            FraudProofVariantV0::InvalidExtrinsicsRoot(_)
                | FraudProofVariantV0::InvalidBundles(_)
                | FraudProofVariantV0::ValidBundle(_)
        )
    }

    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy_fraud_proof(
        domain_id: DomainId,
        bad_receipt_hash: HeaderHashFor<DomainHeader>,
    ) -> FraudProofV0<Number, Hash, DomainHeader, MmrHash> {
        Self {
            domain_id,
            bad_receipt_hash,
            maybe_mmr_proof: None,
            maybe_domain_runtime_code_proof: None,
            proof: FraudProofVariantV0::Dummy,
        }
    }
}

impl<Number, Hash, MmrHash, DomainHeader: HeaderT> FraudProofV0<Number, Hash, DomainHeader, MmrHash>
where
    Number: Encode,
    Hash: Encode,
    MmrHash: Encode,
{
    pub fn hash(&self) -> HeaderHashFor<DomainHeader> {
        HeaderHashingFor::<DomainHeader>::hash(&self.encode())
    }
}

impl<Number, Hash, MmrHash, DomainHeader: HeaderT> fmt::Debug
    for FraudProofV0<Number, Hash, DomainHeader, MmrHash>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fp_target =
            scale_info::prelude::format!("{:?}#{:?}", self.domain_id, self.bad_receipt_hash);
        match &self.proof {
            FraudProofVariantV0::InvalidStateTransition(_) => {
                write!(f, "InvalidStateTransitionFraudProof({fp_target})")
            }
            FraudProofVariantV0::InvalidExtrinsicsRoot(_) => {
                write!(f, "InvalidExtrinsicsRootFraudProof({fp_target})")
            }
            FraudProofVariantV0::InvalidBlockFees(_) => {
                write!(f, "InvalidBlockFeesFraudProof({fp_target})")
            }
            FraudProofVariantV0::ValidBundle(_) => {
                write!(f, "ValidBundleFraudProof({fp_target})")
            }
            FraudProofVariantV0::InvalidBundles(proof) => {
                write!(
                    f,
                    "InvalidBundlesFraudProof(type: {:?}, target: {fp_target})",
                    proof.invalid_bundle_type
                )
            }
            FraudProofVariantV0::InvalidDomainBlockHash(_) => {
                write!(f, "InvalidDomainBlockHashFraudProof({fp_target})")
            }
            FraudProofVariantV0::InvalidTransfers(_) => {
                write!(f, "InvalidTransfersFraudProof({fp_target})")
            }
            #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
            FraudProofVariantV0::Dummy => {
                write!(f, "DummyFraudProof({fp_target})")
            }
        }
    }
}

/// Fraud proof for the valid bundles in `ExecutionReceipt::inboxed_bundles`
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct ValidBundleV0Proof<Number, Hash, DomainHeader: HeaderT> {
    /// The targeted bundle with proof
    pub bundle_with_proof: OpaqueBundleV0WithProof<Number, Hash, DomainHeader, Balance>,
}

/// V0 Invalid bundles proof data.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum InvalidBundlesV0ProofData<Number, Hash, MmrHash, DomainHeader: HeaderT> {
    Extrinsic(StorageProof),
    Bundle(OpaqueBundleV0WithProof<Number, Hash, DomainHeader, Balance>),
    BundleAndExecution {
        bundle_with_proof: OpaqueBundleV0WithProof<Number, Hash, DomainHeader, Balance>,
        execution_proof: StorageProof,
    },
    InvalidXDMProofData {
        extrinsic_proof: StorageProof,
        mmr_root_proof: Option<MmrRootProof<Number, Hash, MmrHash>>,
    },
}

/// A proof about a bundle v0 that was marked invalid (but might or might not actually be invalid).
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct InvalidBundlesV0Proof<Number, Hash, MmrHash, DomainHeader: HeaderT> {
    pub bundle_index: u32,
    /// The invalid bundle type that the bundle was marked with.
    pub invalid_bundle_type: InvalidBundleType,
    /// If `true`, the fraud proof must prove the bundle was correctly marked invalid.
    /// If `false`, it must prove the bundle was marked invalid, but is actually valid.
    pub is_good_invalid_fraud_proof: bool,
    /// Proof data of the bundle which was marked invalid.
    pub proof_data: InvalidBundlesV0ProofData<Number, Hash, MmrHash, DomainHeader>,
}
