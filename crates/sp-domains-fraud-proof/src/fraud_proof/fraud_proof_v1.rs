#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::fraud_proof::fraud_proof_v0::{
    InvalidBundlesV0Proof, InvalidBundlesV0ProofData, ValidBundleV0Proof,
};
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
use sp_domains::bundle::{InvalidBundleType, OpaqueBundle};
use sp_domains::{DomainId, HeaderHashFor, HeaderHashingFor};
use sp_runtime::traits::{Hash as HashT, Header as HeaderT};
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use sp_trie::StorageProof;
use subspace_runtime_primitives::Balance;

/// A V1 version of Fraud proof.
#[derive(Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct FraudProofV1<Number, Hash, DomainHeader: HeaderT, MmrHash> {
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
    pub proof: FraudProofVariantV1<Number, Hash, MmrHash, DomainHeader>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum FraudProofVariantV1<Number, Hash, MmrHash, DomainHeader: HeaderT> {
    #[codec(index = 0)]
    InvalidStateTransition(InvalidStateTransitionProof),
    #[codec(index = 1)]
    ValidBundle(ValidBundleProof<Number, Hash, DomainHeader>),
    #[codec(index = 2)]
    InvalidExtrinsicsRoot(InvalidExtrinsicsRootProof),
    #[codec(index = 3)]
    InvalidBundles(InvalidBundlesProof<Number, Hash, MmrHash, DomainHeader>),
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
    FraudProofV1<Number, Hash, DomainHeader, MmrHash>
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
            && matches!(self.proof, FraudProofVariantV1::InvalidDomainBlockHash(_))
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
            FraudProofVariantV1::InvalidExtrinsicsRoot(_)
                | FraudProofVariantV1::InvalidBundles(_)
                | FraudProofVariantV1::ValidBundle(_)
        )
    }

    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy_fraud_proof(
        domain_id: DomainId,
        bad_receipt_hash: HeaderHashFor<DomainHeader>,
    ) -> FraudProofV1<Number, Hash, DomainHeader, MmrHash> {
        Self {
            domain_id,
            bad_receipt_hash,
            maybe_mmr_proof: None,
            maybe_domain_runtime_code_proof: None,
            proof: FraudProofVariantV1::Dummy,
        }
    }
}

impl<Number, Hash, MmrHash, DomainHeader: HeaderT> FraudProofV1<Number, Hash, DomainHeader, MmrHash>
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
    for FraudProofV1<Number, Hash, DomainHeader, MmrHash>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fp_target =
            scale_info::prelude::format!("{:?}#{:?}", self.domain_id, self.bad_receipt_hash);
        match &self.proof {
            FraudProofVariantV1::InvalidStateTransition(_) => {
                write!(f, "InvalidStateTransitionFraudProof({fp_target})")
            }
            FraudProofVariantV1::InvalidExtrinsicsRoot(_) => {
                write!(f, "InvalidExtrinsicsRootFraudProof({fp_target})")
            }
            FraudProofVariantV1::InvalidBlockFees(_) => {
                write!(f, "InvalidBlockFeesFraudProof({fp_target})")
            }
            FraudProofVariantV1::ValidBundle(_) => {
                write!(f, "ValidBundleFraudProof({fp_target})")
            }
            FraudProofVariantV1::InvalidBundles(proof) => {
                write!(
                    f,
                    "InvalidBundlesFraudProof(type: {:?}, target: {fp_target})",
                    proof.invalid_bundle_type()
                )
            }
            FraudProofVariantV1::InvalidDomainBlockHash(_) => {
                write!(f, "InvalidDomainBlockHashFraudProof({fp_target})")
            }
            FraudProofVariantV1::InvalidTransfers(_) => {
                write!(f, "InvalidTransfersFraudProof({fp_target})")
            }
            #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
            FraudProofVariantV1::Dummy => {
                write!(f, "DummyFraudProof({fp_target})")
            }
        }
    }
}

/// Proof for bundle.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub enum ValidBundleProof<Number, Hash, DomainHeader: HeaderT> {
    /// V0 version of bundle and its proof
    V0(ValidBundleV0Proof<Number, Hash, DomainHeader>),
    /// Versioned bundle and its proof
    Versioned(ValidVersionedBundleProof<Number, Hash, DomainHeader>),
}

impl<Number, Hash, DomainHeader: HeaderT> ValidBundleProof<Number, Hash, DomainHeader> {
    pub fn set_bundle_index(&mut self, index: u32) {
        match self {
            ValidBundleProof::V0(proof) => proof.bundle_with_proof.bundle_index = index,
            ValidBundleProof::Versioned(proof) => proof.bundle_with_proof.bundle_index = index,
        }
    }
}

/// Fraud proof for the valid bundles in `ExecutionReceipt::inboxed_bundles`
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct ValidVersionedBundleProof<Number, Hash, DomainHeader: HeaderT> {
    /// The targeted bundle with proof
    pub bundle_with_proof: VersionedOpaqueBundleWithProof<Number, Hash, DomainHeader, Balance>,
}

/// An invalid bundle proof.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum InvalidBundlesProof<Number, Hash, MmrHash, DomainHeader: HeaderT> {
    /// For V0 bundle.
    V0(InvalidBundlesV0Proof<Number, Hash, MmrHash, DomainHeader>),
    /// For versioned bundle.
    Versioned(InvalidVersionedBundlesProof<Number, Hash, MmrHash, DomainHeader>),
}

impl<Number, Hash, MmrHash, DomainHeader: HeaderT>
    InvalidBundlesProof<Number, Hash, MmrHash, DomainHeader>
{
    pub fn invalid_bundle_type(&self) -> InvalidBundleType {
        match self {
            InvalidBundlesProof::V0(proof) => proof.invalid_bundle_type.clone(),
            InvalidBundlesProof::Versioned(proof) => proof.invalid_bundle_type.clone(),
        }
    }

    pub fn is_good_invalid_fraud_proof(&self) -> bool {
        match self {
            InvalidBundlesProof::V0(proof) => proof.is_good_invalid_fraud_proof,
            InvalidBundlesProof::Versioned(proof) => proof.is_good_invalid_fraud_proof,
        }
    }

    pub fn v1_proof_data(
        &self,
    ) -> Option<&InvalidBundlesProofData<Number, Hash, MmrHash, DomainHeader>> {
        match self {
            InvalidBundlesProof::V0(_) => None,
            InvalidBundlesProof::Versioned(proof) => Some(&proof.proof_data),
        }
    }
}

/// Invalid versioned bundle proof data.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum InvalidBundlesProofData<Number, Hash, MmrHash, DomainHeader: HeaderT> {
    Extrinsic(StorageProof),
    Bundle(VersionedOpaqueBundleWithProof<Number, Hash, DomainHeader, Balance>),
    BundleAndExecution {
        bundle_with_proof: VersionedOpaqueBundleWithProof<Number, Hash, DomainHeader, Balance>,
        execution_proof: StorageProof,
    },
    InvalidXDMProofData {
        extrinsic_proof: StorageProof,
        mmr_root_proof: Option<MmrRootProof<Number, Hash, MmrHash>>,
    },
}

/// A proof about a bundle that was marked invalid (but might or might not actually be invalid).
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct InvalidVersionedBundlesProof<Number, Hash, MmrHash, DomainHeader: HeaderT> {
    pub bundle_index: u32,
    /// The invalid bundle type that the bundle was marked with.
    pub invalid_bundle_type: InvalidBundleType,
    /// If `true`, the fraud proof must prove the bundle was correctly marked invalid.
    /// If `false`, it must prove the bundle was marked invalid, but is actually valid.
    pub is_good_invalid_fraud_proof: bool,
    /// Proof data of the bundle which was marked invalid.
    pub proof_data: InvalidBundlesProofData<Number, Hash, MmrHash, DomainHeader>,
}

impl<Number, Hash, MmrHash, DomainHeader: HeaderT>
    From<InvalidBundlesV0ProofData<Number, Hash, MmrHash, DomainHeader>>
    for InvalidBundlesProofData<Number, Hash, MmrHash, DomainHeader>
{
    fn from(value: InvalidBundlesV0ProofData<Number, Hash, MmrHash, DomainHeader>) -> Self {
        match value {
            InvalidBundlesV0ProofData::Extrinsic(proof) => {
                InvalidBundlesProofData::Extrinsic(proof)
            }
            InvalidBundlesV0ProofData::Bundle(bundle_with_proof) => {
                InvalidBundlesProofData::Bundle(VersionedOpaqueBundleWithProof {
                    bundle: OpaqueBundle::V1(bundle_with_proof.bundle.into()),
                    bundle_index: bundle_with_proof.bundle_index,
                    bundle_storage_proof: bundle_with_proof.bundle_storage_proof,
                })
            }
            InvalidBundlesV0ProofData::BundleAndExecution {
                bundle_with_proof,
                execution_proof,
            } => InvalidBundlesProofData::BundleAndExecution {
                bundle_with_proof: VersionedOpaqueBundleWithProof {
                    bundle: OpaqueBundle::V1(bundle_with_proof.bundle.into()),
                    bundle_index: bundle_with_proof.bundle_index,
                    bundle_storage_proof: bundle_with_proof.bundle_storage_proof,
                },
                execution_proof,
            },
            InvalidBundlesV0ProofData::InvalidXDMProofData {
                extrinsic_proof,
                mmr_root_proof,
            } => InvalidBundlesProofData::InvalidXDMProofData {
                extrinsic_proof,
                mmr_root_proof,
            },
        }
    }
}
