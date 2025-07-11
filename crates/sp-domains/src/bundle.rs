#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bundle::bundle_v0::SealedBundleHeaderV0;
use crate::bundle::bundle_v1::{BundleHeaderV1, SealedBundleHeaderV1};
use crate::execution_receipt::{ExecutionReceipt, ExecutionReceiptMutRef, ExecutionReceiptRef};
use crate::{
    DomainId, HeaderHashFor, HeaderNumberFor, OperatorId, OperatorSignature, ProofOfElection,
};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bundle_v0::BundleV0;
use bundle_v1::BundleV1;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::OpaqueExtrinsic;
use sp_runtime::traits::{BlakeTwo256, Hash, Header as HeaderT, NumberFor, Zero};
use sp_weights::Weight;
use subspace_runtime_primitives::BlockHashFor;

pub mod bundle_v0;
pub mod bundle_v1;

/// Header of bundle holding the references to various versions of SealedHeader.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum SealedBundleHeaderRef<'a, Number, Hash, DomainHeader: HeaderT, Balance> {
    V0(&'a SealedBundleHeaderV0<Number, Hash, DomainHeader, Balance>),
    V1(&'a SealedBundleHeaderV1<Number, Hash, DomainHeader, Balance>),
}

impl<'a, Number: Encode, Hash: Encode, DomainHeader: HeaderT, Balance: Encode>
    SealedBundleHeaderRef<'a, Number, Hash, DomainHeader, Balance>
{
    /// Returns the hash of the inner unsealed header.
    pub fn pre_hash(&self) -> HeaderHashFor<DomainHeader> {
        match self {
            SealedBundleHeaderRef::V0(bundle) => bundle.header.hash(),
            SealedBundleHeaderRef::V1(bundle) => bundle.header.hash(),
        }
    }

    /// Returns the signature on the sealed bundle header.
    pub fn signature(&self) -> &'a OperatorSignature {
        match self {
            SealedBundleHeaderRef::V0(bundle) => &bundle.signature,
            SealedBundleHeaderRef::V1(bundle) => &bundle.signature,
        }
    }

    /// Returns the proof of election on the bundle.
    pub fn proof_of_election(&self) -> &'a ProofOfElection {
        match self {
            SealedBundleHeaderRef::V0(bundle) => &bundle.header.proof_of_election,
            SealedBundleHeaderRef::V1(bundle) => &bundle.header.proof_of_election,
        }
    }

    /// Returns the receipt on the bundle.
    pub fn receipt(
        &self,
    ) -> ExecutionReceiptRef<
        'a,
        Number,
        Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    > {
        match self {
            SealedBundleHeaderRef::V0(bundle) => ExecutionReceiptRef::V0(&bundle.header.receipt),
            SealedBundleHeaderRef::V1(bundle) => match &bundle.header.receipt {
                ExecutionReceipt::V0(receipt) => ExecutionReceiptRef::V0(receipt),
            },
        }
    }

    pub fn slot_number(&self) -> u64 {
        match self {
            SealedBundleHeaderRef::V0(bundle) => bundle.header.proof_of_election.slot_number,
            SealedBundleHeaderRef::V1(bundle) => bundle.header.proof_of_election.slot_number,
        }
    }

    pub fn bundle_extrinsics_root(&self) -> HeaderHashFor<DomainHeader> {
        match self {
            SealedBundleHeaderRef::V0(bundle) => bundle.header.bundle_extrinsics_root,
            SealedBundleHeaderRef::V1(bundle) => bundle.header.bundle_extrinsics_root,
        }
    }
}

/// Bundle Versions.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, Copy)]
pub enum BundleVersion {
    /// V0 bundle version
    V0,
    /// V1 bundle version
    V1,
}

/// Versioned Domain Bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum Bundle<Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance> {
    /// V0 version of the domain bundle.
    V0(BundleV0<Extrinsic, Number, Hash, DomainHeader, Balance>),
    /// V1 version of the domain bundle.
    V1(BundleV1<Extrinsic, Number, Hash, DomainHeader, Balance>),
}

impl<Extrinsic, Number, Hash, DomainHeader, Balance>
    Bundle<Extrinsic, Number, Hash, DomainHeader, Balance>
where
    Extrinsic: Encode + Clone,
    Number: Encode + Zero,
    Hash: Encode + Default,
    DomainHeader: HeaderT,
    Balance: Encode + Zero + Default,
{
    /// Returns the hash of this bundle.
    pub fn hash(&self) -> H256 {
        match self {
            // V0 bundle hash is derived from inner v0 bundle
            // instead of self to maintain backward compatibility.
            Bundle::V0(bundle) => bundle.hash(),
            // Any version above 0, will be hash of entire type.
            _ => BlakeTwo256::hash_of(self),
        }
    }

    /// Returns the domain_id of this bundle.
    pub fn domain_id(&self) -> DomainId {
        match self {
            Bundle::V0(bundle) => bundle.sealed_header.header.proof_of_election.domain_id,
            Bundle::V1(bundle) => bundle.sealed_header.header.proof_of_election.domain_id,
        }
    }

    /// Return the `bundle_extrinsics_root`
    pub fn extrinsics_root(&self) -> HeaderHashFor<DomainHeader> {
        match self {
            Bundle::V0(bundle) => bundle.sealed_header.header.bundle_extrinsics_root,
            Bundle::V1(bundle) => bundle.sealed_header.header.bundle_extrinsics_root,
        }
    }

    /// Return the `operator_id`
    pub fn operator_id(&self) -> OperatorId {
        match self {
            Bundle::V0(bundle) => bundle.sealed_header.header.proof_of_election.operator_id,
            Bundle::V1(bundle) => bundle.sealed_header.header.proof_of_election.operator_id,
        }
    }

    /// Return a reference of the execution receipt.
    pub fn receipt_domain_block_number(&self) -> &HeaderNumberFor<DomainHeader> {
        match self {
            Bundle::V0(bundle) => &bundle.sealed_header.header.receipt.domain_block_number,
            Bundle::V1(bundle) => bundle.sealed_header.header.receipt.domain_block_number(),
        }
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
        match self {
            Bundle::V0(bundle) => ExecutionReceipt::V0(bundle.sealed_header.header.receipt),
            Bundle::V1(bundle) => bundle.sealed_header.header.receipt,
        }
    }

    pub fn receipt(
        &self,
    ) -> ExecutionReceiptRef<
        Number,
        Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    > {
        match self {
            Bundle::V0(bundle) => ExecutionReceiptRef::V0(&bundle.sealed_header.header.receipt),
            Bundle::V1(bundle) => match &bundle.sealed_header.header.receipt {
                ExecutionReceipt::V0(er) => ExecutionReceiptRef::V0(er),
            },
        }
    }

    /// Return the bundle size (include header and body) in bytes
    pub fn size(&self) -> u32 {
        match self {
            // for v0 backward compatibility,
            // use inner bundle's encoded size
            Bundle::V0(bundle) => bundle.encoded_size() as u32,
            _ => self.encoded_size() as u32,
        }
    }

    /// Return the bundle body size in bytes
    pub fn body_size(&self) -> u32 {
        let extrinsics = match self {
            Bundle::V0(bundle) => &bundle.extrinsics,
            Bundle::V1(bundle) => &bundle.extrinsics,
        };

        extrinsics
            .iter()
            .map(|tx| tx.encoded_size() as u32)
            .sum::<u32>()
    }

    /// Return the bundle body length. i.e number of extrinsics in the bundle.
    pub fn body_length(&self) -> usize {
        let extrinsics = match self {
            Bundle::V0(bundle) => &bundle.extrinsics,
            Bundle::V1(bundle) => &bundle.extrinsics,
        };
        extrinsics.len()
    }

    /// Returns the estimated weight of the Bundle.
    pub fn estimated_weight(&self) -> Weight {
        match self {
            Bundle::V0(bundle) => bundle.sealed_header.header.estimated_bundle_weight,
            Bundle::V1(bundle) => bundle.sealed_header.header.estimated_bundle_weight,
        }
    }

    /// Returns the slot number at this bundle was constructed.
    pub fn slot_number(&self) -> u64 {
        match self {
            Bundle::V0(bundle) => bundle.sealed_header.header.proof_of_election.slot_number,
            Bundle::V1(bundle) => bundle.sealed_header.header.proof_of_election.slot_number,
        }
    }

    /// Returns the reference to proof of election.
    pub fn proof_of_election(&self) -> &ProofOfElection {
        match self {
            Bundle::V0(bundle) => &bundle.sealed_header.header.proof_of_election,
            Bundle::V1(bundle) => &bundle.sealed_header.header.proof_of_election,
        }
    }

    /// Returns the sealed header in the Bundle.
    pub fn sealed_header(&self) -> SealedBundleHeaderRef<Number, Hash, DomainHeader, Balance> {
        match self {
            Bundle::V0(bundle) => SealedBundleHeaderRef::V0(&bundle.sealed_header),
            Bundle::V1(bundle) => SealedBundleHeaderRef::V1(&bundle.sealed_header),
        }
    }

    /// Returns the bundle body consuming the bundle. ie extrinsics.
    pub fn into_extrinsics(self) -> Vec<Extrinsic> {
        match self {
            Bundle::V0(bundle) => bundle.extrinsics,
            Bundle::V1(bundle) => bundle.extrinsics,
        }
    }

    /// Returns the reference to bundle body. ie extrinsics.
    pub fn extrinsics(&self) -> &[Extrinsic] {
        match self {
            Bundle::V0(bundle) => &bundle.extrinsics,
            Bundle::V1(bundle) => &bundle.extrinsics,
        }
    }

    /// Sets extrinsics to the bundle.
    pub fn set_extrinsics(&mut self, exts: Vec<Extrinsic>) {
        match self {
            Bundle::V0(bundle) => bundle.extrinsics = exts,
            Bundle::V1(bundle) => bundle.extrinsics = exts,
        }
    }

    /// Sets bundle extrinsic root.
    pub fn set_bundle_extrinsics_root(&mut self, root: HeaderHashFor<DomainHeader>) {
        match self {
            Bundle::V0(bundle) => bundle.sealed_header.header.bundle_extrinsics_root = root,
            Bundle::V1(bundle) => bundle.sealed_header.header.bundle_extrinsics_root = root,
        }
    }

    /// Returns a mutable reference to Execution receipt.
    pub fn execution_receipt_as_mut(
        &mut self,
    ) -> ExecutionReceiptMutRef<
        Number,
        Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    > {
        match self {
            Bundle::V0(bundle) => {
                ExecutionReceiptMutRef::V0(&mut bundle.sealed_header.header.receipt)
            }
            Bundle::V1(bundle) => match &mut bundle.sealed_header.header.receipt {
                ExecutionReceipt::V0(er) => ExecutionReceiptMutRef::V0(er),
            },
        }
    }

    /// Set estimated bundle weight.
    pub fn set_estimated_bundle_weight(&mut self, weight: Weight) {
        match self {
            Bundle::V0(bundle) => bundle.sealed_header.header.estimated_bundle_weight = weight,
            Bundle::V1(bundle) => bundle.sealed_header.header.estimated_bundle_weight = weight,
        }
    }

    /// Sets signature of the bundle.
    pub fn set_signature(&mut self, signature: OperatorSignature) {
        match self {
            Bundle::V0(bundle) => bundle.sealed_header.signature = signature,
            Bundle::V1(bundle) => bundle.sealed_header.signature = signature,
        }
    }

    /// Sets proof of election for bundle.
    pub fn set_proof_of_election(&mut self, poe: ProofOfElection) {
        match self {
            Bundle::V0(bundle) => bundle.sealed_header.header.proof_of_election = poe,
            Bundle::V1(bundle) => bundle.sealed_header.header.proof_of_election = poe,
        }
    }
}

/// Bundle with opaque extrinsics.
pub type OpaqueBundle<Number, Hash, DomainHeader, Balance> =
    Bundle<OpaqueExtrinsic, Number, Hash, DomainHeader, Balance>;

/// List of [`OpaqueBundle`].
pub type OpaqueBundles<Block, DomainHeader, Balance> =
    Vec<OpaqueBundle<NumberFor<Block>, BlockHashFor<Block>, DomainHeader, Balance>>;

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

    let header = BundleHeaderV1 {
        proof_of_election: ProofOfElection::dummy(domain_id, operator_id),
        receipt,
        estimated_bundle_weight: Default::default(),
        bundle_extrinsics_root: Default::default(),
    };
    let signature = OperatorSignature::unchecked_from([0u8; 64]);

    OpaqueBundle::V1(BundleV1 {
        sealed_header: SealedBundleHeaderV1::new(header, signature),
        extrinsics: Vec::new(),
    })
}

/// A digest of the bundle
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleDigest<Hash> {
    /// The hash of the bundle header
    pub header_hash: Hash,
    /// The Merkle root of all new extrinsics included in this bundle.
    pub extrinsics_root: Hash,
    /// The size of the bundle body in bytes.
    pub size: u32,
}

/// Bundle invalidity type
///
/// Each type contains the index of the first invalid extrinsic within the bundle
#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
pub enum InvalidBundleType {
    /// Failed to decode the opaque extrinsic.
    #[codec(index = 0)]
    UndecodableTx(u32),
    /// Transaction is out of the tx range.
    #[codec(index = 1)]
    OutOfRangeTx(u32),
    /// Transaction is illegal (unable to pay the fee, etc).
    #[codec(index = 2)]
    IllegalTx(u32),
    /// Transaction is an invalid XDM.
    #[codec(index = 3)]
    InvalidXDM(u32),
    /// Transaction is an inherent extrinsic.
    #[codec(index = 4)]
    InherentExtrinsic(u32),
    /// The `estimated_bundle_weight` in the bundle header is invalid
    #[codec(index = 5)]
    InvalidBundleWeight,
}

impl InvalidBundleType {
    // Return the checking order of the invalid type
    pub fn checking_order(&self) -> u64 {
        // A bundle can contains multiple invalid extrinsics thus consider the first invalid extrinsic
        // as the invalid type
        let extrinsic_order = match self {
            Self::UndecodableTx(i) => *i,
            Self::OutOfRangeTx(i) => *i,
            Self::IllegalTx(i) => *i,
            Self::InvalidXDM(i) => *i,
            Self::InherentExtrinsic(i) => *i,
            // NOTE: the `InvalidBundleWeight` is targeting the whole bundle not a specific
            // single extrinsic, as `extrinsic_index` is used as the order to check the extrinsic
            // in the bundle returning `u32::MAX` indicate `InvalidBundleWeight` is checked after
            // all the extrinsic in the bundle is checked.
            Self::InvalidBundleWeight => u32::MAX,
        };

        // The extrinsic can be considered as invalid due to multiple `invalid_type` (i.e. an extrinsic
        // can be `OutOfRangeTx` and `IllegalTx` at the same time) thus use the following checking order
        // and consider the first check as the invalid type
        //
        // NOTE: Use explicit number as the order instead of the enum discriminant
        // to avoid changing the order accidentally
        let rule_order = match self {
            Self::UndecodableTx(_) => 1,
            Self::OutOfRangeTx(_) => 2,
            Self::InherentExtrinsic(_) => 3,
            Self::InvalidXDM(_) => 4,
            Self::IllegalTx(_) => 5,
            Self::InvalidBundleWeight => 6,
        };

        // The checking order is a combination of the `extrinsic_order` and `rule_order`
        // it presents as an `u64` where the first 32 bits is the `extrinsic_order` and
        // last 32 bits is the `rule_order` meaning the `extrinsic_order` is checked first
        // then the `rule_order`.
        ((extrinsic_order as u64) << 32) | (rule_order as u64)
    }

    // Return the index of the extrinsic that the invalid type points to
    //
    // NOTE: `InvalidBundleWeight` will return `None` since it is targeting the whole bundle not a
    // specific single extrinsic
    pub fn extrinsic_index(&self) -> Option<u32> {
        match self {
            Self::UndecodableTx(i) => Some(*i),
            Self::OutOfRangeTx(i) => Some(*i),
            Self::IllegalTx(i) => Some(*i),
            Self::InvalidXDM(i) => Some(*i),
            Self::InherentExtrinsic(i) => Some(*i),
            Self::InvalidBundleWeight => None,
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

    pub fn invalid_extrinsic_index(&self) -> Option<u32> {
        match &self.bundle {
            BundleValidity::Invalid(invalid_bundle_type) => invalid_bundle_type.extrinsic_index(),
            BundleValidity::Valid(_) => None,
        }
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
