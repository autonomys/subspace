#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bundle::OpaqueBundle;
use crate::execution_receipt::ExecutionReceipt;
use crate::{HeaderHashFor, HeaderHashingFor, HeaderNumberFor, OperatorSignature, ProofOfElection};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;
use sp_runtime::OpaqueExtrinsic;
use sp_runtime::traits::{Hash, Header as HeaderT};
use sp_weights::Weight;

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, DecodeWithMemTracking)]
pub struct BundleHeaderV0<Number, Hash, DomainHeader: HeaderT, Balance> {
    /// Proof of bundle producer election.
    pub proof_of_election: ProofOfElection,
    /// Execution receipt that should extend the receipt chain or add confirmations
    /// to the head receipt.
    pub receipt: ExecutionReceipt<
        Number,
        Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
    /// The total (estimated) weight of all extrinsics in the bundle.
    ///
    /// Used to prevent overloading the bundle with compute.
    pub estimated_bundle_weight: Weight,
    /// The Merkle root of all new extrinsics included in this bundle.
    pub bundle_extrinsics_root: HeaderHashFor<DomainHeader>,
}

impl<Number: Encode, Hash: Encode, DomainHeader: HeaderT, Balance: Encode>
    BundleHeaderV0<Number, Hash, DomainHeader, Balance>
{
    /// Returns the hash of this header.
    pub fn hash(&self) -> HeaderHashFor<DomainHeader> {
        HeaderHashingFor::<DomainHeader>::hash_of(self)
    }
}

/// Header of bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, DecodeWithMemTracking)]
pub struct SealedBundleHeaderV0<Number, Hash, DomainHeader: HeaderT, Balance> {
    /// Unsealed header.
    pub header: BundleHeaderV0<Number, Hash, DomainHeader, Balance>,
    /// Signature of the bundle.
    pub signature: OperatorSignature,
}

impl<Number: Encode, Hash: Encode, DomainHeader: HeaderT, Balance: Encode>
    SealedBundleHeaderV0<Number, Hash, DomainHeader, Balance>
{
    /// Constructs a new instance of [`SealedBundleHeaderV0`].
    pub fn new(
        header: BundleHeaderV0<Number, Hash, DomainHeader, Balance>,
        signature: OperatorSignature,
    ) -> Self {
        Self { header, signature }
    }
}

/// Domain bundle v0.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, DecodeWithMemTracking)]
pub struct BundleV0<Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance> {
    /// Sealed bundle header.
    pub sealed_header: SealedBundleHeaderV0<Number, Hash, DomainHeader, Balance>,
    /// The accompanying extrinsics.
    pub extrinsics: Vec<Extrinsic>,
}

impl<Extrinsic: Encode, Number, Hash, DomainHeader: HeaderT, Balance>
    BundleV0<Extrinsic, Number, Hash, DomainHeader, Balance>
{
    /// Convert a bundle with generic extrinsic to a bundle with opaque extrinsic.
    pub fn into_opaque_bundle(self) -> OpaqueBundle<Number, Hash, DomainHeader, Balance> {
        let BundleV0 {
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
        OpaqueBundle::V0(BundleV0 {
            sealed_header,
            extrinsics: opaque_extrinsics,
        })
    }
}
