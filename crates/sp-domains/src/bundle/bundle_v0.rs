#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bundle::OpaqueBundle;
use crate::bundle::bundle_v1::{BundleHeaderV1, BundleV1, SealedBundleHeaderV1};
use crate::execution_receipt::ExecutionReceipt;
use crate::execution_receipt::execution_receipt_v0::ExecutionReceiptV0;
use crate::{HeaderHashFor, HeaderHashingFor, HeaderNumberFor, OperatorSignature, ProofOfElection};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::OpaqueExtrinsic;
use sp_runtime::traits::{BlakeTwo256, Hash as HashT, Header as HeaderT, NumberFor};
use sp_weights::Weight;
use subspace_runtime_primitives::BlockHashFor;

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleHeaderV0<Number, Hash, DomainHeader: HeaderT, Balance> {
    /// Proof of bundle producer election.
    pub proof_of_election: ProofOfElection,
    /// Execution receipt that should extend the receipt chain or add confirmations
    /// to the head receipt.
    pub receipt: ExecutionReceiptV0<
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
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
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

/// V0 Domain bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleV0<Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance> {
    /// Sealed bundle header.
    pub sealed_header: SealedBundleHeaderV0<Number, Hash, DomainHeader, Balance>,
    /// The accompanying extrinsics.
    pub extrinsics: Vec<Extrinsic>,
}

impl<Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance>
    From<BundleV0<Extrinsic, Number, Hash, DomainHeader, Balance>>
    for BundleV1<Extrinsic, Number, Hash, DomainHeader, Balance>
{
    fn from(value: BundleV0<Extrinsic, Number, Hash, DomainHeader, Balance>) -> Self {
        let BundleV0 {
            extrinsics,
            sealed_header,
        } = value;

        let SealedBundleHeaderV0 { header, signature } = sealed_header;
        let BundleHeaderV0 {
            proof_of_election,
            receipt,
            estimated_bundle_weight,
            bundle_extrinsics_root,
        } = header;

        let header = BundleHeaderV1 {
            proof_of_election,
            receipt: ExecutionReceipt::V0(receipt),
            estimated_bundle_weight,
            bundle_extrinsics_root,
        };
        BundleV1 {
            sealed_header: SealedBundleHeaderV1 { header, signature },
            extrinsics,
        }
    }
}

impl<Extrinsic: Encode, Number: Encode, Hash: Encode, DomainHeader: HeaderT, Balance: Encode>
    BundleV0<Extrinsic, Number, Hash, DomainHeader, Balance>
{
    /// Returns the hash of this bundle.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }

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

/// BundleV0 with opaque extrinsics.
pub type OpaqueBundleV0<Number, Hash, DomainHeader, Balance> =
    BundleV0<OpaqueExtrinsic, Number, Hash, DomainHeader, Balance>;

/// List of [`OpaqueBundleV0`].
pub type OpaqueBundlesV0<Block, DomainHeader, Balance> =
    Vec<OpaqueBundleV0<NumberFor<Block>, BlockHashFor<Block>, DomainHeader, Balance>>;
