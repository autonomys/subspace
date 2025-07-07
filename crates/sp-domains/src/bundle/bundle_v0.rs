#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bundle::bundle_v1::BundleV1;
use crate::bundle::{OpaqueBundle, SealedBundleHeader};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::OpaqueExtrinsic;
use sp_runtime::traits::{BlakeTwo256, Hash as HashT, Header as HeaderT, NumberFor};
use subspace_runtime_primitives::BlockHashFor;

/// V0 Domain bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleV0<Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance> {
    /// Sealed bundle header.
    pub sealed_header: SealedBundleHeader<Number, Hash, DomainHeader, Balance>,
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
        BundleV1 {
            sealed_header,
            extrinsics,
        }
    }
}

impl<Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance>
    From<BundleV1<Extrinsic, Number, Hash, DomainHeader, Balance>>
    for BundleV0<Extrinsic, Number, Hash, DomainHeader, Balance>
{
    fn from(value: BundleV1<Extrinsic, Number, Hash, DomainHeader, Balance>) -> Self {
        let BundleV1 {
            sealed_header,
            extrinsics,
        } = value;
        BundleV0 {
            sealed_header,
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
