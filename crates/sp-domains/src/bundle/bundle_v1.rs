#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bundle::{OpaqueBundle, SealedBundleHeader};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::OpaqueExtrinsic;
use sp_runtime::traits::{BlakeTwo256, Hash, Header as HeaderT};

/// Domain bundle v1.
// TODO: update sealed header to include versioned execution receipt.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleV1<Extrinsic, Number, Hash, DomainHeader: HeaderT, Balance> {
    /// Sealed bundle header.
    pub sealed_header: SealedBundleHeader<Number, Hash, DomainHeader, Balance>,
    /// The accompanying extrinsics.
    pub extrinsics: Vec<Extrinsic>,
}

impl<Extrinsic: Encode, Number: Encode, Hash: Encode, DomainHeader: HeaderT, Balance: Encode>
    BundleV1<Extrinsic, Number, Hash, DomainHeader, Balance>
{
    /// Returns the hash of this bundle.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

impl<Extrinsic: Encode, Number, Hash, DomainHeader: HeaderT, Balance>
    BundleV1<Extrinsic, Number, Hash, DomainHeader, Balance>
{
    /// Convert a bundle with generic extrinsic to a bundle with opaque extrinsic.
    pub fn into_opaque_bundle(self) -> OpaqueBundle<Number, Hash, DomainHeader, Balance> {
        let BundleV1 {
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
        OpaqueBundle::V1(BundleV1 {
            sealed_header,
            extrinsics: opaque_extrinsics,
        })
    }
}
