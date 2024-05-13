#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::{Balance, Block, Domains, RuntimeCall, UncheckedExtrinsic};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use domain_runtime_primitives::opaque::Header as DomainHeader;
use sp_domains::DomainId;
use sp_runtime::traits::{Block as BlockT, NumberFor};

pub(crate) fn extract_successful_bundles(
    domain_id: DomainId,
    extrinsics: Vec<UncheckedExtrinsic>,
) -> sp_domains::OpaqueBundles<Block, DomainHeader, Balance> {
    let successful_bundles = Domains::successful_bundles(domain_id);
    extrinsics
        .into_iter()
        .filter_map(|uxt| match uxt.function {
            RuntimeCall::Domains(pallet_domains::Call::submit_bundle { opaque_bundle })
                if opaque_bundle.domain_id() == domain_id
                    && successful_bundles.contains(&opaque_bundle.hash()) =>
            {
                Some(opaque_bundle)
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn extract_bundle(
    extrinsic: UncheckedExtrinsic,
) -> Option<
    sp_domains::OpaqueBundle<NumberFor<Block>, <Block as BlockT>::Hash, DomainHeader, Balance>,
> {
    match extrinsic.function {
        RuntimeCall::Domains(pallet_domains::Call::submit_bundle { opaque_bundle }) => {
            Some(opaque_bundle)
        }
        _ => None,
    }
}
