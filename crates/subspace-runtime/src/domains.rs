use crate::{Balance, Block, Domains, RuntimeCall, UncheckedExtrinsic};
use domain_runtime_primitives::opaque::Header as DomainHeader;
use sp_domains::DomainId;
use sp_domains_fraud_proof::fraud_proof::FraudProof;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_std::vec::Vec;

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

pub(crate) fn extract_fraud_proofs(
    domain_id: DomainId,
    extrinsics: Vec<UncheckedExtrinsic>,
) -> Vec<FraudProof<NumberFor<Block>, <Block as BlockT>::Hash, DomainHeader>> {
    let successful_fraud_proofs = Domains::successful_fraud_proofs(domain_id);
    extrinsics
        .into_iter()
        .filter_map(|uxt| match uxt.function {
            RuntimeCall::Domains(pallet_domains::Call::submit_fraud_proof { fraud_proof })
                if fraud_proof.domain_id() == domain_id
                    && successful_fraud_proofs.contains(&fraud_proof.hash()) =>
            {
                Some(*fraud_proof)
            }
            _ => None,
        })
        .collect()
}
