use crate::{Balance, Block, BlockNumber, Domains, Hash, RuntimeCall, UncheckedExtrinsic};
use domain_runtime_primitives::{BlockNumber as DomainNumber, Hash as DomainHash};
use sp_domains::fraud_proof::FraudProof;
use sp_domains::transaction::PreValidationObject;
use sp_domains::{DomainId, ExecutionReceipt};
use sp_std::vec::Vec;

pub(crate) fn extract_successful_bundles(
    domain_id: DomainId,
    extrinsics: Vec<UncheckedExtrinsic>,
) -> sp_domains::OpaqueBundles<Block, DomainNumber, DomainHash, Balance> {
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

// TODO: Remove when proceeding to fraud proof v2.
#[allow(unused)]
pub(crate) fn extract_receipts(
    extrinsics: Vec<UncheckedExtrinsic>,
    domain_id: DomainId,
) -> Vec<ExecutionReceipt<BlockNumber, Hash, DomainNumber, DomainHash, Balance>> {
    let successful_bundles = Domains::successful_bundles(domain_id);
    extrinsics
        .into_iter()
        .filter_map(|uxt| match uxt.function {
            RuntimeCall::Domains(pallet_domains::Call::submit_bundle { opaque_bundle })
                if opaque_bundle.domain_id() == domain_id
                    && successful_bundles.contains(&opaque_bundle.hash()) =>
            {
                Some(opaque_bundle.into_receipt())
            }
            _ => None,
        })
        .collect()
}

// TODO: Remove when proceeding to fraud proof v2.
#[allow(unused)]
pub(crate) fn extract_fraud_proofs(
    extrinsics: Vec<UncheckedExtrinsic>,
    domain_id: DomainId,
) -> Vec<FraudProof<BlockNumber, Hash>> {
    // TODO: Ensure fraud proof extrinsic is infallible.
    extrinsics
        .into_iter()
        .filter_map(|uxt| match uxt.function {
            RuntimeCall::Domains(pallet_domains::Call::submit_fraud_proof { fraud_proof })
                if fraud_proof.domain_id() == domain_id =>
            {
                Some(*fraud_proof)
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn extract_pre_validation_object(
    extrinsic: UncheckedExtrinsic,
) -> PreValidationObject<Block, DomainNumber, DomainHash> {
    match extrinsic.function {
        RuntimeCall::Domains(pallet_domains::Call::submit_fraud_proof { fraud_proof }) => {
            PreValidationObject::FraudProof(*fraud_proof)
        }
        RuntimeCall::Domains(pallet_domains::Call::submit_bundle { opaque_bundle }) => {
            PreValidationObject::Bundle(opaque_bundle)
        }
        _ => PreValidationObject::Null,
    }
}
