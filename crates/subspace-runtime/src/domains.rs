use crate::{Block, BlockNumber, Domains, Hash, RuntimeCall, UncheckedExtrinsic};
use domain_runtime_primitives::{BlockNumber as DomainNumber, Hash as DomainHash};
use sp_consensus_subspace::digests::CompatibleDigestItem;
use sp_consensus_subspace::FarmerPublicKey;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::transaction::PreValidationObject;
use sp_domains::{DomainId, ExecutionReceipt};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT, Zero};
use sp_std::vec::Vec;
use subspace_core_primitives::Randomness;
use subspace_verification::derive_randomness;

pub(crate) fn extract_successful_bundles(
    domain_id: DomainId,
    extrinsics: Vec<UncheckedExtrinsic>,
) -> sp_domains::OpaqueBundles<Block, DomainNumber, DomainHash> {
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
) -> Vec<ExecutionReceipt<BlockNumber, Hash, DomainNumber, DomainHash>> {
    let successful_bundles = Domains::successful_bundles(domain_id);
    extrinsics
        .into_iter()
        .filter_map(|uxt| match uxt.function {
            RuntimeCall::Domains(pallet_domains::Call::submit_bundle { opaque_bundle })
                if opaque_bundle.domain_id() == domain_id
                    && successful_bundles.contains(&opaque_bundle.hash()) =>
            {
                Some(opaque_bundle.receipt)
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
                Some(fraud_proof)
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
            PreValidationObject::FraudProof(fraud_proof)
        }
        RuntimeCall::Domains(pallet_domains::Call::submit_bundle { opaque_bundle }) => {
            PreValidationObject::Bundle(opaque_bundle)
        }
        _ => PreValidationObject::Null,
    }
}

pub(crate) fn extrinsics_shuffling_seed<Block: BlockT>(header: Block::Header) -> Randomness {
    if header.number().is_zero() {
        Randomness::default()
    } else {
        let mut pre_digest: Option<_> = None;
        for log in header.digest().logs() {
            match (
                log.as_subspace_pre_digest::<FarmerPublicKey>(),
                pre_digest.is_some(),
            ) {
                (Some(_), true) => panic!("Multiple Subspace pre-runtime digests in a header"),
                (None, _) => {}
                (s, false) => pre_digest = s,
            }
        }

        let pre_digest = pre_digest.expect("Header must contain one pre-runtime digest; qed");

        let seed: &[u8] = b"extrinsics-shuffling-seed";
        let randomness = derive_randomness(&pre_digest.solution, pre_digest.slot.into());
        let mut data = Vec::with_capacity(seed.len() + randomness.len());
        data.extend_from_slice(seed);
        data.extend_from_slice(randomness.as_ref());

        Randomness::from(BlakeTwo256::hash_of(&data).to_fixed_bytes())
    }
}
