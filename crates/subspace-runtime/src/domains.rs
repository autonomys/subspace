use crate::{Block, BlockNumber, Hash, RuntimeCall, RuntimeEvent, System, UncheckedExtrinsic};
use sp_consensus_subspace::digests::CompatibleDigestItem;
use sp_consensus_subspace::FarmerPublicKey;
use sp_core::H256;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::transaction::PreValidationObject;
use sp_domains::{DomainId, ExecutionReceipt};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT, Zero};
use sp_std::vec::Vec;
use subspace_core_primitives::{PublicKey, Randomness};
use subspace_verification::derive_randomness;

pub(crate) fn extract_system_bundles(
    extrinsics: Vec<UncheckedExtrinsic>,
) -> (
    sp_domains::OpaqueBundles<Block, domain_runtime_primitives::Hash>,
    sp_domains::SignedOpaqueBundles<Block, domain_runtime_primitives::Hash>,
) {
    let (system_bundles, core_bundles): (Vec<_>, Vec<_>) = extrinsics
        .into_iter()
        .filter_map(|uxt| {
            if let RuntimeCall::Domains(pallet_domains::Call::submit_bundle {
                signed_opaque_bundle,
            }) = uxt.function
            {
                if signed_opaque_bundle.domain_id().is_system() {
                    Some((Some(signed_opaque_bundle.bundle), None))
                } else {
                    Some((None, Some(signed_opaque_bundle)))
                }
            } else {
                None
            }
        })
        .unzip();
    (
        system_bundles.into_iter().flatten().collect(),
        core_bundles.into_iter().flatten().collect(),
    )
}

pub(crate) fn extract_core_bundles(
    extrinsics: Vec<UncheckedExtrinsic>,
    domain_id: DomainId,
) -> sp_domains::OpaqueBundles<Block, domain_runtime_primitives::Hash> {
    extrinsics
        .into_iter()
        .filter_map(|uxt| match uxt.function {
            RuntimeCall::Domains(pallet_domains::Call::submit_bundle {
                signed_opaque_bundle,
            }) if signed_opaque_bundle.domain_id() == domain_id => {
                Some(signed_opaque_bundle.bundle)
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn extract_stored_bundle_hashes() -> Vec<H256> {
    System::read_events_no_consensus()
        .filter_map(|e| match e.event {
            RuntimeEvent::Domains(pallet_domains::Event::BundleStored { bundle_hash, .. }) => {
                Some(bundle_hash)
            }
            _ => None,
        })
        .collect::<Vec<_>>()
}

pub(crate) fn extract_receipts(
    extrinsics: Vec<UncheckedExtrinsic>,
    domain_id: DomainId,
) -> Vec<ExecutionReceipt<BlockNumber, Hash, domain_runtime_primitives::Hash>> {
    extrinsics
        .into_iter()
        .filter_map(|uxt| match uxt.function {
            RuntimeCall::Domains(pallet_domains::Call::submit_bundle {
                signed_opaque_bundle,
            }) if signed_opaque_bundle.domain_id() == domain_id => {
                Some(signed_opaque_bundle.bundle.receipts)
            }
            _ => None,
        })
        .flatten()
        .collect()
}

pub(crate) fn extract_fraud_proofs(
    extrinsics: Vec<UncheckedExtrinsic>,
    domain_id: DomainId,
) -> Vec<FraudProof<BlockNumber, Hash>> {
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
) -> PreValidationObject<Block, domain_runtime_primitives::Hash> {
    match extrinsic.function {
        RuntimeCall::Domains(pallet_domains::Call::submit_fraud_proof { fraud_proof }) => {
            PreValidationObject::FraudProof(fraud_proof)
        }
        RuntimeCall::Domains(pallet_domains::Call::submit_bundle {
            signed_opaque_bundle,
        }) => PreValidationObject::Bundle(signed_opaque_bundle),
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
        let randomness = derive_randomness(
            &Into::<PublicKey>::into(&pre_digest.solution.public_key),
            &pre_digest.solution.chunk.to_bytes(),
            &pre_digest.solution.chunk_signature,
        )
        .expect("Tag signature is verified by the client and must always be valid; qed");
        let mut data = Vec::with_capacity(seed.len() + randomness.len());
        data.extend_from_slice(seed);
        data.extend_from_slice(&randomness);

        BlakeTwo256::hash_of(&data).into()
    }
}
