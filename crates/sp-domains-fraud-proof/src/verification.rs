use crate::InvalidDomainExtrinsicRootInfo;
use hash_db::Hasher;
use sp_core::H256;
use sp_domains::fraud_proof::{ExtrinsicDigest, InvalidExtrinsicsRootProof};
use sp_domains::valued_trie_root::valued_ordered_trie_root;
use sp_domains::verification::{
    deduplicate_and_shuffle_extrinsics, extrinsics_shuffling_seed, VerificationError,
};
use sp_domains::ExecutionReceipt;
use sp_runtime::traits::{BlakeTwo256, Block, Hash, NumberFor};
use sp_std::vec::Vec;
use sp_trie::LayoutV1;
use subspace_core_primitives::Randomness;
use trie_db::node::Value;

pub fn verify_invalid_domain_extrinsics_root_fraud_proof<
    CBlock,
    DomainNumber,
    DomainHash,
    Balance,
    Hashing,
    DomainHashing,
>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainNumber,
        DomainHash,
        Balance,
    >,
    fraud_proof: &InvalidExtrinsicsRootProof,
    verification_info: InvalidDomainExtrinsicRootInfo,
) -> Result<(), VerificationError>
where
    CBlock: Block,
    Hashing: Hasher<Out = CBlock::Hash>,
    DomainHashing: Hasher<Out = DomainHash>,
    DomainHash: Into<H256>,
{
    let InvalidExtrinsicsRootProof {
        valid_bundle_digests,
        ..
    } = fraud_proof;

    let InvalidDomainExtrinsicRootInfo {
        block_randomness,
        timestamp_extrinsic,
    } = verification_info;

    let mut bundle_extrinsics_digests = Vec::new();
    for (bad_receipt_valid_bundle_digest, bundle_digest) in bad_receipt
        .valid_bundle_digests()
        .into_iter()
        .zip(valid_bundle_digests)
    {
        let bundle_digest_hash = BlakeTwo256::hash_of(&bundle_digest.bundle_digest);
        if bundle_digest_hash != bad_receipt_valid_bundle_digest {
            return Err(VerificationError::InvalidBundleDigest);
        }

        bundle_extrinsics_digests.extend(bundle_digest.bundle_digest.clone());
    }

    let shuffling_seed =
        H256::from_slice(extrinsics_shuffling_seed::<Hashing>(block_randomness).as_ref());

    let mut ordered_extrinsics = deduplicate_and_shuffle_extrinsics(
        bundle_extrinsics_digests,
        Randomness::from(shuffling_seed.to_fixed_bytes()),
    );

    let timestamp_extrinsic = ExtrinsicDigest::new::<LayoutV1<DomainHashing>>(timestamp_extrinsic);
    ordered_extrinsics.insert(0, timestamp_extrinsic);

    let ordered_trie_node_values = ordered_extrinsics
        .iter()
        .map(|ext_digest| match ext_digest {
            ExtrinsicDigest::Data(data) => Value::Inline(data),
            ExtrinsicDigest::Hash(hash) => Value::Node(hash.0.as_slice()),
        })
        .collect();

    // TODO: domain runtime upgrade extrinsic
    let extrinsics_root =
        valued_ordered_trie_root::<LayoutV1<BlakeTwo256>>(ordered_trie_node_values);
    if bad_receipt.domain_block_extrinsic_root == extrinsics_root {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}
