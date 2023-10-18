use codec::Decode;
use hash_db::Hasher;
use sp_core::storage::StorageKey;
use sp_core::H256;
use sp_domains::fraud_proof::{ExtrinsicDigest, InvalidExtrinsicsRootProof};
use sp_domains::valued_trie_root::valued_ordered_trie_root;
use sp_domains::verification::{
    deduplicate_and_shuffle_extrinsics, extrinsics_shuffling_seed, StorageProofVerifier,
    VerificationError,
};
use sp_domains::ExecutionReceipt;
use sp_runtime::generic::Digest;
use sp_runtime::traits::{BlakeTwo256, Block, Hash, Header as HeaderT, NumberFor};
use sp_std::vec::Vec;
use sp_trie::{LayoutV1, StorageProof};
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
    block_randomness: Randomness,
    domain_timestamp_extrinsic: Vec<u8>,
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

    let timestamp_extrinsic =
        ExtrinsicDigest::new::<LayoutV1<DomainHashing>>(domain_timestamp_extrinsic);
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

pub fn verify_invalid_domain_block_hash_fraud_proof<CBlock, Balance, DomainHeader>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainHeader::Number,
        DomainHeader::Hash,
        Balance,
    >,
    digest_storage_proof: StorageProof,
    parent_domain_block_hash: DomainHeader::Hash,
) -> Result<(), VerificationError>
where
    CBlock: Block,
    Balance: PartialEq + Decode,
    DomainHeader: HeaderT,
    DomainHeader::Hash: From<H256>,
{
    let state_root = bad_receipt.final_state_root;
    let digest_storage_key = StorageKey(sp_domains::fraud_proof::system_digest_final_key());

    let digest = StorageProofVerifier::<DomainHeader::Hashing>::verify_and_get_value::<Digest>(
        &state_root,
        digest_storage_proof,
        digest_storage_key,
    )
    .map_err(|_| VerificationError::InvalidProof)?;

    let derived_domain_block_hash = sp_domains::derive_domain_block_hash::<DomainHeader>(
        bad_receipt.domain_block_number,
        bad_receipt.domain_block_extrinsic_root.into(),
        state_root,
        parent_domain_block_hash,
        digest,
    );

    if bad_receipt.domain_block_hash == derived_domain_block_hash {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}
