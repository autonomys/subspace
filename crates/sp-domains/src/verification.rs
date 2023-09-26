use crate::fraud_proof::{ExtrinsicDigest, InvalidExtrinsicsRootProof, StorageKeys};
use crate::valued_trie_root::valued_ordered_trie_root;
use crate::{ExecutionReceipt, EXTRINSICS_SHUFFLING_SEED};
use domain_runtime_primitives::opaque::AccountId;
use frame_support::PalletError;
use hash_db::Hasher;
use parity_scale_codec::{Decode, Encode};
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use scale_info::TypeInfo;
use sp_core::storage::StorageKey;
use sp_core::H256;
use sp_runtime::traits::{BlakeTwo256, Block, Hash, NumberFor};
use sp_state_machine::trace;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::vec_deque::VecDeque;
use sp_std::fmt::Debug;
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;
use sp_trie::{read_trie_value, LayoutV1, StorageProof};
use subspace_core_primitives::Randomness;
use trie_db::node::Value;

/// Verification error.
#[derive(Debug, PartialEq, Eq, Encode, Decode, PalletError, TypeInfo)]
pub enum VerificationError {
    /// Emits when the given storage proof is invalid.
    InvalidProof,
    /// Value doesn't exist in the Db for the given key.
    MissingValue,
    /// Failed to decode value.
    FailedToDecode,
    /// Invalid bundle digest
    InvalidBundleDigest,
}

pub struct StorageProofVerifier<H: Hasher>(PhantomData<H>);

impl<H: Hasher> StorageProofVerifier<H> {
    pub fn verify_and_get_value<V: Decode>(
        state_root: &H::Out,
        proof: StorageProof,
        key: StorageKey,
    ) -> Result<V, VerificationError> {
        let db = proof.into_memory_db::<H>();
        let val = read_trie_value::<LayoutV1<H>, _>(&db, state_root, key.as_ref(), None, None)
            .map_err(|_| VerificationError::InvalidProof)?
            .ok_or(VerificationError::MissingValue)?;

        let decoded = V::decode(&mut &val[..]).map_err(|_| VerificationError::FailedToDecode)?;

        Ok(decoded)
    }
}

pub fn verify_invalid_total_rewards_fraud_proof<
    CBlock,
    DomainNumber,
    DomainHash,
    Balance,
    Hashing,
>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainNumber,
        DomainHash,
        Balance,
    >,
    storage_proof: &StorageProof,
) -> Result<(), VerificationError>
where
    CBlock: Block,
    Balance: PartialEq + Decode,
    Hashing: Hasher<Out = CBlock::Hash>,
    DomainHash: Encode,
{
    let state_root = bad_receipt.final_state_root.encode();
    let state_root = CBlock::Hash::decode(&mut state_root.as_slice())
        .map_err(|_| VerificationError::FailedToDecode)?;
    let storage_key = StorageKey(crate::fraud_proof::operator_block_rewards_final_key());
    let storage_proof = storage_proof.clone();

    let total_rewards = StorageProofVerifier::<Hashing>::verify_and_get_value::<Balance>(
        &state_root,
        storage_proof,
        storage_key,
    )
    .map_err(|_| VerificationError::InvalidProof)?;

    // if the rewards matches, then this is an invalid fraud proof since rewards must be different.
    if bad_receipt.total_rewards == total_rewards {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}

pub fn verify_invalid_domain_extrinsics_root_fraud_proof<
    CBlock,
    DomainNumber,
    DomainHash,
    Balance,
    Hashing,
    SK,
>(
    consensus_state_root: CBlock::Hash,
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainNumber,
        DomainHash,
        Balance,
    >,
    fraud_proof: &InvalidExtrinsicsRootProof,
) -> Result<(), VerificationError>
where
    CBlock: Block,
    Hashing: Hasher<Out = CBlock::Hash>,
    SK: StorageKeys,
{
    let InvalidExtrinsicsRootProof {
        valid_bundle_digests,
        randomness_proof,
        ..
    } = fraud_proof;

    let mut ext_values = Vec::new();
    for (valid_bundle, bundle_digest) in bad_receipt
        .valid_bundles
        .into_iter()
        .zip(valid_bundle_digests)
    {
        let bundle_digest_hash = BlakeTwo256::hash_of(&bundle_digest.bundle_digest);
        if bundle_digest_hash != valid_bundle.bundle_digest {
            return Err(VerificationError::InvalidBundleDigest);
        }

        ext_values.extend(bundle_digest.bundle_digest.clone());
    }

    let storage_key = SK::block_randomness_key();
    let storage_proof = randomness_proof.clone();
    let block_randomness = StorageProofVerifier::<Hashing>::verify_and_get_value::<Randomness>(
        &consensus_state_root,
        storage_proof,
        storage_key,
    )
    .map_err(|_| VerificationError::InvalidProof)?;

    let shuffling_seed =
        H256::decode(&mut extrinsics_shuffling_seed::<Hashing>(block_randomness).as_ref())
            .map_err(|_| VerificationError::FailedToDecode)?;
    let ordered_extrinsics = deduplicate_and_shuffle_extrinsics(
        ext_values,
        Randomness::from(shuffling_seed.to_fixed_bytes()),
    );
    let ordered_trie_node_values = ordered_extrinsics
        .iter()
        .map(|ext_digest| match ext_digest {
            ExtrinsicDigest::Data(data) => Value::Inline(data),
            ExtrinsicDigest::Hash(hash) => Value::Node(hash.0.as_slice()),
        })
        .collect();
    // TODO: include timestamp and domain runtime upgrade extrinsic
    let extrinsics_root =
        valued_ordered_trie_root::<LayoutV1<BlakeTwo256>>(ordered_trie_node_values);
    if bad_receipt.domain_block_extrinsic_root == extrinsics_root {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}

fn extrinsics_shuffling_seed<Hashing>(block_randomness: Randomness) -> Hashing::Out
where
    Hashing: Hasher,
{
    let mut subject = EXTRINSICS_SHUFFLING_SEED.to_vec();
    subject.extend_from_slice(block_randomness.as_ref());
    Hashing::hash(&subject)
}

pub fn deduplicate_and_shuffle_extrinsics<Extrinsic>(
    mut extrinsics: Vec<(Option<AccountId>, Extrinsic)>,
    shuffling_seed: Randomness,
) -> Vec<Extrinsic>
where
    Extrinsic: Debug + PartialEq + Clone,
{
    let mut seen = Vec::new();
    extrinsics.retain(|(_, uxt)| match seen.contains(uxt) {
        true => {
            trace!(extrinsic = ?uxt, "Duplicated extrinsic");
            false
        }
        false => {
            seen.push(uxt.clone());
            true
        }
    });
    drop(seen);
    trace!(?extrinsics, "Origin deduplicated extrinsics");
    shuffle_extrinsics::<Extrinsic, AccountId>(extrinsics, shuffling_seed)
}

/// Shuffles the extrinsics in a deterministic way.
///
/// The extrinsics are grouped by the signer. The extrinsics without a signer, i.e., unsigned
/// extrinsics, are considered as a special group. The items in different groups are cross shuffled,
/// while the order of items inside the same group is still maintained.
pub fn shuffle_extrinsics<Extrinsic: Debug, AccountId: Ord + Clone>(
    extrinsics: Vec<(Option<AccountId>, Extrinsic)>,
    shuffling_seed: Randomness,
) -> Vec<Extrinsic> {
    let mut rng = ChaCha8Rng::from_seed(*shuffling_seed);

    let mut positions = extrinsics
        .iter()
        .map(|(maybe_signer, _)| maybe_signer)
        .cloned()
        .collect::<Vec<_>>();

    // Shuffles the positions using Fisher–Yates algorithm.
    positions.shuffle(&mut rng);

    let mut grouped_extrinsics: BTreeMap<Option<AccountId>, VecDeque<_>> = extrinsics
        .into_iter()
        .fold(BTreeMap::new(), |mut groups, (maybe_signer, tx)| {
            groups
                .entry(maybe_signer)
                .or_insert_with(VecDeque::new)
                .push_back(tx);
            groups
        });

    // The relative ordering for the items in the same group does not change.
    let shuffled_extrinsics = positions
        .into_iter()
        .map(|maybe_signer| {
            grouped_extrinsics
                .get_mut(&maybe_signer)
                .expect("Extrinsics are grouped correctly; qed")
                .pop_front()
                .expect("Extrinsic definitely exists as it's correctly grouped above; qed")
        })
        .collect::<Vec<_>>();

    trace!(?shuffled_extrinsics, "Shuffled extrinsics");

    shuffled_extrinsics
}
