use crate::mock::{Header, MockImporter, MockStorage, NumberOf};
use crate::{
    calculate_block_weight, extract_header_digests, verify_header_digest_with_parent, HashOf,
    HeaderExt, HeaderImporter, ImportError, SolutionRange, Storage,
};
use frame_support::{assert_err, assert_ok};
use schnorrkel::Keypair;
use sp_consensus_subspace::digests::{
    find_pre_digest, CompatibleDigestItem, GlobalRandomnessDescriptor, PreDigest, SaltDescriptor,
    SolutionRangeDescriptor,
};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature};
use sp_runtime::app_crypto::UncheckedFrom;
use sp_runtime::{Digest, DigestItem};
use std::cmp::Ordering;
use subspace_core_primitives::{Piece, Randomness, Salt, Solution, Tag};
use subspace_solving::{
    create_tag, create_tag_signature, derive_global_challenge, derive_local_challenge,
    derive_target, REWARD_SIGNING_CONTEXT,
};

#[test]
fn test_header_digest_extraction() {
    let mut header = Header {
        parent_hash: [0u8; 32].into(),
        number: 1,
        state_root: Default::default(),
        extrinsics_root: Default::default(),
        digest: Default::default(),
    };

    let res = extract_header_digests(&header);
    assert_err!(res, ImportError::InvalidGlobalRandomnessDigest);

    let randomness = GlobalRandomnessDescriptor {
        global_randomness: Default::default(),
    };
    header
        .digest
        .logs
        .push(DigestItem::global_randomness_descriptor(randomness));
    let res = extract_header_digests(&header);
    assert_err!(res, ImportError::InvalidSolutionRangeDigest);

    let solution_range = SolutionRangeDescriptor { solution_range: 0 };
    header
        .digest
        .logs
        .push(DigestItem::solution_range_descriptor(solution_range));
    let res = extract_header_digests(&header);
    assert_err!(res, ImportError::InvalidSaltDigest);

    let salt = SaltDescriptor {
        salt: Default::default(),
    };
    header.digest.logs.push(DigestItem::salt_descriptor(salt));
    let res = extract_header_digests(&header);
    assert_ok!(res);
}

#[test]
fn verify_header_digests() {
    let expected_randomness = [1u8; 32];
    let expected_solution_range = 0;
    let expected_salt = [2u8; 8];

    let parent_header_ext = HeaderExt {
        header: Header {
            parent_hash: Default::default(),
            number: 0,
            state_root: Default::default(),
            extrinsics_root: Default::default(),
            digest: Default::default(),
        },
        derived_global_randomness: expected_randomness,
        derived_solution_range: expected_solution_range,
        derived_salt: expected_salt,
        total_weight: 0,
    };

    let mut header = Header {
        parent_hash: parent_header_ext.header.parent_hash,
        number: 1,
        state_root: Default::default(),
        extrinsics_root: Default::default(),
        digest: Default::default(),
    };
    let randomness = GlobalRandomnessDescriptor {
        global_randomness: expected_randomness,
    };
    header
        .digest
        .logs
        .push(DigestItem::global_randomness_descriptor(randomness));
    let solution_range = SolutionRangeDescriptor {
        solution_range: expected_solution_range,
    };
    header
        .digest
        .logs
        .push(DigestItem::solution_range_descriptor(solution_range));
    let salt = SaltDescriptor {
        salt: expected_salt,
    };
    header.digest.logs.push(DigestItem::salt_descriptor(salt));

    let res = verify_header_digest_with_parent(&parent_header_ext, &header);
    assert_ok!(res);
}

fn default_randomness_and_salt() -> (Randomness, Salt) {
    let randomness = [1u8; 32];
    let salt = [2u8; 8];
    (randomness, salt)
}

fn derive_solution_range(target: Tag, tag: Tag) -> SolutionRange {
    let target = u64::from_be_bytes(target);
    let tag = u64::from_be_bytes(tag);

    subspace_core_primitives::bidirectional_distance(&target, &tag) * 2
}

fn valid_header(
    parent_hash: HashOf<Header>,
    number: NumberOf<Header>,
    slot: u64,
    keypair: &Keypair,
) -> (Header, SolutionRange) {
    let (randomness, salt) = default_randomness_and_salt();
    let encoding = Piece::default();
    let tag: Tag = create_tag(encoding.as_ref(), salt);
    let global_challenge = derive_global_challenge(&randomness, slot);
    let local_challenge = derive_local_challenge(keypair, global_challenge);
    let target = derive_target(
        &schnorrkel::PublicKey::from_bytes(keypair.public.as_ref()).unwrap(),
        global_challenge,
        &local_challenge,
    )
    .unwrap();
    let solution_range = derive_solution_range(target, tag);
    let ctx = schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT);

    let digests = vec![
        DigestItem::global_randomness_descriptor(GlobalRandomnessDescriptor {
            global_randomness: randomness,
        }),
        DigestItem::solution_range_descriptor(SolutionRangeDescriptor { solution_range }),
        DigestItem::salt_descriptor(SaltDescriptor { salt }),
        DigestItem::subspace_pre_digest(&PreDigest {
            slot: slot.into(),
            solution: Solution {
                public_key: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
                reward_address: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
                piece_index: 0,
                encoding,
                tag_signature: create_tag_signature(keypair, tag),
                local_challenge,
                tag,
            },
        }),
    ];
    let mut header = Header {
        parent_hash,
        number,
        state_root: Default::default(),
        extrinsics_root: Default::default(),
        digest: Digest { logs: digests },
    };

    let pre_hash = header.hash();
    let signature =
        FarmerSignature::unchecked_from(keypair.sign(ctx.bytes(pre_hash.as_bytes())).to_bytes());
    header
        .digest
        .logs
        .push(DigestItem::subspace_seal(signature));

    (header, solution_range)
}

fn import_blocks_until(
    store: &mut MockStorage,
    number: NumberOf<Header>,
    start_slot: u64,
    keypair: &Keypair,
) -> (HashOf<Header>, u64) {
    let mut parent_hash = Default::default();
    let mut slot = start_slot;
    for block_number in 0..=number {
        let (header, solution_range) = valid_header(parent_hash, block_number, slot, keypair);
        let (randomness, salt) = default_randomness_and_salt();
        parent_hash = header.hash();
        slot += 1;
        store.store_header(
            HeaderExt {
                header,
                derived_global_randomness: randomness,
                derived_solution_range: solution_range,
                derived_salt: salt,
                total_weight: 0,
            },
            true,
        );
    }

    (parent_hash, slot)
}

#[test]
fn test_header_import_missing_parent() {
    let mut store = MockStorage::default();
    let keypair = Keypair::generate();
    let slot = 1;
    let (header, _) = valid_header(Default::default(), 0, slot, &keypair);
    let hash = header.hash();
    let res = MockImporter::import_header(&mut store, header);
    assert_err!(res, ImportError::MissingParent(hash));
}

fn header_import_reorg_at_same_height(new_header_weight: Ordering) {
    let mut store = MockStorage::default();
    let keypair = Keypair::generate();
    let (parent_hash, next_slot) = import_blocks_until(&mut store, 2, 1, &keypair);
    let best_header = store.best_header();
    assert_eq!(best_header.header.hash(), parent_hash);

    // import block 3
    let (header, solution_range) = valid_header(parent_hash, 3, next_slot, &keypair);
    store.override_solution_range(parent_hash, solution_range);
    let res = MockImporter::import_header(&mut store, header.clone());
    assert_ok!(res);
    let best_header_ext = store.best_header();
    assert_eq!(best_header_ext.header, header);
    let mut best_header = header;

    // try an import another fork at 3
    let (header, solution_range) = valid_header(parent_hash, 3, next_slot + 1, &keypair);
    let (randomness, _, _) = extract_header_digests(&header).unwrap();
    let pre_digest = find_pre_digest(&header).unwrap();
    let new_weight = calculate_block_weight(&randomness.global_randomness, &pre_digest);
    store.override_solution_range(parent_hash, solution_range);
    match new_header_weight {
        Ordering::Less => {
            store.override_cumulative_weight(best_header_ext.header.hash(), new_weight + 1);
        }
        Ordering::Equal => {
            store.override_cumulative_weight(best_header_ext.header.hash(), new_weight);
        }
        Ordering::Greater => {
            store.override_cumulative_weight(best_header_ext.header.hash(), new_weight - 1);
            best_header = header.clone();
        }
    };
    let res = MockImporter::import_header(&mut store, header);
    assert_ok!(res);
    let best_header_ext = store.best_header();
    assert_eq!(best_header_ext.header, best_header);
    // we still track the forks
    assert_eq!(store.headers_at(3).len(), 2);
}

#[test]
fn test_header_import_non_canonical() {
    header_import_reorg_at_same_height(Ordering::Less)
}

#[test]
fn test_header_import_canonical() {
    header_import_reorg_at_same_height(Ordering::Greater)
}

#[test]
fn test_header_import_non_canonical_with_equal_block_weight() {
    header_import_reorg_at_same_height(Ordering::Equal)
}

#[test]
fn test_header_import_success() {
    let mut store = MockStorage::default();
    let keypair = Keypair::generate();
    let (parent_hash, next_slot) = import_blocks_until(&mut store, 2, 1, &keypair);
    let best_header = store.best_header();
    assert_eq!(best_header.header.hash(), parent_hash);

    // verify and import next headers
    let mut slot = next_slot;
    let mut parent_hash = parent_hash;
    for number in 3..=10 {
        let (header, solution_range) = valid_header(parent_hash, number, slot, &keypair);
        store.override_solution_range(parent_hash, solution_range);
        let res = MockImporter::import_header(&mut store, header.clone());
        assert_ok!(res);
        // best header should be correct
        let best_header = store.best_header();
        assert_eq!(best_header.header, header);
        slot += 1;
        parent_hash = header.hash();
    }
}
