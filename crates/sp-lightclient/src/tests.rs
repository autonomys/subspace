use crate::mock::{Header, MockStorage};
use crate::{
    ChainConstants, HashOf, HeaderExt, HeaderImporter, ImportError, NumberOf, SolutionRange,
    Storage,
};
use frame_support::{assert_err, assert_ok};
use schnorrkel::Keypair;
use sp_consensus_subspace::digests::{
    extract_subspace_digest_items, CompatibleDigestItem, PreDigest, SubspaceDigestItems,
};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature};
use sp_runtime::app_crypto::UncheckedFrom;
use sp_runtime::{Digest, DigestItem};
use std::cmp::Ordering;
use subspace_core_primitives::{Piece, Randomness, Salt, Solution, Tag, PIECE_SIZE};
use subspace_solving::{
    create_tag, create_tag_signature, derive_global_challenge, derive_local_challenge,
    derive_target, REWARD_SIGNING_CONTEXT,
};

fn default_randomness_and_salt() -> (Randomness, Salt) {
    let randomness = [1u8; 32];
    let salt = [2u8; 8];
    (randomness, salt)
}

fn default_test_constants() -> ChainConstants<Header> {
    ChainConstants { k_depth: 7 }
}

fn derive_solution_range(target: Tag, tag: Tag) -> SolutionRange {
    let target = u64::from_be_bytes(target);
    let tag = u64::from_be_bytes(tag);

    subspace_core_primitives::bidirectional_distance(&target, &tag) * 2
}

fn random_piece() -> Piece {
    rand::random::<[u8; PIECE_SIZE]>().into()
}

fn valid_header_with_default_randomness_and_salt(
    parent_hash: HashOf<Header>,
    number: NumberOf<Header>,
    slot: u64,
    keypair: &Keypair,
) -> (Header, SolutionRange) {
    let (randomness, salt) = default_randomness_and_salt();
    valid_header(parent_hash, number, slot, keypair, randomness, salt)
}

fn valid_header(
    parent_hash: HashOf<Header>,
    number: NumberOf<Header>,
    slot: u64,
    keypair: &Keypair,
    randomness: Randomness,
    salt: Salt,
) -> (Header, SolutionRange) {
    let encoding = random_piece();
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
        DigestItem::global_randomness(randomness),
        DigestItem::solution_range(solution_range),
        DigestItem::salt(salt),
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
        let (header, solution_range) =
            valid_header_with_default_randomness_and_salt(parent_hash, block_number, slot, keypair);
        parent_hash = header.hash();
        slot += 1;

        let (randomness, salt) = default_randomness_and_salt();
        let header_ext = HeaderExt {
            header,
            derived_global_randomness: randomness,
            derived_solution_range: solution_range,
            derived_salt: salt,
            total_weight: 0,
        };
        store.store_header(header_ext, true);
    }

    (parent_hash, slot)
}

#[test]
fn test_header_import_missing_parent() {
    let constants = default_test_constants();
    let mut store = MockStorage::new(constants);
    let keypair = Keypair::generate();
    let (_parent_hash, next_slot) = import_blocks_until(&mut store, 0, 0, &keypair);
    let (header, _) =
        valid_header_with_default_randomness_and_salt(Default::default(), 1, next_slot, &keypair);
    assert_err!(
        HeaderImporter::import_header(&mut store, header.clone()),
        ImportError::MissingParent(header.hash())
    );
}

fn header_import_reorg_at_same_height(new_header_weight: Ordering) {
    let constants = default_test_constants();
    let mut store = MockStorage::new(constants);
    let keypair = Keypair::generate();
    let (parent_hash, next_slot) = import_blocks_until(&mut store, 2, 1, &keypair);
    let best_header = store.best_header();
    assert_eq!(best_header.header.hash(), parent_hash);

    // import block 3
    let (header, solution_range) =
        valid_header_with_default_randomness_and_salt(parent_hash, 3, next_slot, &keypair);
    store.override_solution_range(parent_hash, solution_range);
    assert_ok!(HeaderImporter::import_header(&mut store, header.clone()));
    let best_header_ext = store.best_header();
    assert_eq!(best_header_ext.header, header);
    let mut best_header = header;

    // try an import another fork at 3
    let (header, solution_range) =
        valid_header_with_default_randomness_and_salt(parent_hash, 3, next_slot + 1, &keypair);
    let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
        extract_subspace_digest_items(&header).unwrap();
    let new_weight = HeaderImporter::<Header, MockStorage>::calculate_block_weight(
        &digests.global_randomness,
        &digests.pre_digest,
    );
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
    assert_ok!(HeaderImporter::import_header(&mut store, header));
    let best_header_ext = store.best_header();
    assert_eq!(best_header_ext.header, best_header);
    // we still track the forks
    assert_eq!(store.headers_at_number(3).len(), 2);
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

fn ensure_finalized_heads_have_no_forks(store: &MockStorage, finalized_number: NumberOf<Header>) {
    let finalized_header = store.finalized_header();
    let (expected_finalized_number, hash) = (
        finalized_header.header.number,
        finalized_header.header.hash(),
    );
    assert_eq!(expected_finalized_number, finalized_number);
    assert_eq!(store.headers_at_number(finalized_number).len(), 1);
    if finalized_number < 1 {
        return;
    }

    let header = store.header(hash).unwrap();
    let mut parent_hash = header.header.parent_hash;
    let mut finalized_number = finalized_number - 1;
    while finalized_number > 0 {
        assert_eq!(store.headers_at_number(finalized_number).len(), 1);
        let hash = store.headers_at_number(finalized_number)[0].header.hash();
        assert_eq!(parent_hash, hash);
        parent_hash = store.header(hash).unwrap().header.parent_hash;
        finalized_number -= 1;
    }
}

#[test]
fn test_header_import_success() {
    let mut store = MockStorage::new(default_test_constants());
    let keypair = Keypair::generate();
    let (parent_hash, next_slot) = import_blocks_until(&mut store, 2, 1, &keypair);
    let best_header = store.best_header();
    assert_eq!(best_header.header.hash(), parent_hash);

    // verify and import next headers
    let mut slot = next_slot;
    let mut parent_hash = parent_hash;
    for number in 3..=10 {
        let (header, solution_range) =
            valid_header_with_default_randomness_and_salt(parent_hash, number, slot, &keypair);
        store.override_solution_range(parent_hash, solution_range);
        let res = HeaderImporter::import_header(&mut store, header.clone());
        assert_ok!(res);
        // best header should be correct
        let best_header = store.best_header();
        assert_eq!(best_header.header, header);
        slot += 1;
        parent_hash = header.hash();
    }

    // finalized head must be best 10 - 7 = 3
    let finalized_header = store.finalized_header();
    assert_eq!(finalized_header.header.number, 3);

    // header count at the finalized head must be 1
    ensure_finalized_heads_have_no_forks(&store, 3);
}

fn create_fork_chain_from(
    store: &mut MockStorage,
    parent_hash: HashOf<Header>,
    from: NumberOf<Header>,
    until: NumberOf<Header>,
    slot: u64,
    keypair: &Keypair,
) -> (HashOf<Header>, u64) {
    let best_header_ext = store.best_header();
    let mut parent_hash = parent_hash;
    let mut next_slot = slot + 1;
    for number in from..=until {
        let (header, solution_range) =
            valid_header_with_default_randomness_and_salt(parent_hash, number, next_slot, keypair);
        let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
            extract_subspace_digest_items(&header).unwrap();
        let new_weight = HeaderImporter::<Header, MockStorage>::calculate_block_weight(
            &digests.global_randomness,
            &digests.pre_digest,
        );
        store.override_solution_range(parent_hash, solution_range);
        store.override_cumulative_weight(best_header_ext.header.hash(), new_weight + 1);
        // override parent weight to 0
        store.override_cumulative_weight(parent_hash, 0);
        parent_hash = header.hash();
        next_slot += 1;
        assert_ok!(HeaderImporter::import_header(store, header));
        // best header should not change
        assert_eq!(store.best_header().header, best_header_ext.header);
    }

    (parent_hash, next_slot)
}

#[test]
fn test_finalized_chain_reorg_to_longer_chain() {
    let mut constants = default_test_constants();
    constants.k_depth = 4;
    let mut store = MockStorage::new(constants);
    let keypair = Keypair::generate();
    let (parent_hash, next_slot) = import_blocks_until(&mut store, 4, 1, &keypair);
    let best_header = store.best_header();
    assert_eq!(best_header.header.hash(), parent_hash);

    // create a fork chain from number 1
    let genesis_hash = store.headers_at_number(0)[0].header.hash();
    create_fork_chain_from(&mut store, genesis_hash, 1, 5, next_slot + 1, &keypair);
    assert_eq!(best_header.header.hash(), parent_hash);
    // block 0 should be finalized
    assert_eq!(store.finalized_header().header.number, 0);
    ensure_finalized_heads_have_no_forks(&store, 0);

    // add new best header at 5
    let (header, solution_range) =
        valid_header_with_default_randomness_and_salt(parent_hash, 5, next_slot, &keypair);
    store.override_solution_range(parent_hash, solution_range);
    let res = HeaderImporter::import_header(&mut store, header.clone());
    assert_ok!(res);
    let best_header = store.best_header();
    assert_eq!(best_header.header, header);

    // block 1 should be finalized
    assert_eq!(store.finalized_header().header.number, 1);
    ensure_finalized_heads_have_no_forks(&store, 1);

    // create a fork chain from number 5
    let (fork_parent_hash, fork_next_slot) =
        create_fork_chain_from(&mut store, parent_hash, 5, 8, next_slot, &keypair);

    // best header should still be the same
    assert_eq!(best_header.header, store.best_header().header);

    // there must be 2 heads at 5
    assert_eq!(store.headers_at_number(5).len(), 2);

    // block 1 should be finalized
    assert_eq!(store.finalized_header().header.number, 1);
    ensure_finalized_heads_have_no_forks(&store, 1);

    // import a new head to the fork chain and make it the best.
    let (header, solution_range) = valid_header_with_default_randomness_and_salt(
        fork_parent_hash,
        9,
        fork_next_slot,
        &keypair,
    );
    let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
        extract_subspace_digest_items(&header).unwrap();
    let new_weight = HeaderImporter::<Header, MockStorage>::calculate_block_weight(
        &digests.global_randomness,
        &digests.pre_digest,
    );
    store.override_solution_range(fork_parent_hash, solution_range);
    store.override_cumulative_weight(store.best_header().header.hash(), new_weight - 1);
    // override parent weight to 0
    store.override_cumulative_weight(fork_parent_hash, 0);
    let res = HeaderImporter::import_header(&mut store, header.clone());
    assert_ok!(res);
    assert_eq!(store.best_header().header, header);

    // now the finalized header must be 5
    ensure_finalized_heads_have_no_forks(&store, 5)
}

#[test]
fn test_reorg_to_heavier_smaller_chain() {
    let mut constants = default_test_constants();
    constants.k_depth = 4;
    let mut store = MockStorage::new(constants);
    let keypair = Keypair::generate();
    let (parent_hash, next_slot) = import_blocks_until(&mut store, 2, 1, &keypair);
    let best_header = store.best_header();
    assert_eq!(best_header.header.hash(), parent_hash);

    // verify and import next headers
    let mut slot = next_slot;
    let mut parent_hash = parent_hash;
    let fork_parent_hash = parent_hash;
    for number in 3..=5 {
        let (header, solution_range) =
            valid_header_with_default_randomness_and_salt(parent_hash, number, slot, &keypair);
        store.override_solution_range(parent_hash, solution_range);
        let res = HeaderImporter::import_header(&mut store, header.clone());
        assert_ok!(res);
        // best header should be correct
        let best_header = store.best_header();
        assert_eq!(best_header.header, header);
        slot += 1;
        parent_hash = header.hash();
    }

    // finalized head must be best(5) - 4 = 1
    let number = store.finalized_header().header.number;
    assert_eq!(number, 1);

    // header count at the finalized head must be 1
    ensure_finalized_heads_have_no_forks(&store, 1);

    // now import a fork header 3 that becomes canonical
    let (header, solution_range) =
        valid_header_with_default_randomness_and_salt(fork_parent_hash, 3, next_slot + 1, &keypair);
    let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
        extract_subspace_digest_items(&header).unwrap();
    let new_weight = HeaderImporter::<Header, MockStorage>::calculate_block_weight(
        &digests.global_randomness,
        &digests.pre_digest,
    );
    store.override_solution_range(fork_parent_hash, solution_range);
    store.override_cumulative_weight(store.best_header().header.hash(), new_weight - 1);
    // override parent weight to 0
    store.override_cumulative_weight(fork_parent_hash, 0);
    let res = HeaderImporter::import_header(&mut store, header);
    assert_err!(res, ImportError::SwitchedToForkBelowArchivingDepth)
}
