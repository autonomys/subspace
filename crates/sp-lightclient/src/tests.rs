use crate::mock::{Header, MockImporter, MockStorage};
use crate::{
    calculate_block_weight, derive_next_eon_index, ChainConstants, HashOf, HeaderExt,
    HeaderImporter, ImportError, NumberOf, SolutionRange, Storage,
};
use frame_support::{assert_err, assert_ok};
use rand_core::RngCore;
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
use subspace_verification::{derive_next_solution_range, derive_randomness};

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

fn random_piece() -> Piece {
    let mut data = [0u8; PIECE_SIZE];
    rand_core::OsRng::default().fill_bytes(&mut data);
    data.into()
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
    eon_duration: u64,
    keypair: &Keypair,
) -> (HashOf<Header>, u64) {
    let mut parent_hash = Default::default();
    let mut slot = start_slot;
    let mut parent_header = None;
    let genesis_slot = start_slot;
    for block_number in 0..=number {
        let (header, _solution_range) =
            valid_header_with_default_randomness_and_salt(parent_hash, block_number, slot, keypair);
        parent_hash = header.hash();
        slot += 1;
        let eon_index = if let Some(parent_header) = parent_header {
            derive_next_eon_index(
                eon_duration,
                &parent_header,
                &header,
                slot.into(),
                genesis_slot.into(),
            )
            .unwrap()
        } else {
            0
        };

        let header_ext = HeaderExt {
            header,
            total_weight: 0,
            eon_index,
            should_update_salt: false,
            next_salt: None,
            overrides: Default::default(),
        };
        parent_header = Some(header_ext.clone());
        store.store_header(header_ext, true);
    }

    (parent_hash, slot)
}

fn default_test_constants() -> ChainConstants<Header> {
    ChainConstants {
        randomness_interval: 10,
        era_duration: 10,
        k_depth: 7,
        slot_probability: (1, 6),
        eon_duration: 10,
        next_salt_reveal_duration: 4,
    }
}

#[test]
fn test_header_import_missing_parent() {
    let constants = default_test_constants();
    let mut store = MockStorage::new(constants.clone());
    let keypair = Keypair::generate();
    let (_parent_hash, next_slot) =
        import_blocks_until(&mut store, 0, 0, constants.eon_duration, &keypair);
    let (header, _) =
        valid_header_with_default_randomness_and_salt(Default::default(), 1, next_slot, &keypair);
    assert_err!(
        MockImporter::import_header(&mut store, header.clone()),
        ImportError::MissingParent(header.hash())
    );
}

fn header_import_reorg_at_same_height(new_header_weight: Ordering) {
    let constants = default_test_constants();
    let mut store = MockStorage::new(constants.clone());
    let keypair = Keypair::generate();
    let (parent_hash, next_slot) =
        import_blocks_until(&mut store, 2, 1, constants.eon_duration, &keypair);
    let best_header = store.best_header();
    assert_eq!(best_header.header.hash(), parent_hash);

    // import block 3
    let (header, solution_range) =
        valid_header_with_default_randomness_and_salt(parent_hash, 3, next_slot, &keypair);
    store.override_solution_range(parent_hash, solution_range);
    assert_ok!(MockImporter::import_header(&mut store, header.clone()));
    let best_header_ext = store.best_header();
    assert_eq!(best_header_ext.header, header);
    let mut best_header = header;

    // try an import another fork at 3
    let (header, solution_range) =
        valid_header_with_default_randomness_and_salt(parent_hash, 3, next_slot + 1, &keypair);
    let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
        extract_subspace_digest_items(&header).unwrap();
    let new_weight = calculate_block_weight(&digests.global_randomness, &digests.pre_digest);
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
    assert_ok!(MockImporter::import_header(&mut store, header));
    let best_header_ext = store.best_header();
    assert_eq!(best_header_ext.header, best_header);
    // we still track the forks
    assert_eq!(store.heads_at_number(3).len(), 2);
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
    let mut constants = default_test_constants();
    constants.eon_duration = 9;
    let mut store = MockStorage::new(constants.clone());
    let keypair = Keypair::generate();
    let (parent_hash, next_slot) =
        import_blocks_until(&mut store, 2, 1, constants.eon_duration, &keypair);
    let best_header = store.best_header();
    assert_eq!(best_header.header.hash(), parent_hash);

    // verify and import next headers
    let mut slot = next_slot;
    let mut parent_hash = parent_hash;
    for number in 3..=10 {
        let (header, solution_range) =
            valid_header_with_default_randomness_and_salt(parent_hash, number, slot, &keypair);
        store.override_solution_range(parent_hash, solution_range);
        let res = MockImporter::import_header(&mut store, header.clone());
        assert_ok!(res);
        // best header should be correct
        let best_header = store.best_header();
        assert_eq!(best_header.header, header);
        slot += 1;
        parent_hash = header.hash();
    }

    // finalized head must be best 10 - 7 = 3
    let (number, _) = store.finalized_head();
    assert_eq!(number, 3);

    // header count at the finalized head must be 1
    ensure_finalized_heads_have_no_forks(&store, 3);

    let header = store.header(store.heads_at_number(10)[0]).unwrap();
    let digest_items =
        extract_subspace_digest_items::<Header, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header.header,
        )
        .unwrap();
    let derived_items = header.derive_digest_items(&store).unwrap();

    // check for updated global randomness at block number 10
    let expected_global_randomness = derive_randomness(
        &Into::<subspace_core_primitives::PublicKey>::into(
            &digest_items.pre_digest.solution.public_key,
        ),
        digest_items.pre_digest.solution.tag,
        &digest_items.pre_digest.solution.tag_signature,
    )
    .unwrap();
    assert_ne!(expected_global_randomness, digest_items.global_randomness);
    assert_eq!(expected_global_randomness, derived_items.global_randomness);

    // check for updated solution range at block 10
    let ancestor_header = store.header(store.heads_at_number(1)[0]).unwrap();
    let ancestor_digests =
        extract_subspace_digest_items::<Header, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &ancestor_header.header,
        )
        .unwrap();
    let expected_solution_range = derive_next_solution_range(
        u64::from(ancestor_digests.pre_digest.slot),
        u64::from(digest_items.pre_digest.slot),
        store.constants().slot_probability,
        digest_items.solution_range,
        store
            .constants()
            .era_duration
            .try_into()
            .unwrap_or_else(|_| panic!("Era duration is always within u64; qed")),
    );
    assert_ne!(expected_solution_range, digest_items.solution_range);
    assert_eq!(expected_solution_range, derived_items.solution_range);

    // eon index should be 0 at block #9
    assert_eq!(
        store.header(header.header.parent_hash).unwrap().eon_index,
        0
    );
    assert!(
        !store
            .header(header.header.parent_hash)
            .unwrap()
            .should_update_salt
    );
    // eon index should be 1 at block #10
    assert_eq!(header.eon_index, 1);
    assert!(header.should_update_salt);

    // next salt should not be derived at Block #3. Salt reveal edge
    assert_eq!(
        store.header(store.heads_at_number(3)[0]).unwrap().next_salt,
        None
    );
    assert!(
        !store
            .header(store.heads_at_number(3)[0])
            .unwrap()
            .should_update_salt
    );

    // next salt is revealed at Block #5
    assert!(store
        .header(store.heads_at_number(5)[0])
        .unwrap()
        .next_salt
        .is_some());
    let expected_salt = store
        .header(store.heads_at_number(5)[0])
        .unwrap()
        .next_salt
        .unwrap();
    assert!(
        !store
            .header(store.heads_at_number(5)[0])
            .unwrap()
            .should_update_salt
    );

    // next salt is used in block #11
    assert_ne!(expected_salt, digest_items.salt);
    assert_eq!(expected_salt, derived_items.salt);

    // import Block #11 with expected randomness and salt
    let parent_hash = header.header.hash();
    let (header, solution_range) = valid_header(
        parent_hash,
        11,
        slot,
        &keypair,
        expected_global_randomness,
        expected_salt,
    );
    store.override_solution_range(parent_hash, solution_range);
    let res = MockImporter::import_header(&mut store, header.clone());
    assert_ok!(res);
    // best header should be correct
    let best_header = store.best_header();
    assert_eq!(best_header.header, header);

    // next salt should be empty
    assert_eq!(best_header.next_salt, None);
    assert!(!best_header.should_update_salt);
}

fn ensure_finalized_heads_have_no_forks(store: &MockStorage, finalized_number: NumberOf<Header>) {
    let (expected_finalized_number, hash) = store.finalized_head();
    assert_eq!(expected_finalized_number, finalized_number);
    assert_eq!(store.heads_at_number(finalized_number).len(), 1);
    let header = store.header(hash).unwrap();
    let mut parent_hash = header.header.parent_hash;
    let mut finalized_number = finalized_number - 1;
    while finalized_number > 0 {
        assert_eq!(store.heads_at_number(finalized_number).len(), 1);
        let hash = store.heads_at_number(finalized_number)[0];
        assert_eq!(parent_hash, hash);
        parent_hash = store.header(hash).unwrap().header.parent_hash;
        finalized_number -= 1;
    }
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
        let new_weight = calculate_block_weight(&digests.global_randomness, &digests.pre_digest);
        store.override_solution_range(parent_hash, solution_range);
        store.override_cumulative_weight(best_header_ext.header.hash(), new_weight + 1);
        // override parent weight to 0
        store.override_cumulative_weight(parent_hash, 0);
        parent_hash = header.hash();
        next_slot += 1;
        assert_ok!(MockImporter::import_header(store, header));
        // best header should not change
        assert_eq!(store.best_header().header, best_header_ext.header);
    }

    (parent_hash, next_slot)
}

#[test]
fn test_finalized_chain_reorg_to_longer_chain() {
    let mut constants = default_test_constants();
    constants.k_depth = 4;
    let mut store = MockStorage::new(constants.clone());
    let keypair = Keypair::generate();
    let (parent_hash, next_slot) =
        import_blocks_until(&mut store, 3, 1, constants.eon_duration, &keypair);
    let best_header = store.best_header();
    assert_eq!(best_header.header.hash(), parent_hash);

    // add new best header at 4
    let (header, solution_range) =
        valid_header_with_default_randomness_and_salt(parent_hash, 4, next_slot, &keypair);
    store.override_solution_range(parent_hash, solution_range);
    let res = MockImporter::import_header(&mut store, header.clone());
    assert_ok!(res);
    let best_header = store.best_header();
    assert_eq!(best_header.header, header);

    // create a fork chain from number 3
    let (fork_parent_hash, fork_next_slot) =
        create_fork_chain_from(&mut store, parent_hash, 4, 7, next_slot, &keypair);

    // best header should still be the same
    assert_eq!(best_header.header, store.best_header().header);

    // there must be 2 heads at 3
    assert_eq!(store.heads_at_number(4).len(), 2);

    // block 0 should be finalized
    assert_eq!(store.finalized_head().0, 0);

    // import a new head to the fork chain and make it the best.
    let (header, solution_range) = valid_header_with_default_randomness_and_salt(
        fork_parent_hash,
        8,
        fork_next_slot,
        &keypair,
    );
    let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
        extract_subspace_digest_items(&header).unwrap();
    let new_weight = calculate_block_weight(&digests.global_randomness, &digests.pre_digest);
    store.override_solution_range(fork_parent_hash, solution_range);
    store.override_cumulative_weight(store.best_header().header.hash(), new_weight - 1);
    // override parent weight to 0
    store.override_cumulative_weight(fork_parent_hash, 0);
    let res = MockImporter::import_header(&mut store, header.clone());
    assert_ok!(res);
    assert_eq!(store.best_header().header, header);

    // now the finalized header must be 4
    ensure_finalized_heads_have_no_forks(&store, 4)
}

#[test]
fn test_reorg_to_heavier_smaller_chain() {
    let mut constants = default_test_constants();
    constants.k_depth = 4;
    let mut store = MockStorage::new(constants.clone());
    let keypair = Keypair::generate();
    let (parent_hash, next_slot) =
        import_blocks_until(&mut store, 2, 1, constants.eon_duration, &keypair);
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
        let res = MockImporter::import_header(&mut store, header.clone());
        assert_ok!(res);
        // best header should be correct
        let best_header = store.best_header();
        assert_eq!(best_header.header, header);
        slot += 1;
        parent_hash = header.hash();
    }

    // finalized head must be best(5) - 4 = 1
    let (number, _) = store.finalized_head();
    assert_eq!(number, 1);

    // header count at the finalized head must be 1
    ensure_finalized_heads_have_no_forks(&store, 1);

    // now import a fork header 3 that becomes canonical
    let (header, solution_range) =
        valid_header_with_default_randomness_and_salt(fork_parent_hash, 3, next_slot + 1, &keypair);
    let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
        extract_subspace_digest_items(&header).unwrap();
    let new_weight = calculate_block_weight(&digests.global_randomness, &digests.pre_digest);
    store.override_solution_range(fork_parent_hash, solution_range);
    store.override_cumulative_weight(store.best_header().header.hash(), new_weight - 1);
    // override parent weight to 0
    store.override_cumulative_weight(fork_parent_hash, 0);
    let res = MockImporter::import_header(&mut store, header.clone());
    assert_ok!(res);
    assert_eq!(store.best_header().header, header);

    // finalized head must be set back to genesis
    let (number, _) = store.finalized_head();
    assert_eq!(number, 0);

    // fork heads should still be present at the number 3 as its not finalized
    assert_eq!(store.heads_at_number(3).len(), 2)
}
