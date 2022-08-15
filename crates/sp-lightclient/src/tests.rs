use crate::mock::{Header, MockStorage};
use crate::{
    ChainConstants, DigestError, HashOf, HeaderExt, HeaderImporter, ImportError, NextDigestItems,
    NumberOf, SaltDerivationInfo, Storage,
};
use frame_support::{assert_err, assert_ok};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    extract_pre_digest, extract_subspace_digest_items, CompatibleDigestItem, ErrorDigestType,
    PreDigest, SubspaceDigestItems,
};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature};
use sp_runtime::app_crypto::UncheckedFrom;
use sp_runtime::{Digest, DigestItem};
use std::cmp::Ordering;
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::{
    EonIndex, Piece, Randomness, RecordsRoot, Salt, SegmentIndex, Solution, SolutionRange, Tag,
    PIECE_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, RECORD_SIZE,
};
use subspace_solving::{
    create_tag, create_tag_signature, derive_global_challenge, derive_local_challenge,
    derive_target, SubspaceCodec, REWARD_SIGNING_CONTEXT,
};
use subspace_verification::{
    derive_next_eon_index, derive_next_salt_from_randomness, derive_next_solution_range,
    derive_randomness,
};

fn default_randomness_and_salt() -> (Randomness, Salt) {
    let randomness = [1u8; 32];
    let salt = [2u8; 8];
    (randomness, salt)
}

fn default_test_constants() -> ChainConstants<Header> {
    let (randomness, salt) = default_randomness_and_salt();
    ChainConstants {
        k_depth: 7,
        genesis_digest_items: NextDigestItems {
            next_global_randomness: randomness,
            next_solution_range: Default::default(),
            next_salt: salt,
        },
        max_plot_size: 100 * 1024 * 1024 * 1024 / PIECE_SIZE as u64,
        genesis_records_roots: Default::default(),
        global_randomness_interval: 20,
        era_duration: 20,
        slot_probability: (1, 6),
        eon_duration: 20,
        next_salt_reveal_interval: 6,
    }
}

fn derive_solution_range(target: Tag, tag: Tag) -> SolutionRange {
    let target = u64::from_be_bytes(target);
    let tag = u64::from_be_bytes(tag);

    subspace_core_primitives::bidirectional_distance(&target, &tag) * 2
}

fn valid_piece(pub_key: schnorrkel::PublicKey) -> (Piece, u64, SegmentIndex, RecordsRoot) {
    // we don't care about the block data
    let mut rng = StdRng::seed_from_u64(0);
    let mut block = vec![0u8; RECORDED_HISTORY_SEGMENT_SIZE as usize];
    rng.fill(block.as_mut_slice());

    let mut archiver =
        Archiver::new(RECORD_SIZE as usize, RECORDED_HISTORY_SEGMENT_SIZE as usize).unwrap();

    let archived_segment = archiver
        .add_block(block, Default::default())
        .first()
        .cloned()
        .unwrap();

    let (position, piece) = archived_segment
        .pieces
        .as_pieces()
        .enumerate()
        .collect::<Vec<(usize, &[u8])>>()
        .first()
        .cloned()
        .unwrap();

    assert!(subspace_archiving::archiver::is_piece_valid(
        piece,
        archived_segment.root_block.records_root(),
        position,
        RECORD_SIZE as usize,
    ));

    let codec = SubspaceCodec::new(pub_key.as_ref());
    let mut piece = piece.to_vec();
    codec.encode(&mut piece, position as u64).unwrap();

    (
        Piece::try_from(piece.as_slice()).unwrap(),
        position as u64,
        archived_segment.root_block.segment_index(),
        archived_segment.root_block.records_root(),
    )
}

fn valid_header_with_default_randomness_and_salt(
    parent_hash: HashOf<Header>,
    number: NumberOf<Header>,
    slot: u64,
    keypair: &Keypair,
) -> (Header, SolutionRange, SegmentIndex, RecordsRoot) {
    let (randomness, salt) = default_randomness_and_salt();
    valid_header(ValidHeaderParams {
        parent_hash,
        number,
        slot,
        keypair,
        randomness,
        salt,
        should_add_next_randomness: false,
        maybe_next_solution_range: None,
        maybe_next_salt: None,
        maybe_derive_salt_from_predigest: None,
    })
}

fn valid_header_with_next_digests(
    parent_hash: HashOf<Header>,
    number: NumberOf<Header>,
    slot: u64,
    keypair: &Keypair,
    should_add_next_randomness: bool,
    maybe_next_solution_range: Option<(Slot, (u64, u64), NumberOf<Header>)>,
    maybe_next_salt: Option<Salt>,
) -> (Header, SolutionRange, SegmentIndex, RecordsRoot) {
    let (randomness, salt) = default_randomness_and_salt();
    valid_header(ValidHeaderParams {
        parent_hash,
        number,
        slot,
        keypair,
        randomness,
        salt,
        should_add_next_randomness,
        maybe_next_solution_range,
        maybe_next_salt,
        maybe_derive_salt_from_predigest: None,
    })
}

fn valid_header_with_next_salt_revealed_at_this_header(
    parent_hash: HashOf<Header>,
    number: NumberOf<Header>,
    slot: u64,
    keypair: &Keypair,
    maybe_derive_salt_from_predigest: Option<EonIndex>,
) -> (Header, SolutionRange, SegmentIndex, RecordsRoot) {
    let (randomness, salt) = default_randomness_and_salt();
    valid_header(ValidHeaderParams {
        parent_hash,
        number,
        slot,
        keypair,
        randomness,
        salt,
        should_add_next_randomness: false,
        maybe_next_solution_range: None,
        maybe_next_salt: None,
        maybe_derive_salt_from_predigest,
    })
}

struct ValidHeaderParams<'a> {
    parent_hash: HashOf<Header>,
    number: NumberOf<Header>,
    slot: u64,
    keypair: &'a Keypair,
    randomness: Randomness,
    salt: Salt,
    should_add_next_randomness: bool,
    maybe_next_solution_range: Option<(Slot, (u64, u64), NumberOf<Header>)>,
    maybe_next_salt: Option<Salt>,
    maybe_derive_salt_from_predigest: Option<EonIndex>,
}

fn valid_header(
    params: ValidHeaderParams<'_>,
) -> (Header, SolutionRange, SegmentIndex, RecordsRoot) {
    let ValidHeaderParams {
        parent_hash,
        number,
        slot,
        keypair,
        randomness,
        salt,
        should_add_next_randomness,
        maybe_next_solution_range,
        maybe_next_salt,
        maybe_derive_salt_from_predigest: derive_next_salt_from_predigest,
    } = params;
    let (encoding, piece_index, segment_index, records_root) = valid_piece(keypair.public);
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
    let tag_signature = create_tag_signature(keypair, tag);
    let pre_digest = PreDigest {
        slot: slot.into(),
        solution: Solution {
            public_key: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
            reward_address: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
            piece_index,
            encoding,
            tag_signature,
            local_challenge,
            tag,
        },
    };
    let mut digests = vec![
        DigestItem::global_randomness(randomness),
        DigestItem::solution_range(solution_range),
        DigestItem::salt(salt),
        DigestItem::subspace_pre_digest(&pre_digest),
    ];

    if should_add_next_randomness {
        let next_global_randomness = derive_randomness(
            &subspace_core_primitives::PublicKey::from(&FarmerPublicKey::unchecked_from(
                keypair.public.to_bytes(),
            )),
            tag,
            &tag_signature,
        )
        .unwrap();
        digests.push(DigestItem::next_global_randomness(next_global_randomness));
    }

    if let Some((start_slot, probability, era_duration)) = maybe_next_solution_range {
        let expected_next_solution_range = derive_next_solution_range(
            u64::from(start_slot),
            slot,
            probability,
            solution_range,
            era_duration,
        );

        digests.push(DigestItem::next_solution_range(
            expected_next_solution_range,
        ))
    }

    if let Some(next_salt) = maybe_next_salt {
        digests.push(DigestItem::next_salt(next_salt))
    } else if let Some(eon_index) = derive_next_salt_from_predigest {
        let randomness = derive_randomness(
            &subspace_core_primitives::PublicKey::from(&FarmerPublicKey::unchecked_from(
                keypair.public.to_bytes(),
            )),
            pre_digest.solution.tag,
            &pre_digest.solution.tag_signature,
        )
        .unwrap();

        let next_salt = derive_next_salt_from_randomness(eon_index, &randomness);
        digests.push(DigestItem::next_salt(next_salt))
    }

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

    (header, solution_range, segment_index, records_root)
}

fn import_blocks_until(
    store: &mut MockStorage,
    number: NumberOf<Header>,
    start_slot: u64,
    keypair: &Keypair,
) -> (HashOf<Header>, u64) {
    let mut parent_hash = Default::default();
    let mut slot = start_slot;
    let mut next_eon_index = 0;
    let genesis_slot = start_slot;
    let mut era_start_slot = start_slot;
    for block_number in 0..=number {
        let (header, _solution_range, segment_index, records_root) =
            valid_header_with_default_randomness_and_salt(parent_hash, block_number, slot, keypair);
        parent_hash = header.hash();
        slot += 1;

        if HeaderImporter::<_, MockStorage>::has_era_changed(
            &header,
            store.chain_constants().era_duration,
        ) {
            era_start_slot = slot;
        }
        let header_ext = HeaderExt {
            header,
            total_weight: 0,
            salt_derivation_info: SaltDerivationInfo {
                eon_index: next_eon_index,
                maybe_randomness: None,
            },
            era_start_slot: era_start_slot.into(),
            should_adjust_solution_range: true,
            maybe_current_solution_range_override: None,
            maybe_next_solution_range_override: None,
            test_overrides: Default::default(),
        };
        store.store_header(header_ext, true);
        store.store_records_root(segment_index, records_root);
        next_eon_index = derive_next_eon_index(
            next_eon_index,
            store.chain_constants().eon_duration,
            genesis_slot,
            slot,
        )
        .unwrap_or(next_eon_index)
    }

    (parent_hash, slot)
}

#[test]
fn test_header_import_missing_parent() {
    let constants = default_test_constants();
    let mut store = MockStorage::new(constants);
    let keypair = Keypair::generate();
    let (_parent_hash, next_slot) = import_blocks_until(&mut store, 0, 0, &keypair);
    let (header, _, segment_index, records_root) =
        valid_header_with_default_randomness_and_salt(Default::default(), 1, next_slot, &keypair);
    store.store_records_root(segment_index, records_root);
    let mut importer = HeaderImporter::new(store);
    assert_err!(
        importer.import_header(header.clone()),
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
    let mut importer = HeaderImporter::new(store);

    // import block 3
    let (header, solution_range, segment_index, records_root) =
        valid_header_with_default_randomness_and_salt(parent_hash, 3, next_slot, &keypair);
    importer
        .store
        .override_solution_range(parent_hash, solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    assert_ok!(importer.import_header(header.clone()));
    let best_header_ext = importer.store.best_header();
    assert_eq!(best_header_ext.header, header);
    let mut best_header = header;

    // try an import another fork at 3
    let (header, solution_range, segment_index, records_root) =
        valid_header_with_default_randomness_and_salt(parent_hash, 3, next_slot + 1, &keypair);
    let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
        extract_subspace_digest_items(&header).unwrap();
    let new_weight = HeaderImporter::<Header, MockStorage>::calculate_block_weight(
        &digests.global_randomness,
        &digests.pre_digest,
    );
    importer
        .store
        .override_solution_range(parent_hash, solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    match new_header_weight {
        Ordering::Less => {
            importer
                .store
                .override_cumulative_weight(best_header_ext.header.hash(), new_weight + 1);
        }
        Ordering::Equal => {
            importer
                .store
                .override_cumulative_weight(best_header_ext.header.hash(), new_weight);
        }
        Ordering::Greater => {
            importer
                .store
                .override_cumulative_weight(best_header_ext.header.hash(), new_weight - 1);
            best_header = header.clone();
        }
    };
    assert_ok!(importer.import_header(header));
    let best_header_ext = importer.store.best_header();
    assert_eq!(best_header_ext.header, best_header);
    // we still track the forks
    assert_eq!(importer.store.headers_at_number(3).len(), 2);
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
    let mut constants = default_test_constants();
    constants.global_randomness_interval = 11;
    constants.era_duration = 11;
    constants.eon_duration = 10;
    constants.next_salt_reveal_interval = 3;
    let mut store = MockStorage::new(constants);
    let keypair = Keypair::generate();
    let (parent_hash, next_slot) = import_blocks_until(&mut store, 2, 1, &keypair);
    let best_header = store.best_header();
    assert_eq!(best_header.header.hash(), parent_hash);
    let mut importer = HeaderImporter::new(store);

    // verify and import next headers
    let mut slot = next_slot;
    let mut parent_hash = parent_hash;
    for number in 3..=10 {
        let (header, solution_range, segment_index, records_root) =
            valid_header_with_default_randomness_and_salt(parent_hash, number, slot, &keypair);
        importer
            .store
            .override_solution_range(parent_hash, solution_range);
        importer
            .store
            .store_records_root(segment_index, records_root);

        let res = importer.import_header(header.clone());
        assert_ok!(res);
        // best header should be correct
        let best_header = importer.store.best_header();
        assert_eq!(best_header.header, header);
        slot += 1;
        parent_hash = header.hash();
    }

    // finalized head must be best 10 - 7 = 3
    let finalized_header = importer.store.finalized_header();
    assert_eq!(finalized_header.header.number, 3);

    // header count at the finalized head must be 1
    ensure_finalized_heads_have_no_forks(&importer.store, 3);

    // verify global randomness
    // global randomness at block number 11 should be updated as the interval is 11.
    let (header, solution_range, segment_index, records_root) =
        valid_header_with_default_randomness_and_salt(parent_hash, 11, slot, &keypair);
    importer
        .store
        .override_solution_range(parent_hash, solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);

    // this should fail since the next digest for randomness is missing
    let res = importer.import_header(header);
    assert_err!(
        res,
        ImportError::DigestError(DigestError::NextDigestVerificationError(
            ErrorDigestType::NextGlobalRandomness
        ))
    );

    // inject expected randomness digest but should still fail due to missing next solution range
    let (header, solution_range, segment_index, records_root) =
        valid_header_with_next_digests(parent_hash, 11, slot, &keypair, true, None, None);
    importer
        .store
        .override_solution_range(parent_hash, solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);

    // this should fail since the next digest for solution range is missing
    let res = importer.import_header(header);
    assert_err!(
        res,
        ImportError::DigestError(DigestError::NextDigestVerificationError(
            ErrorDigestType::NextSolutionRange
        ))
    );

    // inject next solution range
    let ancestor_header = importer
        .store
        .headers_at_number(1)
        .first()
        .cloned()
        .unwrap();
    let ancestor_digests =
        extract_subspace_digest_items::<Header, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &ancestor_header.header,
        )
        .unwrap();

    let constants = importer.store.chain_constants();
    let (header, solution_range, segment_index, records_root) = valid_header_with_next_digests(
        parent_hash,
        11,
        slot,
        &keypair,
        true,
        Some((
            ancestor_digests.pre_digest.slot,
            constants.slot_probability,
            constants.era_duration,
        )),
        None,
    );
    importer
        .store
        .override_solution_range(parent_hash, solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);

    let res = importer.import_header(header);
    assert_err!(
        res,
        ImportError::DigestError(DigestError::NextDigestVerificationError(
            ErrorDigestType::NextSalt
        ))
    );

    // inject next salt
    let header_at_3 = importer
        .store
        .headers_at_number(3)
        .first()
        .cloned()
        .unwrap();
    let header_at_4 = importer
        .store
        .headers_at_number(4)
        .first()
        .cloned()
        .unwrap();

    // verify salt reveal at block #4
    // salt reveal number should be empty at header #3
    assert_eq!(header_at_3.salt_derivation_info.eon_index, 0);
    assert_eq!(header_at_3.salt_derivation_info.maybe_randomness, None);
    // eon index should still be 0 and the next salt should be revealed at #4
    assert_eq!(header_at_4.salt_derivation_info.eon_index, 0);
    let digests_at_4 = extract_pre_digest(&header_at_4.header).unwrap();
    let randomness = derive_randomness(
        &subspace_core_primitives::PublicKey::from(&FarmerPublicKey::unchecked_from(
            keypair.public.to_bytes(),
        )),
        digests_at_4.solution.tag,
        &digests_at_4.solution.tag_signature,
    )
    .unwrap();
    assert_eq!(
        header_at_4.salt_derivation_info.maybe_randomness,
        Some(randomness)
    );

    let next_salt = derive_next_salt_from_randomness(0, &randomness);

    // edge case when slot between #10 and #11 is long enough that, salt is revealed immediately in the first of block of next eon.
    // so set the next slot far enough
    slot = 15;
    let (header, solution_range, segment_index, records_root) = valid_header_with_next_digests(
        parent_hash,
        11,
        slot,
        &keypair,
        true,
        Some((
            ancestor_digests.pre_digest.slot,
            constants.slot_probability,
            constants.era_duration,
        )),
        Some(next_salt),
    );
    importer
        .store
        .override_solution_range(parent_hash, solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);

    let res = importer.import_header(header);
    assert_ok!(res);

    // verify eon index changes at block #11
    let header_at_11 = importer
        .store
        .headers_at_number(11)
        .first()
        .cloned()
        .unwrap();

    // eon index should be 1
    // since the slot is far enough, the salt should be revealed in this header as well
    let digests_at_11 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_11.header,
        )
        .unwrap();
    let randomness = derive_randomness(
        &subspace_core_primitives::PublicKey::from(&FarmerPublicKey::unchecked_from(
            keypair.public.to_bytes(),
        )),
        digests_at_11.pre_digest.solution.tag,
        &digests_at_11.pre_digest.solution.tag_signature,
    )
    .unwrap();
    assert_eq!(header_at_11.salt_derivation_info.eon_index, 1);
    assert_eq!(
        header_at_11.salt_derivation_info.maybe_randomness,
        Some(randomness)
    );

    parent_hash = header_at_11.header.hash();
    slot += 1;
    let (header, solution_range, segment_index, records_root) = valid_header(ValidHeaderParams {
        parent_hash,
        number: 12,
        slot,
        keypair: &keypair,
        randomness: digests_at_11.next_global_randomness.unwrap(),
        salt: digests_at_11.next_salt.unwrap(),
        should_add_next_randomness: false,
        maybe_next_solution_range: None,
        maybe_next_salt: None,
        maybe_derive_salt_from_predigest: None,
    });
    importer
        .store
        .override_next_solution_range(parent_hash, solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);

    let res = importer.import_header(header.clone());
    assert_ok!(res);
    // best header should be correct
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header, header);
    // randomness should be carried over till next eon change
    assert_eq!(best_header.salt_derivation_info.eon_index, 1);
    assert_eq!(
        best_header.salt_derivation_info.maybe_randomness,
        Some(randomness)
    );
}

fn create_fork_chain_from(
    importer: &mut HeaderImporter<Header, MockStorage>,
    parent_hash: HashOf<Header>,
    from: NumberOf<Header>,
    until: NumberOf<Header>,
    slot: u64,
    keypair: &Keypair,
) -> (HashOf<Header>, u64) {
    let best_header_ext = importer.store.best_header();
    let mut parent_hash = parent_hash;
    let mut next_slot = slot + 1;
    for number in from..=until {
        let (header, solution_range, segment_index, records_root) =
            valid_header_with_default_randomness_and_salt(parent_hash, number, next_slot, keypair);
        let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
            extract_subspace_digest_items(&header).unwrap();
        let new_weight = HeaderImporter::<Header, MockStorage>::calculate_block_weight(
            &digests.global_randomness,
            &digests.pre_digest,
        );
        importer
            .store
            .override_solution_range(parent_hash, solution_range);
        importer
            .store
            .store_records_root(segment_index, records_root);
        importer
            .store
            .override_cumulative_weight(best_header_ext.header.hash(), new_weight + 1);
        // override parent weight to 0
        importer.store.override_cumulative_weight(parent_hash, 0);
        parent_hash = header.hash();
        next_slot += 1;
        if number == 1 {
            // adjust Chain constants for Block #1
            let mut constants = importer.store.chain_constants();
            constants.genesis_digest_items.next_solution_range = solution_range;
            importer.store.override_constants(constants)
        }
        assert_ok!(importer.import_header(header));
        // best header should not change
        assert_eq!(importer.store.best_header().header, best_header_ext.header);
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
    let mut importer = HeaderImporter::new(store);

    // create a fork chain from number 1
    let genesis_hash = importer.store.headers_at_number(0)[0].header.hash();
    create_fork_chain_from(&mut importer, genesis_hash, 1, 5, next_slot + 1, &keypair);
    assert_eq!(best_header.header.hash(), parent_hash);
    // block 0 should be finalized
    assert_eq!(importer.store.finalized_header().header.number, 0);
    ensure_finalized_heads_have_no_forks(&importer.store, 0);

    // add new best header at 5
    let (header, solution_range, segment_index, records_root) =
        valid_header_with_default_randomness_and_salt(parent_hash, 5, next_slot, &keypair);
    importer
        .store
        .override_solution_range(parent_hash, solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header, header);

    // block 1 should be finalized
    assert_eq!(importer.store.finalized_header().header.number, 1);
    ensure_finalized_heads_have_no_forks(&importer.store, 1);

    // create a fork chain from number 5
    let (fork_parent_hash, fork_next_slot) =
        create_fork_chain_from(&mut importer, parent_hash, 5, 8, next_slot, &keypair);

    // best header should still be the same
    assert_eq!(best_header.header, importer.store.best_header().header);

    // there must be 2 heads at 5
    assert_eq!(importer.store.headers_at_number(5).len(), 2);

    // block 1 should be finalized
    assert_eq!(importer.store.finalized_header().header.number, 1);
    ensure_finalized_heads_have_no_forks(&importer.store, 1);

    // import a new head to the fork chain and make it the best.
    let (header, solution_range, segment_index, records_root) =
        valid_header_with_default_randomness_and_salt(
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
    importer
        .store
        .override_solution_range(fork_parent_hash, solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(importer.store.best_header().header.hash(), new_weight - 1);
    // override parent weight to 0
    importer
        .store
        .override_cumulative_weight(fork_parent_hash, 0);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    assert_eq!(importer.store.best_header().header, header);

    // now the finalized header must be 5
    ensure_finalized_heads_have_no_forks(&importer.store, 5)
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
    let mut importer = HeaderImporter::new(store);

    // verify and import next headers
    let mut slot = next_slot;
    let mut parent_hash = parent_hash;
    let fork_parent_hash = parent_hash;
    for number in 3..=5 {
        let (header, solution_range, segment_index, records_root) =
            valid_header_with_default_randomness_and_salt(parent_hash, number, slot, &keypair);
        importer
            .store
            .override_solution_range(parent_hash, solution_range);
        importer
            .store
            .store_records_root(segment_index, records_root);
        let res = importer.import_header(header.clone());
        assert_ok!(res);
        // best header should be correct
        let best_header = importer.store.best_header();
        assert_eq!(best_header.header, header);
        slot += 1;
        parent_hash = header.hash();
    }

    // finalized head must be best(5) - 4 = 1
    let number = importer.store.finalized_header().header.number;
    assert_eq!(number, 1);

    // header count at the finalized head must be 1
    ensure_finalized_heads_have_no_forks(&importer.store, 1);

    // now import a fork header 3 that becomes canonical
    let (header, solution_range, segment_index, records_root) =
        valid_header_with_default_randomness_and_salt(fork_parent_hash, 3, next_slot + 1, &keypair);
    let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
        extract_subspace_digest_items(&header).unwrap();
    let new_weight = HeaderImporter::<Header, MockStorage>::calculate_block_weight(
        &digests.global_randomness,
        &digests.pre_digest,
    );
    importer
        .store
        .override_solution_range(fork_parent_hash, solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(importer.store.best_header().header.hash(), new_weight - 1);
    // override parent weight to 0
    importer
        .store
        .override_cumulative_weight(fork_parent_hash, 0);
    let res = importer.import_header(header);
    assert_err!(res, ImportError::SwitchedToForkBelowArchivingDepth)
}

#[test]
fn test_salt_reveal_and_eon_change_in_same_block() {
    let mut constants = default_test_constants();
    constants.eon_duration = 10;
    constants.next_salt_reveal_interval = 3;
    let mut store = MockStorage::new(constants);
    let keypair = Keypair::generate();
    let (parent_hash, next_slot) = import_blocks_until(&mut store, 1, 0, &keypair);
    let best_header = store.best_header();
    assert_eq!(best_header.header.hash(), parent_hash);
    let mut importer = HeaderImporter::new(store);

    // verify and import next headers
    let mut slot = next_slot;
    let mut parent_hash = parent_hash;
    for number in 2..=3 {
        let (header, solution_range, segment_index, records_root) =
            valid_header_with_default_randomness_and_salt(parent_hash, number, slot, &keypair);
        importer
            .store
            .override_solution_range(parent_hash, solution_range);
        importer
            .store
            .store_records_root(segment_index, records_root);

        let res = importer.import_header(header.clone());
        assert_ok!(res);
        // best header should be correct
        let best_header = importer.store.best_header();
        assert_eq!(best_header.header, header);
        slot += 1;
        parent_hash = header.hash();
    }

    let header_at_3 = importer
        .store
        .headers_at_number(3)
        .first()
        .cloned()
        .unwrap();

    // salt reveal number should be empty at header #3
    assert_eq!(header_at_3.salt_derivation_info.eon_index, 0);
    assert_eq!(header_at_3.salt_derivation_info.maybe_randomness, None);

    // Block #4 slot is so far that following happens in the same block
    // Salt is revealed
    // eon will be changed
    // next salt is also revealed
    slot = 15;
    let (header, solution_range, segment_index, records_root) =
        valid_header_with_next_salt_revealed_at_this_header(
            parent_hash,
            4,
            slot,
            &keypair,
            Some(0),
        );
    importer
        .store
        .override_solution_range(parent_hash, solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);

    let res = importer.import_header(header);
    assert_ok!(res);

    // verify eon index changeed and also next salt is revealed
    let header_at_4 = importer
        .store
        .headers_at_number(4)
        .first()
        .cloned()
        .unwrap();

    let digests_at_4 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_4.header,
        )
        .unwrap();

    let randomness = derive_randomness(
        &subspace_core_primitives::PublicKey::from(&FarmerPublicKey::unchecked_from(
            keypair.public.to_bytes(),
        )),
        digests_at_4.pre_digest.solution.tag,
        &digests_at_4.pre_digest.solution.tag_signature,
    )
    .unwrap();

    // eon index has changed
    assert_eq!(header_at_4.salt_derivation_info.eon_index, 1);
    assert_eq!(
        header_at_4.salt_derivation_info.maybe_randomness,
        Some(randomness)
    );
}
