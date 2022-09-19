use crate::mock::{Header, MockStorage};
use crate::{
    ChainConstants, DigestError, HashOf, HeaderExt, HeaderImporter, ImportError, NextDigestItems,
    NumberOf, SaltDerivationInfo, Storage, StorageBound,
};
use frame_support::{assert_err, assert_ok};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    derive_next_global_randomness, derive_next_salt, derive_next_solution_range,
    extract_pre_digest, extract_subspace_digest_items, CompatibleDigestItem,
    DeriveNextSolutionRangeParams, ErrorDigestType, PreDigest, SubspaceDigestItems,
};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature};
use sp_runtime::app_crypto::UncheckedFrom;
use sp_runtime::testing::H256;
use sp_runtime::traits::Header as HeaderT;
use sp_runtime::{Digest, DigestItem};
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::{
    Piece, PublicKey, Randomness, RecordsRoot, Salt, SegmentIndex, Solution, SolutionRange, Tag,
    RECORDED_HISTORY_SEGMENT_SIZE, RECORD_SIZE,
};
use subspace_solving::{
    create_tag, create_tag_signature, derive_global_challenge, derive_local_challenge,
    derive_target, SubspaceCodec, REWARD_SIGNING_CONTEXT,
};
use subspace_verification::derive_randomness;

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
        max_plot_size: 100 * 1024 * 1024 * 1024,
        genesis_records_roots: Default::default(),
        global_randomness_interval: 20,
        era_duration: 20,
        slot_probability: (1, 6),
        eon_duration: 20,
        next_salt_reveal_interval: 6,
        storage_bound: Default::default(),
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

    let mut archiver = Archiver::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE).unwrap();

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
        position as u32,
        RECORD_SIZE,
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

struct ValidHeaderParams<'a> {
    parent_hash: HashOf<Header>,
    number: NumberOf<Header>,
    slot: u64,
    keypair: &'a Keypair,
    randomness: Randomness,
    salt: Salt,
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
    let digests = vec![
        DigestItem::global_randomness(randomness),
        DigestItem::solution_range(solution_range),
        DigestItem::salt(salt),
        DigestItem::subspace_pre_digest(&pre_digest),
    ];

    let header = Header {
        parent_hash,
        number,
        state_root: Default::default(),
        extrinsics_root: Default::default(),
        digest: Digest { logs: digests },
    };

    (header, solution_range, segment_index, records_root)
}

fn seal_header(keypair: &Keypair, header: &mut Header) {
    let ctx = schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT);
    let pre_hash = header.hash();
    let signature =
        FarmerSignature::unchecked_from(keypair.sign(ctx.bytes(pre_hash.as_bytes())).to_bytes());
    header
        .digest
        .logs
        .push(DigestItem::subspace_seal(signature));
}

fn remove_seal(header: &mut Header) {
    let digests = header.digest_mut();
    digests.pop();
}

fn next_slot(slot_probability: (u64, u64), current_slot: Slot) -> Slot {
    let mut rng = StdRng::seed_from_u64(current_slot.into());
    current_slot + rng.gen_range(slot_probability.0..=slot_probability.1)
}

fn initialize_store(
    constants: ChainConstants<Header>,
    should_adjust_solution_range: bool,
    maybe_root_plot_public_key: Option<FarmerPublicKey>,
) -> (MockStorage, HashOf<Header>) {
    let mut store = MockStorage::new(constants);
    let mut rng = StdRng::seed_from_u64(0);
    let mut state_root = vec![0u8; 32];
    rng.fill(state_root.as_mut_slice());
    let genesis_header = Header {
        parent_hash: Default::default(),
        number: 0,
        state_root: H256::from_slice(&state_root),
        extrinsics_root: Default::default(),
        digest: Default::default(),
    };

    let genesis_hash = genesis_header.hash();
    let header = HeaderExt {
        header: genesis_header,
        total_weight: 0,
        salt_derivation_info: Default::default(),
        era_start_slot: Default::default(),
        should_adjust_solution_range,
        maybe_current_solution_range_override: None,
        maybe_next_solution_range_override: None,
        maybe_root_plot_public_key,
        genesis_slot: Default::default(),
        test_overrides: Default::default(),
    };

    store.store_header(header, true);
    (store, genesis_hash)
}

fn add_next_digests(store: &MockStorage, number: NumberOf<Header>, header: &mut Header) {
    let constants = store.chain_constants();
    let parent_header = store.header(*header.parent_hash()).unwrap();
    let digests =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            header,
        )
        .unwrap();

    let digest_logs = header.digest_mut();
    if let Some(next_randomness) = derive_next_global_randomness::<Header>(
        number,
        constants.global_randomness_interval,
        &digests.pre_digest,
    )
    .unwrap()
    {
        digest_logs.push(DigestItem::next_global_randomness(next_randomness));
    }

    if let Some(next_solution_range) =
        derive_next_solution_range::<Header>(DeriveNextSolutionRangeParams {
            number,
            era_duration: constants.era_duration,
            slot_probability: constants.slot_probability,
            current_slot: digests.pre_digest.slot,
            current_solution_range: digests.solution_range,
            era_start_slot: parent_header.era_start_slot,
            should_adjust_solution_range: true,
            maybe_next_solution_range_override: None,
        })
        .unwrap()
    {
        digest_logs.push(DigestItem::next_solution_range(next_solution_range));
    }

    // re-check if the salt was revealed and eon also changes with this header, then derive randomness
    let parent_salt_derivation_info = SaltDerivationInfo {
        eon_index: parent_header.salt_derivation_info.eon_index,
        maybe_randomness: parent_header
            .salt_derivation_info
            .maybe_randomness
            .or_else(|| {
                HeaderImporter::<Header, MockStorage>::randomness_for_next_salt(
                    &store.chain_constants(),
                    parent_header.salt_derivation_info.eon_index,
                    parent_header.genesis_slot,
                    &digests.pre_digest,
                )
                .unwrap()
            }),
    };

    if let Some(next_salt) = derive_next_salt::<Header>(
        constants.eon_duration,
        parent_salt_derivation_info.eon_index,
        parent_header.genesis_slot,
        digests.pre_digest.slot,
        parent_salt_derivation_info.maybe_randomness,
    )
    .unwrap()
    {
        digest_logs.push(DigestItem::next_salt(next_salt));
    }
}

struct ForkAt {
    parent_hash: HashOf<Header>,
    // if None, fork chain cumulative weight is equal to canonical chain weight
    is_best: Option<bool>,
}

fn add_headers_to_chain(
    importer: &mut HeaderImporter<Header, MockStorage>,
    keypair: &Keypair,
    headers_to_add: NumberOf<Header>,
    maybe_fork_chain: Option<ForkAt>,
) -> HashOf<Header> {
    let best_header_ext = importer.store.best_header();
    let constants = importer.store.chain_constants();
    let (parent_hash, number, slot) = if let Some(ForkAt { parent_hash, .. }) = maybe_fork_chain {
        let header = importer.store.header(parent_hash).unwrap();
        let digests = extract_pre_digest(&header.header).unwrap();

        (parent_hash, *header.header.number(), digests.slot)
    } else {
        let digests = extract_pre_digest(&best_header_ext.header).unwrap();
        (
            best_header_ext.header.hash(),
            *best_header_ext.header.number(),
            digests.slot,
        )
    };

    let until_number = number + headers_to_add;
    let mut parent_hash = parent_hash;
    let mut number = number + 1;
    let mut slot = next_slot(constants.slot_probability, slot);
    let mut best_header_hash = best_header_ext.header.hash();
    while number <= until_number {
        let (randomness, salt, override_next_solution) = if number == 1 {
            let (randomness, salt) = default_randomness_and_salt();
            (randomness, salt, false)
        } else {
            let header = importer.store.header(parent_hash).unwrap();
            let digests = extract_subspace_digest_items::<
                _,
                FarmerPublicKey,
                FarmerPublicKey,
                FarmerSignature,
            >(&header.header)
            .unwrap();

            let randomness = digests
                .next_global_randomness
                .unwrap_or(digests.global_randomness);
            let salt = digests.next_salt.unwrap_or(digests.salt);
            (randomness, salt, digests.next_global_randomness.is_some())
        };

        let (mut header, solution_range, segment_index, records_root) =
            valid_header(ValidHeaderParams {
                parent_hash,
                number,
                slot: slot.into(),
                keypair,
                randomness,
                salt,
            });
        let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
            extract_subspace_digest_items(&header).unwrap();
        let new_weight = HeaderImporter::<Header, MockStorage>::calculate_block_weight(
            &digests.global_randomness,
            &digests.pre_digest,
        );
        importer.store.override_cumulative_weight(parent_hash, 0);
        if number == 1 {
            // adjust Chain constants for Block #1
            let mut constants = importer.store.chain_constants();
            constants.genesis_digest_items.next_solution_range = solution_range;
            importer.store.override_constants(constants)
        } else if override_next_solution {
            importer
                .store
                .override_next_solution_range(parent_hash, solution_range);
        } else {
            importer
                .store
                .override_solution_range(parent_hash, solution_range);
        }
        importer
            .store
            .store_records_root(segment_index, records_root);
        if let Some(ForkAt {
            is_best: maybe_best,
            ..
        }) = maybe_fork_chain
        {
            if let Some(is_best) = maybe_best {
                if is_best {
                    importer
                        .store
                        .override_cumulative_weight(best_header_hash, new_weight - 1)
                } else {
                    importer
                        .store
                        .override_cumulative_weight(best_header_hash, new_weight + 1)
                }
            } else {
                importer
                    .store
                    .override_cumulative_weight(best_header_hash, new_weight)
            }
        }

        add_next_digests(&importer.store, number, &mut header);
        seal_header(keypair, &mut header);
        parent_hash = header.hash();
        slot = next_slot(constants.slot_probability, slot);
        number += 1;

        assert_ok!(importer.import_header(header.clone()));
        if let Some(ForkAt {
            is_best: maybe_best,
            ..
        }) = maybe_fork_chain
        {
            if let Some(is_best) = maybe_best {
                if is_best {
                    best_header_hash = header.hash()
                }
            }
        } else {
            best_header_hash = header.hash()
        }

        assert_eq!(importer.store.best_header().header.hash(), best_header_hash);
    }

    parent_hash
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
fn test_header_import_missing_parent() {
    let constants = default_test_constants();
    let (mut store, _genesis_hash) = initialize_store(constants, true, None);
    let (randomness, salt) = default_randomness_and_salt();
    let keypair = Keypair::generate();
    let (header, _, segment_index, records_root) = valid_header(ValidHeaderParams {
        parent_hash: Default::default(),
        number: 1,
        slot: 1,
        keypair: &keypair,
        randomness,
        salt,
    });
    store.store_records_root(segment_index, records_root);
    let mut importer = HeaderImporter::new(store);
    assert_err!(
        importer.import_header(header.clone()),
        ImportError::MissingParent(header.hash())
    );
}

#[test]
fn test_header_import_non_canonical() {
    let constants = default_test_constants();
    let (store, _genesis_hash) = initialize_store(constants, true, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    let hash_of_2 = add_headers_to_chain(&mut importer, &keypair, 2, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_2);

    // import canonical block 3
    let hash_of_3 = add_headers_to_chain(&mut importer, &keypair, 1, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_3);
    let best_header = importer.store.header(hash_of_3).unwrap();
    assert_eq!(importer.store.headers_at_number(3).len(), 1);

    // import non canonical block 3
    add_headers_to_chain(
        &mut importer,
        &keypair,
        1,
        Some(ForkAt {
            parent_hash: hash_of_2,
            is_best: Some(false),
        }),
    );

    let best_header_ext = importer.store.best_header();
    assert_eq!(best_header_ext.header, best_header.header);
    // we still track the forks
    assert_eq!(importer.store.headers_at_number(3).len(), 2);
}

#[test]
fn test_header_import_canonical() {
    let constants = default_test_constants();
    let (store, _genesis_hash) = initialize_store(constants, true, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    let hash_of_5 = add_headers_to_chain(&mut importer, &keypair, 5, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_5);

    // import some more canonical blocks
    let hash_of_25 = add_headers_to_chain(&mut importer, &keypair, 20, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_25);
    assert_eq!(importer.store.headers_at_number(25).len(), 1);
}

#[test]
fn test_header_import_non_canonical_with_equal_block_weight() {
    let constants = default_test_constants();
    let (store, _genesis_hash) = initialize_store(constants, true, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    let hash_of_2 = add_headers_to_chain(&mut importer, &keypair, 2, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_2);

    // import canonical block 3
    let hash_of_3 = add_headers_to_chain(&mut importer, &keypair, 1, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_3);
    let best_header = importer.store.header(hash_of_3).unwrap();
    assert_eq!(importer.store.headers_at_number(3).len(), 1);

    // import non canonical block 3
    add_headers_to_chain(
        &mut importer,
        &keypair,
        1,
        Some(ForkAt {
            parent_hash: hash_of_2,
            is_best: None,
        }),
    );

    let best_header_ext = importer.store.best_header();
    assert_eq!(best_header_ext.header, best_header.header);
    // we still track the forks
    assert_eq!(importer.store.headers_at_number(3).len(), 2);
}

#[test]
fn test_chain_reorg_to_longer_chain() {
    let mut constants = default_test_constants();
    constants.k_depth = 4;
    let (store, genesis_hash) = initialize_store(constants, true, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_4);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    // create a fork chain of 4 headers from number 1
    add_headers_to_chain(
        &mut importer,
        &keypair,
        4,
        Some(ForkAt {
            parent_hash: genesis_hash,
            is_best: Some(false),
        }),
    );
    assert_eq!(best_header.header.hash(), hash_of_4);
    // block 0 is still finalized
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );
    ensure_finalized_heads_have_no_forks(&importer.store, 0);

    // add new best header at 5
    let hash_of_5 = add_headers_to_chain(&mut importer, &keypair, 1, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_5);

    // block 1 should be finalized
    assert_eq!(importer.store.finalized_header().header.number, 1);
    ensure_finalized_heads_have_no_forks(&importer.store, 1);

    // create a fork chain from number 5 with block until 8
    let fork_hash_of_8 = add_headers_to_chain(
        &mut importer,
        &keypair,
        4,
        Some(ForkAt {
            parent_hash: hash_of_4,
            is_best: Some(false),
        }),
    );

    // best header should still be the same
    assert_eq!(best_header.header, importer.store.best_header().header);

    // there must be 2 heads at 5
    assert_eq!(importer.store.headers_at_number(5).len(), 2);

    // block 1 should be finalized
    assert_eq!(importer.store.finalized_header().header.number, 1);
    ensure_finalized_heads_have_no_forks(&importer.store, 1);

    // import a new head to the fork chain and make it the best.
    let hash_of_9 = add_headers_to_chain(
        &mut importer,
        &keypair,
        1,
        Some(ForkAt {
            parent_hash: fork_hash_of_8,
            is_best: Some(true),
        }),
    );
    assert_eq!(importer.store.best_header().header.hash(), hash_of_9);

    // now the finalized header must be 5
    ensure_finalized_heads_have_no_forks(&importer.store, 5)
}

#[test]
fn test_reorg_to_heavier_smaller_chain() {
    let mut constants = default_test_constants();
    constants.k_depth = 4;
    let (store, genesis_hash) = initialize_store(constants, true, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_5 = add_headers_to_chain(&mut importer, &keypair, 5, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_5);
    assert_eq!(importer.store.finalized_header().header.number, 1);

    // header count at the finalized head must be 1
    ensure_finalized_heads_have_no_forks(&importer.store, 1);

    // now import a fork header 3 that becomes canonical
    let constants = importer.store.chain_constants();
    let header_at_2 = importer
        .store
        .headers_at_number(2)
        .first()
        .cloned()
        .unwrap();
    let digests_at_2 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_2.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_2.header.hash(),
            number: 3,
            slot: next_slot(constants.slot_probability, digests_at_2.pre_digest.slot).into(),
            keypair: &keypair,
            randomness: digests_at_2.global_randomness,
            salt: digests_at_2.salt,
        });
    seal_header(&keypair, &mut header);
    let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
        extract_subspace_digest_items(&header).unwrap();
    let new_weight = HeaderImporter::<Header, MockStorage>::calculate_block_weight(
        &digests.global_randomness,
        &digests.pre_digest,
    );
    importer
        .store
        .override_solution_range(header_at_2.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(importer.store.best_header().header.hash(), new_weight - 1);
    // override parent weight to 0
    importer
        .store
        .override_cumulative_weight(header_at_2.header.hash(), 0);
    let res = importer.import_header(header);
    assert_err!(res, ImportError::SwitchedToForkBelowArchivingDepth)
}

#[test]
fn test_next_global_randomness_digest() {
    let mut constants = default_test_constants();
    constants.global_randomness_interval = 5;
    let (store, genesis_hash) = initialize_store(constants, true, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None);
    assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

    // try to import header with out next global randomness
    let constants = importer.store.chain_constants();
    let header_at_4 = importer.store.header(hash_of_4).unwrap();
    let digests_at_4 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_4.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_4.header.hash(),
            number: 5,
            slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot).into(),
            keypair: &keypair,
            randomness: digests_at_4.global_randomness,
            salt: digests_at_4.salt,
        });
    seal_header(&keypair, &mut header);
    importer
        .store
        .override_solution_range(header_at_4.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(header_at_4.header.hash(), 0);
    let res = importer.import_header(header.clone());
    assert_err!(
        res,
        ImportError::DigestError(DigestError::NextDigestVerificationError(
            ErrorDigestType::NextGlobalRandomness
        ))
    );
    assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

    // add next global randomness
    remove_seal(&mut header);
    let pre_digest = extract_pre_digest(&header).unwrap();
    let randomness = derive_randomness(
        &PublicKey::from(&pre_digest.solution.public_key),
        pre_digest.solution.tag,
        &pre_digest.solution.tag_signature,
    )
    .unwrap();
    let digests = header.digest_mut();
    digests.push(DigestItem::next_global_randomness(randomness));
    seal_header(&keypair, &mut header);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    assert_eq!(importer.store.best_header().header.hash(), header.hash());
}

#[test]
fn test_next_solution_range_digest_with_adjustment_enabled() {
    let mut constants = default_test_constants();
    constants.era_duration = 5;
    let (store, genesis_hash) = initialize_store(constants, true, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None);
    assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

    // try to import header with out next global randomness
    let constants = importer.store.chain_constants();
    let header_at_4 = importer.store.header(hash_of_4).unwrap();
    let digests_at_4 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_4.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_4.header.hash(),
            number: 5,
            slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot).into(),
            keypair: &keypair,
            randomness: digests_at_4.global_randomness,
            salt: digests_at_4.salt,
        });
    seal_header(&keypair, &mut header);
    importer
        .store
        .override_solution_range(header_at_4.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(header_at_4.header.hash(), 0);
    let pre_digest = extract_pre_digest(&header).unwrap();
    let res = importer.import_header(header.clone());
    assert_err!(
        res,
        ImportError::DigestError(DigestError::NextDigestVerificationError(
            ErrorDigestType::NextSolutionRange
        ))
    );
    assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

    // add next solution range
    remove_seal(&mut header);
    let next_solution_range = subspace_verification::derive_next_solution_range(
        u64::from(header_at_4.era_start_slot),
        u64::from(pre_digest.slot),
        constants.slot_probability,
        solution_range,
        constants.era_duration,
    );
    let digests = header.digest_mut();
    digests.push(DigestItem::next_solution_range(next_solution_range));
    seal_header(&keypair, &mut header);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    assert_eq!(importer.store.best_header().header.hash(), header.hash());
}

#[test]
fn test_next_solution_range_digest_with_adjustment_disabled() {
    let mut constants = default_test_constants();
    constants.era_duration = 5;
    let (store, genesis_hash) = initialize_store(constants, false, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None);
    assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

    // try to import header with out next global randomness
    let constants = importer.store.chain_constants();
    let header_at_4 = importer.store.header(hash_of_4).unwrap();
    let digests_at_4 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_4.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_4.header.hash(),
            number: 5,
            slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot).into(),
            keypair: &keypair,
            randomness: digests_at_4.global_randomness,
            salt: digests_at_4.salt,
        });
    importer
        .store
        .override_solution_range(header_at_4.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(header_at_4.header.hash(), 0);

    // since solution range adjustment is disabled
    // current solution range is used as next
    let next_solution_range = solution_range;
    let digests = header.digest_mut();
    digests.push(DigestItem::next_solution_range(next_solution_range));
    seal_header(&keypair, &mut header);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    assert_eq!(importer.store.best_header().header.hash(), header.hash());
    assert!(!importer.store.best_header().should_adjust_solution_range);
}

#[test]
fn test_enable_solution_range_adjustment_without_override() {
    let mut constants = default_test_constants();
    constants.era_duration = 5;
    let (store, genesis_hash) = initialize_store(constants, false, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None);
    assert_eq!(importer.store.best_header().header.hash(), hash_of_4);
    // solution range adjustment is disabled
    assert!(!importer.store.best_header().should_adjust_solution_range);

    // enable solution range adjustment in this header
    let constants = importer.store.chain_constants();
    let header_at_4 = importer.store.header(hash_of_4).unwrap();
    let digests_at_4 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_4.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_4.header.hash(),
            number: 5,
            slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot).into(),
            keypair: &keypair,
            randomness: digests_at_4.global_randomness,
            salt: digests_at_4.salt,
        });
    importer
        .store
        .override_solution_range(header_at_4.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(header_at_4.header.hash(), 0);
    let pre_digest = extract_pre_digest(&header).unwrap();
    let next_solution_range = subspace_verification::derive_next_solution_range(
        u64::from(header_at_4.era_start_slot),
        u64::from(pre_digest.slot),
        constants.slot_probability,
        solution_range,
        constants.era_duration,
    );
    let digests = header.digest_mut();
    digests.push(DigestItem::next_solution_range(next_solution_range));
    digests.push(DigestItem::enable_solution_range_adjustment_and_override(
        None,
    ));
    seal_header(&keypair, &mut header);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    assert_eq!(importer.store.best_header().header.hash(), header.hash());
    assert!(importer.store.best_header().should_adjust_solution_range);
    assert_eq!(header_at_4.maybe_current_solution_range_override, None);
    assert_eq!(header_at_4.maybe_next_solution_range_override, None);
}

#[test]
fn test_enable_solution_range_adjustment_with_override_between_update_intervals() {
    let mut constants = default_test_constants();
    constants.era_duration = 5;
    let (store, genesis_hash) = initialize_store(constants, false, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_3 = add_headers_to_chain(&mut importer, &keypair, 3, None);
    assert_eq!(importer.store.best_header().header.hash(), hash_of_3);
    // solution range adjustment is disabled
    assert!(!importer.store.best_header().should_adjust_solution_range);

    // enable solution range adjustment with override in this header
    let constants = importer.store.chain_constants();
    let header_at_3 = importer.store.header(hash_of_3).unwrap();
    let digests_at_3 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_3.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_3.header.hash(),
            number: 4,
            slot: next_slot(constants.slot_probability, digests_at_3.pre_digest.slot).into(),
            keypair: &keypair,
            randomness: digests_at_3.global_randomness,
            salt: digests_at_3.salt,
        });
    importer
        .store
        .override_solution_range(header_at_3.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(header_at_3.header.hash(), 0);
    let digests = header.digest_mut();
    let solution_range_override = 100;
    digests.push(DigestItem::enable_solution_range_adjustment_and_override(
        Some(solution_range_override),
    ));
    seal_header(&keypair, &mut header);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    let header_at_4 = importer.store.best_header();
    assert_eq!(header_at_4.header.hash(), header.hash());
    assert!(header_at_4.should_adjust_solution_range);
    // current solution range override and next solution range overrides are updated
    assert_eq!(
        header_at_4.maybe_current_solution_range_override,
        Some(solution_range_override)
    );
    assert_eq!(
        header_at_4.maybe_next_solution_range_override,
        Some(solution_range_override)
    );
}

#[test]
fn test_enable_solution_range_adjustment_with_override_at_interval_change() {
    let mut constants = default_test_constants();
    constants.era_duration = 5;
    let (store, genesis_hash) = initialize_store(constants, false, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None);
    assert_eq!(importer.store.best_header().header.hash(), hash_of_4);
    // solution range adjustment is disabled
    assert!(!importer.store.best_header().should_adjust_solution_range);

    // enable solution range adjustment in this header
    let constants = importer.store.chain_constants();
    let header_at_4 = importer.store.header(hash_of_4).unwrap();
    let digests_at_4 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_4.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_4.header.hash(),
            number: 5,
            slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot).into(),
            keypair: &keypair,
            randomness: digests_at_4.global_randomness,
            salt: digests_at_4.salt,
        });
    importer
        .store
        .override_solution_range(header_at_4.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(header_at_4.header.hash(), 0);
    let solution_range_override = 100;
    let next_solution_range = solution_range_override;
    let digests = header.digest_mut();
    digests.push(DigestItem::next_solution_range(next_solution_range));
    digests.push(DigestItem::enable_solution_range_adjustment_and_override(
        Some(solution_range_override),
    ));
    seal_header(&keypair, &mut header);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    assert_eq!(importer.store.best_header().header.hash(), header.hash());
    assert!(importer.store.best_header().should_adjust_solution_range);
    assert_eq!(header_at_4.maybe_current_solution_range_override, None);
    assert_eq!(header_at_4.maybe_next_solution_range_override, None);
}

#[test]
fn test_disallow_enable_solution_range_digest_when_solution_range_adjustment_is_already_enabled() {
    let mut constants = default_test_constants();
    constants.era_duration = 5;
    let (store, genesis_hash) = initialize_store(constants, true, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None);
    assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

    // try to import header with enable solution range adjustment digest
    let constants = importer.store.chain_constants();
    let header_at_4 = importer.store.header(hash_of_4).unwrap();
    let digests_at_4 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_4.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_4.header.hash(),
            number: 5,
            slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot).into(),
            keypair: &keypair,
            randomness: digests_at_4.global_randomness,
            salt: digests_at_4.salt,
        });
    importer
        .store
        .override_solution_range(header_at_4.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(header_at_4.header.hash(), 0);
    let digests = header.digest_mut();
    digests.push(DigestItem::enable_solution_range_adjustment_and_override(
        None,
    ));
    seal_header(&keypair, &mut header);
    let res = importer.import_header(header.clone());
    assert_err!(
        res,
        ImportError::DigestError(DigestError::NextDigestVerificationError(
            ErrorDigestType::EnableSolutionRangeAdjustmentAndOverride
        ))
    );
}

#[test]
fn test_next_salt_digest() {
    let mut constants = default_test_constants();
    constants.eon_duration = 10;
    constants.next_salt_reveal_interval = 3;
    // slot probability to 1 block a second so that we can predict eon change
    constants.slot_probability = (1, 1);
    let (store, genesis_hash) = initialize_store(constants, true, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_10 = add_headers_to_chain(&mut importer, &keypair, 10, None);
    let header_at_10 = importer.store.best_header();
    assert_eq!(header_at_10.header.hash(), hash_of_10);
    assert_eq!(header_at_10.salt_derivation_info.eon_index, 0);

    // salt must been revealed at header_4 so randomness should be empty until 3
    let header_at_3 = importer
        .store
        .headers_at_number(3)
        .first()
        .cloned()
        .unwrap();
    assert_eq!(header_at_3.salt_derivation_info.eon_index, 0);
    assert_eq!(header_at_3.salt_derivation_info.maybe_randomness, None);

    // randomness is stored starting from header 4
    let header_at_4 = importer
        .store
        .headers_at_number(4)
        .first()
        .cloned()
        .unwrap();
    assert_eq!(header_at_4.salt_derivation_info.eon_index, 0);
    let digests_at_4 = extract_pre_digest(&header_at_4.header).unwrap();
    let randomness_at_4 = derive_randomness(
        &PublicKey::from(&digests_at_4.solution.public_key),
        digests_at_4.solution.tag,
        &digests_at_4.solution.tag_signature,
    )
    .unwrap();
    assert_eq!(
        header_at_4.salt_derivation_info.maybe_randomness,
        Some(randomness_at_4)
    );

    // try to import header at 11 without next salt
    let digests_at_10 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_10.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_10.header.hash(),
            number: 11,
            slot: digests_at_10.pre_digest.slot.saturating_add(1u64).into(),
            keypair: &keypair,
            randomness: digests_at_10.global_randomness,
            salt: digests_at_10.salt,
        });
    seal_header(&keypair, &mut header);
    importer
        .store
        .override_solution_range(header_at_10.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(header_at_10.header.hash(), 0);
    let res = importer.import_header(header.clone());
    assert_err!(
        res,
        ImportError::DigestError(DigestError::NextDigestVerificationError(
            ErrorDigestType::NextSalt
        ))
    );

    // add next salt and eon index will change
    remove_seal(&mut header);
    let next_salt = subspace_verification::derive_next_salt_from_randomness(0, &randomness_at_4);
    let digests = header.digest_mut();
    digests.push(DigestItem::next_salt(next_salt));
    seal_header(&keypair, &mut header);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    let header_at_11 = importer.store.best_header();
    assert_eq!(header_at_11.header.hash(), header.hash());
    assert_eq!(header_at_11.salt_derivation_info.eon_index, 1);
    assert_eq!(header_at_11.salt_derivation_info.maybe_randomness, None);
}

#[test]
fn test_next_salt_reveal_in_same_block_as_eon_change() {
    let mut constants = default_test_constants();
    constants.eon_duration = 10;
    constants.next_salt_reveal_interval = 3;
    // slot probability to 1 block a second so that we can predict eon change
    constants.slot_probability = (1, 1);
    let (store, genesis_hash) = initialize_store(constants, true, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_10 = add_headers_to_chain(&mut importer, &keypair, 10, None);
    let header_at_10 = importer.store.best_header();
    assert_eq!(header_at_10.header.hash(), hash_of_10);
    assert_eq!(header_at_10.salt_derivation_info.eon_index, 0);

    // header 11 slot is long enough that it missed the salt reveal
    // hence, next salt for next eon is revealed at block 11 itself
    let digests_at_10 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_10.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_10.header.hash(),
            number: 11,
            slot: digests_at_10.pre_digest.slot.saturating_add(5u64).into(),
            keypair: &keypair,
            randomness: digests_at_10.global_randomness,
            salt: digests_at_10.salt,
        });
    importer
        .store
        .override_solution_range(header_at_10.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(header_at_10.header.hash(), 0);
    let header_at_4 = importer
        .store
        .headers_at_number(4)
        .first()
        .cloned()
        .unwrap();
    assert_eq!(header_at_4.salt_derivation_info.eon_index, 0);
    let digests_at_4 = extract_pre_digest(&header_at_4.header).unwrap();
    let randomness_at_4 = derive_randomness(
        &PublicKey::from(&digests_at_4.solution.public_key),
        digests_at_4.solution.tag,
        &digests_at_4.solution.tag_signature,
    )
    .unwrap();
    let next_salt = subspace_verification::derive_next_salt_from_randomness(0, &randomness_at_4);
    let digests = header.digest_mut();
    digests.push(DigestItem::next_salt(next_salt));
    seal_header(&keypair, &mut header);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    let header_at_11 = importer.store.best_header();
    assert_eq!(header_at_11.header.hash(), header.hash());
    assert_eq!(header_at_11.salt_derivation_info.eon_index, 1);
    let digests_at_11 = extract_pre_digest(&header_at_11.header).unwrap();
    let randomness_at_11 = derive_randomness(
        &PublicKey::from(&digests_at_11.solution.public_key),
        digests_at_11.solution.tag,
        &digests_at_11.solution.tag_signature,
    )
    .unwrap();
    assert_eq!(
        header_at_11.salt_derivation_info.maybe_randomness,
        Some(randomness_at_11)
    );
}

#[test]
fn test_current_salt_reveal_and_eon_change_in_same_block() {
    let mut constants = default_test_constants();
    constants.eon_duration = 10;
    constants.next_salt_reveal_interval = 3;
    // slot probability to 1 block a second so that we can predict eon change
    constants.slot_probability = (1, 1);
    let (store, genesis_hash) = initialize_store(constants, true, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    assert_eq!(
        importer.store.finalized_header().header.hash(),
        genesis_hash
    );

    let hash_of_3 = add_headers_to_chain(&mut importer, &keypair, 3, None);
    let header_at_3 = importer.store.best_header();
    assert_eq!(header_at_3.header.hash(), hash_of_3);
    assert_eq!(header_at_3.salt_derivation_info.eon_index, 0);
    assert_eq!(header_at_3.salt_derivation_info.maybe_randomness, None);

    // Block #4 slot is so far that following happens in the same block
    // Salt is revealed
    // eon will be changed
    // next salt is also revealed
    let digests_at_3 =
        extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &header_at_3.header,
        )
        .unwrap();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: header_at_3.header.hash(),
            number: 4,
            slot: digests_at_3.pre_digest.slot.saturating_add(8u64).into(),
            keypair: &keypair,
            randomness: digests_at_3.global_randomness,
            salt: digests_at_3.salt,
        });
    importer
        .store
        .override_solution_range(header_at_3.header.hash(), solution_range);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer
        .store
        .override_cumulative_weight(header_at_3.header.hash(), 0);
    let digests_at_4 = extract_pre_digest(&header).unwrap();
    let randomness_at_4 = derive_randomness(
        &PublicKey::from(&digests_at_4.solution.public_key),
        digests_at_4.solution.tag,
        &digests_at_4.solution.tag_signature,
    )
    .unwrap();
    let next_salt = subspace_verification::derive_next_salt_from_randomness(0, &randomness_at_4);
    let digests = header.digest_mut();
    digests.push(DigestItem::next_salt(next_salt));
    seal_header(&keypair, &mut header);
    let res = importer.import_header(header.clone());
    assert_ok!(res);

    let header_at_4 = importer.store.best_header();
    assert_eq!(header_at_4.header.hash(), header.hash());
    assert_eq!(header_at_4.salt_derivation_info.eon_index, 1);
    assert_eq!(header_at_4.salt_derivation_info.maybe_randomness, None);
}

fn ensure_store_is_storage_bounded(headers_to_keep_beyond_k_depth: NumberOf<Header>) {
    let mut constants = default_test_constants();
    constants.k_depth = 7;
    constants.storage_bound =
        StorageBound::NumberOfHeaderToKeepBeyondKDepth(headers_to_keep_beyond_k_depth);
    let (store, _genesis_hash) = initialize_store(constants, true, None);
    let keypair = Keypair::generate();
    let mut importer = HeaderImporter::new(store);
    // import some more canonical blocks
    let hash_of_50 = add_headers_to_chain(&mut importer, &keypair, 50, None);
    let best_header = importer.store.best_header();
    assert_eq!(best_header.header.hash(), hash_of_50);

    // check storage bound
    let finalized_head = importer.store.finalized_header();
    assert_eq!(finalized_head.header.number, 43);
    // there should be headers at and below (finalized_head - bound - 1)
    let mut pruned_number = 43 - headers_to_keep_beyond_k_depth - 1;
    while pruned_number != 0 {
        assert!(importer.store.headers_at_number(pruned_number).is_empty());
        pruned_number -= 1;
    }

    assert!(importer.store.headers_at_number(0).is_empty());
}

#[test]
fn test_storage_bound_with_headers_beyond_k_depth_is_zero() {
    ensure_store_is_storage_bounded(0)
}

#[test]
fn test_storage_bound_with_headers_beyond_k_depth_is_one() {
    ensure_store_is_storage_bounded(1)
}

#[test]
fn test_storage_bound_with_headers_beyond_k_depth_is_more_than_one() {
    ensure_store_is_storage_bounded(5)
}

#[test]
fn test_block_author_different_farmer() {
    let mut constants = default_test_constants();
    let keypair_allowed = Keypair::generate();
    let pub_key = FarmerPublicKey::unchecked_from(keypair_allowed.public.to_bytes());
    let (store, genesis_hash) = initialize_store(constants.clone(), true, Some(pub_key));
    let mut importer = HeaderImporter::new(store);

    // try to import header authored by different farmer
    let keypair_disallowed = Keypair::generate();
    let (randomness, salt) = default_randomness_and_salt();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: genesis_hash,
            number: 1,
            slot: 1,
            keypair: &keypair_disallowed,
            randomness,
            salt,
        });
    seal_header(&keypair_disallowed, &mut header);
    constants.genesis_digest_items.next_solution_range = solution_range;
    importer.store.override_constants(constants);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer.store.override_cumulative_weight(genesis_hash, 0);
    let res = importer.import_header(header);
    assert_err!(
        res,
        ImportError::IncorrectBlockAuthor(FarmerPublicKey::unchecked_from(
            keypair_disallowed.public.to_bytes()
        ))
    )
}

#[test]
fn test_block_author_first_farmer() {
    let mut constants = default_test_constants();
    let keypair = Keypair::generate();
    let pub_key = FarmerPublicKey::unchecked_from(keypair.public.to_bytes());
    let (store, genesis_hash) = initialize_store(constants.clone(), true, None);
    let mut importer = HeaderImporter::new(store);

    // try import header with first farmer
    let (randomness, salt) = default_randomness_and_salt();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: genesis_hash,
            number: 1,
            slot: 1,
            keypair: &keypair,
            randomness,
            salt,
        });
    header
        .digest
        .logs
        .push(DigestItem::root_plot_public_key_update(Some(
            pub_key.clone(),
        )));
    seal_header(&keypair, &mut header);
    constants.genesis_digest_items.next_solution_range = solution_range;
    importer.store.override_constants(constants);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer.store.override_cumulative_weight(genesis_hash, 0);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    let best_header = importer.store.best_header();
    assert_eq!(header.hash(), best_header.header.hash());
    assert_eq!(best_header.maybe_root_plot_public_key, Some(pub_key))
}

#[test]
fn test_block_author_allow_any_farmer() {
    let mut constants = default_test_constants();
    let keypair = Keypair::generate();
    let pub_key = FarmerPublicKey::unchecked_from(keypair.public.to_bytes());
    let (store, genesis_hash) = initialize_store(constants.clone(), true, Some(pub_key));
    let mut importer = HeaderImporter::new(store);

    // try to import header authored by different farmer
    let (randomness, salt) = default_randomness_and_salt();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: genesis_hash,
            number: 1,
            slot: 1,
            keypair: &keypair,
            randomness,
            salt,
        });
    header
        .digest
        .logs
        .push(DigestItem::root_plot_public_key_update(None));
    seal_header(&keypair, &mut header);
    constants.genesis_digest_items.next_solution_range = solution_range;
    importer.store.override_constants(constants);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer.store.override_cumulative_weight(genesis_hash, 0);
    let res = importer.import_header(header.clone());
    assert_ok!(res);
    let best_header = importer.store.best_header();
    assert_eq!(header.hash(), best_header.header.hash());
    assert_eq!(best_header.maybe_root_plot_public_key, None)
}

#[test]
fn test_disallow_root_plot_public_key_override() {
    let mut constants = default_test_constants();
    let keypair_allowed = Keypair::generate();
    let pub_key = FarmerPublicKey::unchecked_from(keypair_allowed.public.to_bytes());
    let (store, genesis_hash) = initialize_store(constants.clone(), true, Some(pub_key));
    let mut importer = HeaderImporter::new(store);

    // try to import header that contains root plot public key override
    let (randomness, salt) = default_randomness_and_salt();
    let (mut header, solution_range, segment_index, records_root) =
        valid_header(ValidHeaderParams {
            parent_hash: genesis_hash,
            number: 1,
            slot: 1,
            keypair: &keypair_allowed,
            randomness,
            salt,
        });
    let keypair_disallowed = Keypair::generate();
    let pub_key = FarmerPublicKey::unchecked_from(keypair_disallowed.public.to_bytes());
    header
        .digest
        .logs
        .push(DigestItem::root_plot_public_key_update(Some(pub_key)));
    seal_header(&keypair_allowed, &mut header);
    constants.genesis_digest_items.next_solution_range = solution_range;
    importer.store.override_constants(constants);
    importer
        .store
        .store_records_root(segment_index, records_root);
    importer.store.override_cumulative_weight(genesis_hash, 0);
    let res = importer.import_header(header);
    assert_err!(
        res,
        ImportError::DigestError(DigestError::NextDigestVerificationError(
            ErrorDigestType::RootPlotPublicKeyUpdate
        ))
    )
}
