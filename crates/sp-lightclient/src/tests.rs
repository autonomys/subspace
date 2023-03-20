use crate::mock::{new_test_ext, Header, MockStorage};
use crate::{
    ChainConstants, DigestError, HashOf, HeaderExt, HeaderImporter, ImportError, NextDigestItems,
    NumberOf, Storage, StorageBound,
};
use async_trait::async_trait;
use codec::{Decode, Encode};
use frame_support::{assert_err, assert_ok};
use futures::executor::block_on;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    derive_next_global_randomness, derive_next_solution_range, extract_pre_digest,
    extract_subspace_digest_items, CompatibleDigestItem, DeriveNextSolutionRangeParams,
    ErrorDigestType, PreDigest, SubspaceDigestItems,
};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature};
use sp_runtime::app_crypto::UncheckedFrom;
use sp_runtime::testing::H256;
use sp_runtime::traits::Header as HeaderT;
use sp_runtime::{Digest, DigestItem};
use std::error::Error;
use std::io::Cursor;
use std::num::{NonZeroU32, NonZeroU64};
use subspace_archiving::archiver::{ArchivedSegment, Archiver};
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::sector_codec::SectorCodec;
use subspace_core_primitives::{
    Piece, PieceIndex, PublicKey, Randomness, RecordsRoot, RootBlock, SectorId, SegmentIndex,
    Solution, SolutionRange, PLOT_SECTOR_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, RECORD_SIZE,
};
use subspace_farmer_components::farming::audit_sector;
use subspace_farmer_components::plotting::{plot_sector, PieceGetter, PieceGetterRetryPolicy};
use subspace_farmer_components::{FarmerProtocolInfo, SectorMetadata};
use subspace_solving::{derive_global_challenge, REWARD_SIGNING_CONTEXT};
use subspace_verification::{derive_audit_chunk, derive_randomness};

fn default_randomness() -> Randomness {
    [1u8; 32]
}

fn default_test_constants() -> ChainConstants<Header> {
    let randomness = default_randomness();
    ChainConstants {
        k_depth: 7,
        genesis_digest_items: NextDigestItems {
            next_global_randomness: randomness,
            next_solution_range: Default::default(),
        },
        genesis_records_roots: Default::default(),
        global_randomness_interval: 20,
        era_duration: 20,
        slot_probability: (1, 6),
        storage_bound: Default::default(),
    }
}

fn derive_solution_range(
    local_challenge: &SolutionRange,
    audit_chunk: &SolutionRange,
) -> SolutionRange {
    subspace_core_primitives::bidirectional_distance(local_challenge, audit_chunk) * 2
}

fn archived_segment(kzg: Kzg) -> ArchivedSegment {
    // we don't care about the block data
    let mut rng = StdRng::seed_from_u64(0);
    let mut block = vec![0u8; RECORDED_HISTORY_SEGMENT_SIZE as usize];
    rng.fill(block.as_mut_slice());

    let mut archiver = Archiver::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg).unwrap();

    archiver
        .add_block(block, Default::default())
        .into_iter()
        .next()
        .unwrap()
}

struct Farmer {
    root_block: RootBlock,
    sector: Vec<u8>,
    sector_metadata: Vec<u8>,
}

impl Farmer {
    fn new(keypair: &Keypair) -> Self {
        let kzg = Kzg::new(kzg::embedded_kzg_settings());
        let archived_segment = archived_segment(kzg.clone());
        let root_block = archived_segment.root_block;
        let total_pieces = NonZeroU64::new(archived_segment.pieces.count() as u64).unwrap();
        let mut sector = vec![0u8; PLOT_SECTOR_SIZE as usize];
        let mut sector_metadata = vec![0u8; SectorMetadata::encoded_size()];
        let sector_index = 0;
        let piece_getter = TestPieceGetter { archived_segment };
        let public_key = PublicKey::from(keypair.public.to_bytes());
        let farmer_protocol_info = FarmerProtocolInfo {
            record_size: NonZeroU32::new(RECORD_SIZE).unwrap(),
            recorded_history_segment_size: RECORDED_HISTORY_SEGMENT_SIZE,
            total_pieces,
            sector_expiration: 100,
        };
        let sector_codec = SectorCodec::new(PLOT_SECTOR_SIZE as usize).unwrap();

        block_on(plot_sector(
            &public_key,
            sector_index,
            &piece_getter,
            PieceGetterRetryPolicy::default(),
            &farmer_protocol_info,
            &kzg,
            &sector_codec,
            Cursor::new(sector.as_mut_slice()),
            Cursor::new(sector_metadata.as_mut_slice()),
            Default::default(),
        ))
        .unwrap();

        Self {
            root_block,
            sector,
            sector_metadata,
        }
    }
}

struct ValidHeaderParams<'a> {
    parent_hash: HashOf<Header>,
    number: NumberOf<Header>,
    slot: u64,
    keypair: &'a Keypair,
    randomness: Randomness,
    farmer: &'a Farmer,
}

struct TestPieceGetter {
    archived_segment: ArchivedSegment,
}

#[async_trait]
impl PieceGetter for TestPieceGetter {
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
        _: PieceGetterRetryPolicy,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        Ok(self
            .archived_segment
            .pieces
            .as_pieces()
            .nth(piece_index as usize)
            .map(Piece::from))
    }
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
        farmer,
    } = params;

    let segment_index = farmer.root_block.segment_index();
    let records_root = farmer.root_block.records_root();
    let sector_index = 0;
    let public_key = PublicKey::from(keypair.public.to_bytes());
    let sector_codec = SectorCodec::new(PLOT_SECTOR_SIZE as usize).unwrap();

    let global_challenge = derive_global_challenge(&randomness, slot);
    let eligible_sector = audit_sector(
        &public_key,
        sector_index,
        &global_challenge,
        SolutionRange::MAX,
        Cursor::new(&farmer.sector),
    )
    .unwrap()
    .expect("With max solution range there must be a sector eligible; qed");
    let local_challenge = eligible_sector.local_challenge;
    let solution = eligible_sector
        .try_into_solutions(
            keypair,
            public_key,
            &sector_codec,
            farmer.sector.as_slice(),
            farmer.sector_metadata.as_slice(),
        )
        .unwrap()
        .into_iter()
        .next()
        .expect("With max solution range there must be a solution; qed");
    // Lazy conversion to a different type of public key and reward address
    let solution =
        Solution::<FarmerPublicKey, FarmerPublicKey>::decode(&mut solution.encode().as_slice())
            .unwrap();
    let audit_chunk = derive_audit_chunk(&solution.chunk.to_bytes());
    let solution_range = derive_solution_range(&local_challenge, &audit_chunk);

    let pre_digest = PreDigest {
        slot: slot.into(),
        solution,
    };
    let digests = vec![
        DigestItem::global_randomness(randomness),
        DigestItem::solution_range(solution_range),
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
        era_start_slot: Default::default(),
        should_adjust_solution_range,
        maybe_current_solution_range_override: None,
        maybe_next_solution_range_override: None,
        maybe_root_plot_public_key,
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
    farmer: &Farmer,
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
        let (randomness, override_next_solution) = if number == 1 {
            let randomness = default_randomness();
            (randomness, false)
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
            (randomness, digests.next_global_randomness.is_some())
        };

        let (mut header, solution_range, segment_index, records_root) =
            valid_header(ValidHeaderParams {
                parent_hash,
                number,
                slot: slot.into(),
                keypair,
                randomness,
                farmer,
            });
        let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
            extract_subspace_digest_items(&header).unwrap();
        let sector_id = SectorId::new(
            &(&digests.pre_digest.solution.public_key).into(),
            digests.pre_digest.solution.sector_index,
        );
        let new_weight =
            HeaderImporter::<Header, MockStorage>::calculate_block_weight(&sector_id, &digests);
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
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let constants = default_test_constants();
        let (mut store, _genesis_hash) = initialize_store(constants, true, None);
        let randomness = default_randomness();
        let (header, _, segment_index, records_root) = valid_header(ValidHeaderParams {
            parent_hash: Default::default(),
            number: 1,
            slot: 1,
            keypair: &keypair,
            randomness,
            farmer: &farmer,
        });
        store.store_records_root(segment_index, records_root);
        let mut importer = HeaderImporter::new(store);
        assert_err!(
            importer.import_header(header.clone()),
            ImportError::MissingParent(header.hash())
        );
    });
}

#[test]
fn test_header_import_non_canonical() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let constants = default_test_constants();
        let (store, _genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        let hash_of_2 = add_headers_to_chain(&mut importer, &keypair, 2, None, &farmer);
        let best_header = importer.store.best_header();
        assert_eq!(best_header.header.hash(), hash_of_2);

        // import canonical block 3
        let hash_of_3 = add_headers_to_chain(&mut importer, &keypair, 1, None, &farmer);
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
            &farmer,
        );

        let best_header_ext = importer.store.best_header();
        assert_eq!(best_header_ext.header, best_header.header);
        // we still track the forks
        assert_eq!(importer.store.headers_at_number(3).len(), 2);
    });
}

#[test]
fn test_header_import_canonical() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let constants = default_test_constants();
        let (store, _genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        let hash_of_5 = add_headers_to_chain(&mut importer, &keypair, 5, None, &farmer);
        let best_header = importer.store.best_header();
        assert_eq!(best_header.header.hash(), hash_of_5);

        // import some more canonical blocks
        let hash_of_25 = add_headers_to_chain(&mut importer, &keypair, 20, None, &farmer);
        let best_header = importer.store.best_header();
        assert_eq!(best_header.header.hash(), hash_of_25);
        assert_eq!(importer.store.headers_at_number(25).len(), 1);
    });
}

#[test]
fn test_header_import_non_canonical_with_equal_block_weight() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let constants = default_test_constants();
        let (store, _genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        let hash_of_2 = add_headers_to_chain(&mut importer, &keypair, 2, None, &farmer);
        let best_header = importer.store.best_header();
        assert_eq!(best_header.header.hash(), hash_of_2);

        // import canonical block 3
        let hash_of_3 = add_headers_to_chain(&mut importer, &keypair, 1, None, &farmer);
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
            &farmer,
        );

        let best_header_ext = importer.store.best_header();
        assert_eq!(best_header_ext.header, best_header.header);
        // we still track the forks
        assert_eq!(importer.store.headers_at_number(3).len(), 2);
    });
}

#[test]
fn test_chain_reorg_to_longer_chain() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        constants.k_depth = 4;
        let (store, genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer);
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
            &farmer,
        );
        assert_eq!(best_header.header.hash(), hash_of_4);
        // block 0 is still finalized
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );
        ensure_finalized_heads_have_no_forks(&importer.store, 0);

        // add new best header at 5
        let hash_of_5 = add_headers_to_chain(&mut importer, &keypair, 1, None, &farmer);
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
            &farmer,
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
            &farmer,
        );
        assert_eq!(importer.store.best_header().header.hash(), hash_of_9);

        // now the finalized header must be 5
        ensure_finalized_heads_have_no_forks(&importer.store, 5);
    });
}

#[test]
fn test_reorg_to_heavier_smaller_chain() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        constants.k_depth = 4;
        let (store, genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_5 = add_headers_to_chain(&mut importer, &keypair, 5, None, &farmer);
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
                farmer: &farmer,
            });
        seal_header(&keypair, &mut header);
        let digests: SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature> =
            extract_subspace_digest_items(&header).unwrap();
        let sector_id = SectorId::new(
            &(&digests.pre_digest.solution.public_key).into(),
            digests.pre_digest.solution.sector_index,
        );
        let new_weight =
            HeaderImporter::<Header, MockStorage>::calculate_block_weight(&sector_id, &digests);
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
        assert_err!(res, ImportError::SwitchedToForkBelowArchivingDepth);
    });
}

#[test]
fn test_next_global_randomness_digest() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        constants.global_randomness_interval = 5;
        let (store, genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer);
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
                farmer: &farmer,
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
            &pre_digest.solution.chunk.to_bytes(),
            &pre_digest.solution.chunk_signature,
        )
        .unwrap();
        let digests = header.digest_mut();
        digests.push(DigestItem::next_global_randomness(randomness));
        seal_header(&keypair, &mut header);
        let res = importer.import_header(header.clone());
        assert_ok!(res);
        assert_eq!(importer.store.best_header().header.hash(), header.hash());
    });
}

#[test]
fn test_next_solution_range_digest_with_adjustment_enabled() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        constants.era_duration = 5;
        let (store, genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer);
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
                farmer: &farmer,
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
    });
}

#[test]
fn test_next_solution_range_digest_with_adjustment_disabled() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        constants.era_duration = 5;
        let (store, genesis_hash) = initialize_store(constants, false, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer);
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
                farmer: &farmer,
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
    });
}

#[test]
fn test_enable_solution_range_adjustment_without_override() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        constants.era_duration = 5;
        let (store, genesis_hash) = initialize_store(constants, false, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer);
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
                farmer: &farmer,
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
    });
}

#[test]
fn test_enable_solution_range_adjustment_with_override_between_update_intervals() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        constants.era_duration = 5;
        let (store, genesis_hash) = initialize_store(constants, false, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_3 = add_headers_to_chain(&mut importer, &keypair, 3, None, &farmer);
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
                farmer: &farmer,
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
    });
}

#[test]
fn test_enable_solution_range_adjustment_with_override_at_interval_change() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        constants.era_duration = 5;
        let (store, genesis_hash) = initialize_store(constants, false, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer);
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
                farmer: &farmer,
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
    });
}

#[test]
fn test_disallow_enable_solution_range_digest_when_solution_range_adjustment_is_already_enabled() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        constants.era_duration = 5;
        let (store, genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer);
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
                farmer: &farmer,
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
    });
}

fn ensure_store_is_storage_bounded(headers_to_keep_beyond_k_depth: NumberOf<Header>) {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        constants.k_depth = 7;
        constants.storage_bound =
            StorageBound::NumberOfHeaderToKeepBeyondKDepth(headers_to_keep_beyond_k_depth);
        let (store, _genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        // import some more canonical blocks
        let hash_of_50 = add_headers_to_chain(&mut importer, &keypair, 50, None, &farmer);
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
    });
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
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        let keypair_allowed = Keypair::generate();
        let pub_key = FarmerPublicKey::unchecked_from(keypair_allowed.public.to_bytes());
        let (store, genesis_hash) = initialize_store(constants.clone(), true, Some(pub_key));
        let mut importer = HeaderImporter::new(store);

        // try to import header authored by different farmer
        let keypair_disallowed = Keypair::generate();
        let randomness = default_randomness();
        let (mut header, solution_range, segment_index, records_root) =
            valid_header(ValidHeaderParams {
                parent_hash: genesis_hash,
                number: 1,
                slot: 1,
                keypair: &keypair_disallowed,
                randomness,
                farmer: &farmer,
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
        );
    });
}

#[test]
fn test_block_author_first_farmer() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        let pub_key = FarmerPublicKey::unchecked_from(keypair.public.to_bytes());
        let (store, genesis_hash) = initialize_store(constants.clone(), true, None);
        let mut importer = HeaderImporter::new(store);

        // try import header with first farmer
        let randomness = default_randomness();
        let (mut header, solution_range, segment_index, records_root) =
            valid_header(ValidHeaderParams {
                parent_hash: genesis_hash,
                number: 1,
                slot: 1,
                keypair: &keypair,
                randomness,
                farmer: &farmer,
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
        assert_eq!(best_header.maybe_root_plot_public_key, Some(pub_key));
    });
}

#[test]
fn test_block_author_allow_any_farmer() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        let pub_key = FarmerPublicKey::unchecked_from(keypair.public.to_bytes());
        let (store, genesis_hash) = initialize_store(constants.clone(), true, Some(pub_key));
        let mut importer = HeaderImporter::new(store);

        // try to import header authored by different farmer
        let randomness = default_randomness();
        let (mut header, solution_range, segment_index, records_root) =
            valid_header(ValidHeaderParams {
                parent_hash: genesis_hash,
                number: 1,
                slot: 1,
                keypair: &keypair,
                randomness,
                farmer: &farmer,
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
        assert_eq!(best_header.maybe_root_plot_public_key, None);
    });
}

#[test]
fn test_disallow_root_plot_public_key_override() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = Farmer::new(&keypair);

        let mut constants = default_test_constants();
        let keypair_allowed = Keypair::generate();
        let pub_key = FarmerPublicKey::unchecked_from(keypair_allowed.public.to_bytes());
        let (store, genesis_hash) = initialize_store(constants.clone(), true, Some(pub_key));
        let mut importer = HeaderImporter::new(store);

        // try to import header that contains root plot public key override
        let randomness = default_randomness();
        let (mut header, solution_range, segment_index, records_root) =
            valid_header(ValidHeaderParams {
                parent_hash: genesis_hash,
                number: 1,
                slot: 1,
                keypair: &keypair_allowed,
                randomness,
                farmer: &farmer,
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
        );
    });
}
