use crate::mock::{kzg_instance, new_test_ext, Header, MockStorage, PosTable};
use crate::{
    ChainConstants, DigestError, HashOf, HeaderExt, HeaderImporter, ImportError, NextDigestItems,
    NumberOf, Storage, StorageBound,
};
use frame_support::{assert_err, assert_ok};
use futures::executor::block_on;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
#[cfg(not(feature = "pot"))]
use sp_consensus_subspace::digests::derive_next_global_randomness;
use sp_consensus_subspace::digests::{
    derive_next_solution_range, extract_pre_digest, extract_subspace_digest_items,
    CompatibleDigestItem, DeriveNextSolutionRangeParams, ErrorDigestType, PreDigest,
};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature};
use sp_runtime::app_crypto::UncheckedFrom;
use sp_runtime::testing::H256;
use sp_runtime::traits::Header as HeaderT;
use sp_runtime::{Digest, DigestItem};
use std::iter;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::OnceLock;
use subspace_archiving::archiver::{Archiver, NewArchivedSegment};
#[cfg(feature = "pot")]
use subspace_core_primitives::PotOutput;
use subspace_core_primitives::{
    BlockWeight, HistorySize, PublicKey, Randomness, Record, RecordedHistorySegment,
    SegmentCommitment, SegmentIndex, SlotNumber, Solution, SolutionRange, REWARD_SIGNING_CONTEXT,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::auditing::audit_sector;
use subspace_farmer_components::plotting::plot_sector;
use subspace_farmer_components::sector::{sector_size, SectorMetadataChecksummed};
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_proof_of_space::Table;
#[cfg(not(feature = "pot"))]
use subspace_verification::derive_randomness;
use subspace_verification::{calculate_block_weight, verify_solution, VerifySolutionParams};

fn erasure_coding_instance() -> &'static ErasureCoding {
    static ERASURE_CODING: OnceLock<ErasureCoding> = OnceLock::new();

    ERASURE_CODING.get_or_init(|| {
        ErasureCoding::new(
            NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
                .expect("Not zero; qed"),
        )
        .unwrap()
    })
}

#[cfg(not(feature = "pot"))]
fn default_randomness() -> Randomness {
    Randomness::from([1u8; 32])
}

fn default_test_constants() -> ChainConstants<Header> {
    #[cfg(not(feature = "pot"))]
    let global_randomness = default_randomness();
    ChainConstants {
        k_depth: 7,
        genesis_digest_items: NextDigestItems {
            #[cfg(not(feature = "pot"))]
            next_global_randomness: global_randomness,
            next_solution_range: Default::default(),
        },
        genesis_segment_commitments: Default::default(),
        #[cfg(not(feature = "pot"))]
        global_randomness_interval: 20,
        era_duration: 20,
        slot_probability: (1, 6),
        storage_bound: Default::default(),
        recent_segments: HistorySize::from(NonZeroU64::new(5).unwrap()),
        recent_history_fraction: (
            HistorySize::from(NonZeroU64::new(1).unwrap()),
            HistorySize::from(NonZeroU64::new(10).unwrap()),
        ),
        min_sector_lifetime: HistorySize::from(NonZeroU64::new(4).unwrap()),
    }
}

fn archived_segment() -> &'static NewArchivedSegment {
    static ARCHIVED_SEGMENT: OnceLock<NewArchivedSegment> = OnceLock::new();

    ARCHIVED_SEGMENT.get_or_init(|| {
        // we don't care about the block data
        let mut rng = StdRng::seed_from_u64(0);
        let mut block = vec![0u8; RecordedHistorySegment::SIZE];
        rng.fill(block.as_mut_slice());

        let mut archiver = Archiver::new(kzg_instance().clone()).unwrap();

        archiver
            .add_block(block, Default::default(), true)
            .into_iter()
            .next()
            .unwrap()
    })
}

struct FarmerParameters {
    farmer_protocol_info: FarmerProtocolInfo,
}

impl FarmerParameters {
    fn new() -> Self {
        let farmer_protocol_info = FarmerProtocolInfo {
            history_size: HistorySize::from(SegmentIndex::ZERO),
            max_pieces_in_sector: 1,
            recent_segments: HistorySize::from(NonZeroU64::new(5).unwrap()),
            recent_history_fraction: (
                HistorySize::from(NonZeroU64::new(1).unwrap()),
                HistorySize::from(NonZeroU64::new(10).unwrap()),
            ),
            min_sector_lifetime: HistorySize::from(NonZeroU64::new(4).unwrap()),
        };

        Self {
            farmer_protocol_info,
        }
    }
}

struct ValidHeaderParams<'a> {
    parent_hash: HashOf<Header>,
    number: NumberOf<Header>,
    slot: u64,
    keypair: &'a Keypair,
    #[cfg(not(feature = "pot"))]
    global_randomness: Randomness,
    #[cfg(feature = "pot")]
    proof_of_time: PotOutput,
    #[cfg(feature = "pot")]
    future_proof_of_time: PotOutput,
    farmer_parameters: &'a FarmerParameters,
}

fn valid_header(
    params: ValidHeaderParams<'_>,
) -> (
    Header,
    SolutionRange,
    BlockWeight,
    SegmentIndex,
    SegmentCommitment,
) {
    let ValidHeaderParams {
        parent_hash,
        number,
        slot,
        keypair,
        #[cfg(not(feature = "pot"))]
        global_randomness,
        #[cfg(feature = "pot")]
        proof_of_time,
        #[cfg(feature = "pot")]
        future_proof_of_time,
        farmer_parameters,
    } = params;

    let archived_segment = archived_segment();

    let segment_index = archived_segment.segment_header.segment_index();
    let segment_commitment = archived_segment.segment_header.segment_commitment();
    let public_key = PublicKey::from(keypair.public.to_bytes());

    let pieces_in_sector = farmer_parameters.farmer_protocol_info.max_pieces_in_sector;
    let sector_size = sector_size(pieces_in_sector);

    let mut table_generator = PosTable::generator();

    for sector_index in iter::from_fn(|| Some(rand::random())) {
        let mut plotted_sector_bytes = Vec::new();
        let mut plotted_sector_metadata_bytes = Vec::new();

        let plotted_sector = block_on(plot_sector(
            &public_key,
            sector_index,
            &archived_segment.pieces,
            &farmer_parameters.farmer_protocol_info,
            kzg_instance(),
            erasure_coding_instance(),
            pieces_in_sector,
            &mut plotted_sector_bytes,
            &mut plotted_sector_metadata_bytes,
            records_encoder: &mut CpuRecordsEncoder::<PosTable>::new(
                slice::from_mut(&mut table_generator),
                &erasure_coding,
                &Default::default(),
            ),
        ))
        .unwrap();

        #[cfg(feature = "pot")]
        let global_randomness = proof_of_time.derive_global_randomness();
        let global_challenge = global_randomness.derive_global_challenge(slot);

        let maybe_solution_candidates = audit_sector(
            &public_key,
            &global_challenge,
            SolutionRange::MAX,
            &plotted_sector_bytes,
            &plotted_sector.sector_metadata,
        );

        let Some(solution_candidates) = maybe_solution_candidates else {
            // Sector didn't have any solutions
            continue;
        };

        let solution = solution_candidates
            .into_iter::<_, PosTable>(
                &public_key,
                kzg_instance(),
                erasure_coding_instance(),
                &mut table_generator,
            )
            .unwrap()
            .next()
            .unwrap()
            .unwrap();

        let solution = Solution {
            public_key: FarmerPublicKey::from_bytes(keypair.public.to_bytes()),
            reward_address: solution.reward_address,
            sector_index: solution.sector_index,
            history_size: solution.history_size,
            piece_offset: solution.piece_offset,
            record_commitment: solution.record_commitment,
            record_witness: solution.record_witness,
            chunk: solution.chunk,
            chunk_witness: solution.chunk_witness,
            proof_of_space: solution.proof_of_space,
        };

        let solution_distance = verify_solution::<PosTable, _, _>(
            &solution,
            slot,
            &VerifySolutionParams {
                #[cfg(not(feature = "pot"))]
                global_randomness,
                #[cfg(feature = "pot")]
                proof_of_time,
                solution_range: SolutionRange::MAX,
                piece_check_params: None,
            },
            kzg_instance(),
        )
        .unwrap();
        let solution_range = solution_distance * 2;
        let block_weight = calculate_block_weight(solution_range);

        let pre_digest = PreDigest::V0 {
            slot: slot.into(),
            solution,
            #[cfg(feature = "pot")]
            proof_of_time,
            #[cfg(feature = "pot")]
            future_proof_of_time,
        };
        let digests = vec![
            #[cfg(not(feature = "pot"))]
            DigestItem::global_randomness(global_randomness),
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

        return (
            header,
            solution_range,
            block_weight,
            segment_index,
            segment_commitment,
        );
    }

    unreachable!("Will find solution before exhausting u64")
}

fn seal_header(keypair: &Keypair, header: &mut Header) {
    let ctx = schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT);
    let pre_hash = header.hash();
    let signature =
        FarmerSignature::from_bytes(keypair.sign(ctx.bytes(pre_hash.as_bytes())).to_bytes());
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
    #[cfg(not(feature = "pot"))]
    if let Some(next_randomness) = derive_next_global_randomness::<Header>(
        number,
        constants.global_randomness_interval,
        &digests.pre_digest,
    ) {
        digest_logs.push(DigestItem::next_global_randomness(next_randomness));
    }

    if let Some(next_solution_range) =
        derive_next_solution_range::<Header>(DeriveNextSolutionRangeParams {
            number,
            era_duration: constants.era_duration,
            slot_probability: constants.slot_probability,
            current_slot: digests.pre_digest.slot(),
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
    farmer_parameters: &FarmerParameters,
) -> HashOf<Header> {
    let best_header_ext = importer.store.best_header();
    let constants = importer.store.chain_constants();
    let (parent_hash, number, slot) = if let Some(ForkAt { parent_hash, .. }) = maybe_fork_chain {
        let header = importer.store.header(parent_hash).unwrap();
        let digests = extract_pre_digest(&header.header).unwrap();

        (parent_hash, *header.header.number(), digests.slot())
    } else {
        let digests = extract_pre_digest(&best_header_ext.header).unwrap();
        (
            best_header_ext.header.hash(),
            *best_header_ext.header.number(),
            digests.slot(),
        )
    };

    let until_number = number + headers_to_add;
    let mut parent_hash = parent_hash;
    let mut number = number + 1;
    let mut slot = next_slot(constants.slot_probability, slot);
    let mut best_header_hash = best_header_ext.header.hash();
    while number <= until_number {
        let (global_randomness, override_next_solution) = if number == 1 {
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

        let (mut header, solution_range, block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash,
                number,
                slot: slot.into(),
                keypair,
                global_randomness,
                farmer_parameters,
            });
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
            .store_segment_commitment(segment_index, segment_commitment);
        if let Some(ForkAt {
            is_best: maybe_best,
            ..
        }) = maybe_fork_chain
        {
            if let Some(is_best) = maybe_best {
                if is_best {
                    importer
                        .store
                        .override_cumulative_weight(best_header_hash, block_weight - 1)
                } else {
                    importer
                        .store
                        .override_cumulative_weight(best_header_hash, block_weight + 1)
                }
            } else {
                importer
                    .store
                    .override_cumulative_weight(best_header_hash, block_weight)
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
        let farmer_parameters = FarmerParameters::new();

        let constants = default_test_constants();
        let (mut store, _genesis_hash) = initialize_store(constants, true, None);
        let global_randomness = default_randomness();
        let (header, _solution_range, _block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: Default::default(),
                number: 1,
                slot: 1,
                keypair: &keypair,
                global_randomness,
                farmer_parameters: &farmer_parameters,
            });
        store.store_segment_commitment(segment_index, segment_commitment);
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
        let farmer = FarmerParameters::new();

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
        let farmer = FarmerParameters::new();

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
        let farmer = FarmerParameters::new();

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

// TODO: This test doesn't actually reorg, but probably should
#[test]
fn test_chain_reorg_to_heavier_chain() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer = FarmerParameters::new();

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
        let farmer_parameters = FarmerParameters::new();

        let mut constants = default_test_constants();
        constants.k_depth = 4;
        let (store, genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_5 = add_headers_to_chain(&mut importer, &keypair, 5, None, &farmer_parameters);
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
        let (mut header, solution_range, block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: header_at_2.header.hash(),
                number: 3,
                slot: next_slot(constants.slot_probability, digests_at_2.pre_digest.slot()).into(),
                keypair: &keypair,
                #[cfg(not(feature = "pot"))]
                global_randomness: digests_at_2.global_randomness,
                // TODO: Correct value
                #[cfg(feature = "pot")]
                proof_of_time: PotOutput::default(),
                // TODO: Correct value
                #[cfg(feature = "pot")]
                future_proof_of_time: PotOutput::default(),
                farmer_parameters: &farmer_parameters,
            });
        seal_header(&keypair, &mut header);
        importer
            .store
            .override_solution_range(header_at_2.header.hash(), solution_range);
        importer
            .store
            .store_segment_commitment(segment_index, segment_commitment);
        importer.store.override_cumulative_weight(
            importer.store.best_header().header.hash(),
            block_weight - 1,
        );
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
        let farmer_parameters = FarmerParameters::new();

        let mut constants = default_test_constants();
        constants.global_randomness_interval = 5;
        let (store, genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer_parameters);
        assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

        // try to import header with out next global randomness
        let constants = importer.store.chain_constants();
        let header_at_4 = importer.store.header(hash_of_4).unwrap();
        let digests_at_4 =
            extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
                &header_at_4.header,
            )
            .unwrap();
        let (mut header, solution_range, _block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: header_at_4.header.hash(),
                number: 5,
                slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot()).into(),
                keypair: &keypair,
                global_randomness: digests_at_4.global_randomness,
                farmer_parameters: &farmer_parameters,
            });
        seal_header(&keypair, &mut header);
        importer
            .store
            .override_solution_range(header_at_4.header.hash(), solution_range);
        importer
            .store
            .store_segment_commitment(segment_index, segment_commitment);
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
        let randomness = derive_randomness(pre_digest.solution(), pre_digest.slot().into());
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
        let farmer_parameters = FarmerParameters::new();

        let mut constants = default_test_constants();
        constants.era_duration = 5;
        let (store, genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer_parameters);
        assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

        // try to import header with out next global randomness
        let constants = importer.store.chain_constants();
        let header_at_4 = importer.store.header(hash_of_4).unwrap();
        let digests_at_4 =
            extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
                &header_at_4.header,
            )
            .unwrap();
        let (mut header, solution_range, _block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: header_at_4.header.hash(),
                number: 5,
                slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot()).into(),
                keypair: &keypair,
                global_randomness: digests_at_4.global_randomness,
                farmer_parameters: &farmer_parameters,
            });
        seal_header(&keypair, &mut header);
        importer
            .store
            .override_solution_range(header_at_4.header.hash(), solution_range);
        importer
            .store
            .store_segment_commitment(segment_index, segment_commitment);
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
            SlotNumber::from(header_at_4.era_start_slot),
            SlotNumber::from(pre_digest.slot()),
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
        let farmer_parameters = FarmerParameters::new();

        let mut constants = default_test_constants();
        constants.era_duration = 5;
        let (store, genesis_hash) = initialize_store(constants, false, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer_parameters);
        assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

        // try to import header with out next global randomness
        let constants = importer.store.chain_constants();
        let header_at_4 = importer.store.header(hash_of_4).unwrap();
        let digests_at_4 =
            extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
                &header_at_4.header,
            )
            .unwrap();
        let (mut header, solution_range, _block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: header_at_4.header.hash(),
                number: 5,
                slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot()).into(),
                keypair: &keypair,
                global_randomness: digests_at_4.global_randomness,
                farmer_parameters: &farmer_parameters,
            });
        importer
            .store
            .override_solution_range(header_at_4.header.hash(), solution_range);
        importer
            .store
            .store_segment_commitment(segment_index, segment_commitment);
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
        let farmer_parameters = FarmerParameters::new();

        let mut constants = default_test_constants();
        constants.era_duration = 5;
        let (store, genesis_hash) = initialize_store(constants, false, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer_parameters);
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
        let (mut header, solution_range, _block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: header_at_4.header.hash(),
                number: 5,
                slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot()).into(),
                keypair: &keypair,
                global_randomness: digests_at_4.global_randomness,
                farmer_parameters: &farmer_parameters,
            });
        importer
            .store
            .override_solution_range(header_at_4.header.hash(), solution_range);
        importer
            .store
            .store_segment_commitment(segment_index, segment_commitment);
        importer
            .store
            .override_cumulative_weight(header_at_4.header.hash(), 0);
        let pre_digest = extract_pre_digest(&header).unwrap();
        let next_solution_range = subspace_verification::derive_next_solution_range(
            SlotNumber::from(header_at_4.era_start_slot),
            SlotNumber::from(pre_digest.slot()),
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
        let farmer_parameters = FarmerParameters::new();

        let mut constants = default_test_constants();
        constants.era_duration = 5;
        let (store, genesis_hash) = initialize_store(constants, false, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_3 = add_headers_to_chain(&mut importer, &keypair, 3, None, &farmer_parameters);
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
        let (mut header, solution_range, _block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: header_at_3.header.hash(),
                number: 4,
                slot: next_slot(constants.slot_probability, digests_at_3.pre_digest.slot()).into(),
                keypair: &keypair,
                global_randomness: digests_at_3.global_randomness,
                farmer_parameters: &farmer_parameters,
            });
        importer
            .store
            .override_solution_range(header_at_3.header.hash(), solution_range);
        importer
            .store
            .store_segment_commitment(segment_index, segment_commitment);
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
        let farmer_parameters = FarmerParameters::new();

        let mut constants = default_test_constants();
        constants.era_duration = 5;
        let (store, genesis_hash) = initialize_store(constants, false, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer_parameters);
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
        let (mut header, solution_range, _block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: header_at_4.header.hash(),
                number: 5,
                slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot()).into(),
                keypair: &keypair,
                global_randomness: digests_at_4.global_randomness,
                farmer_parameters: &farmer_parameters,
            });
        importer
            .store
            .override_solution_range(header_at_4.header.hash(), solution_range);
        importer
            .store
            .store_segment_commitment(segment_index, segment_commitment);
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
        let farmer_parameters = FarmerParameters::new();

        let mut constants = default_test_constants();
        constants.era_duration = 5;
        let (store, genesis_hash) = initialize_store(constants, true, None);
        let mut importer = HeaderImporter::new(store);
        assert_eq!(
            importer.store.finalized_header().header.hash(),
            genesis_hash
        );

        let hash_of_4 = add_headers_to_chain(&mut importer, &keypair, 4, None, &farmer_parameters);
        assert_eq!(importer.store.best_header().header.hash(), hash_of_4);

        // try to import header with enable solution range adjustment digest
        let constants = importer.store.chain_constants();
        let header_at_4 = importer.store.header(hash_of_4).unwrap();
        let digests_at_4 =
            extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
                &header_at_4.header,
            )
            .unwrap();
        let (mut header, solution_range, _block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: header_at_4.header.hash(),
                number: 5,
                slot: next_slot(constants.slot_probability, digests_at_4.pre_digest.slot()).into(),
                keypair: &keypair,
                global_randomness: digests_at_4.global_randomness,
                farmer_parameters: &farmer_parameters,
            });
        importer
            .store
            .override_solution_range(header_at_4.header.hash(), solution_range);
        importer
            .store
            .store_segment_commitment(segment_index, segment_commitment);
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
        let farmer = FarmerParameters::new();

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
        let farmer_parameters = FarmerParameters::new();

        let mut constants = default_test_constants();
        let keypair_allowed = Keypair::generate();
        let pub_key = FarmerPublicKey::from_bytes(keypair_allowed.public.to_bytes());
        let (store, genesis_hash) = initialize_store(constants.clone(), true, Some(pub_key));
        let mut importer = HeaderImporter::new(store);

        // try to import header authored by different farmer
        let keypair_disallowed = Keypair::generate();
        let global_randomness = default_randomness();
        let (mut header, solution_range, _block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: genesis_hash,
                number: 1,
                slot: 1,
                keypair: &keypair_disallowed,
                global_randomness,
                farmer_parameters: &farmer_parameters,
            });
        seal_header(&keypair_disallowed, &mut header);
        constants.genesis_digest_items.next_solution_range = solution_range;
        importer.store.override_constants(constants);
        importer
            .store
            .store_segment_commitment(segment_index, segment_commitment);
        importer.store.override_cumulative_weight(genesis_hash, 0);
        let res = importer.import_header(header);
        assert_err!(
            res,
            ImportError::IncorrectBlockAuthor(FarmerPublicKey::from_bytes(
                keypair_disallowed.public.to_bytes()
            ))
        );
    });
}

#[test]
fn test_block_author_first_farmer() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let farmer_parameters = FarmerParameters::new();

        let mut constants = default_test_constants();
        let pub_key = FarmerPublicKey::from_bytes(keypair.public.to_bytes());
        let (store, genesis_hash) = initialize_store(constants.clone(), true, None);
        let mut importer = HeaderImporter::new(store);

        // try import header with first farmer
        let global_randomness = default_randomness();
        let (mut header, solution_range, _block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: genesis_hash,
                number: 1,
                slot: 1,
                keypair: &keypair,
                global_randomness,
                farmer_parameters: &farmer_parameters,
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
            .store_segment_commitment(segment_index, segment_commitment);
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
        let farmer_parameters = FarmerParameters::new();

        let mut constants = default_test_constants();
        let pub_key = FarmerPublicKey::from_bytes(keypair.public.to_bytes());
        let (store, genesis_hash) = initialize_store(constants.clone(), true, Some(pub_key));
        let mut importer = HeaderImporter::new(store);

        // try to import header authored by different farmer
        let global_randomness = default_randomness();
        let (mut header, solution_range, _block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: genesis_hash,
                number: 1,
                slot: 1,
                keypair: &keypair,
                global_randomness,
                farmer_parameters: &farmer_parameters,
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
            .store_segment_commitment(segment_index, segment_commitment);
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
        let farmer_parameters = FarmerParameters::new();

        let mut constants = default_test_constants();
        let keypair_allowed = Keypair::generate();
        let pub_key = FarmerPublicKey::from_bytes(keypair_allowed.public.to_bytes());
        let (store, genesis_hash) = initialize_store(constants.clone(), true, Some(pub_key));
        let mut importer = HeaderImporter::new(store);

        // try to import header that contains root plot public key override
        let global_randomness = default_randomness();
        let (mut header, solution_range, _block_weight, segment_index, segment_commitment) =
            valid_header(ValidHeaderParams {
                parent_hash: genesis_hash,
                number: 1,
                slot: 1,
                keypair: &keypair_allowed,
                global_randomness,
                farmer_parameters: &farmer_parameters,
            });
        let keypair_disallowed = Keypair::generate();
        let pub_key = FarmerPublicKey::from_bytes(keypair_disallowed.public.to_bytes());
        header
            .digest
            .logs
            .push(DigestItem::root_plot_public_key_update(Some(pub_key)));
        seal_header(&keypair_allowed, &mut header);
        constants.genesis_digest_items.next_solution_range = solution_range;
        importer.store.override_constants(constants);
        importer
            .store
            .store_segment_commitment(segment_index, segment_commitment);
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

// TODO: Test for expired sector
