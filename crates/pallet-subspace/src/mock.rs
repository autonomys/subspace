// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Test utilities

use crate::equivocation::EquivocationHandler;
use crate::{
    self as pallet_subspace, AllowAuthoringBy, Config, CurrentSlot, FarmerPublicKey,
    NormalEraChange,
};
use frame_support::parameter_types;
use frame_support::traits::{ConstU128, ConstU16, ConstU32, ConstU64, OnInitialize};
use futures::executor::block_on;
use rand::Rng;
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{CompatibleDigestItem, PreDigest, PreDigestPotInfo};
use sp_consensus_subspace::{
    FarmerSignature, KzgExtension, PosExtension, PotExtension, SignedVote, Vote,
};
use sp_core::crypto::UncheckedFrom;
use sp_core::storage::StateVersion;
use sp_core::H256;
use sp_io::TestExternalities;
use sp_runtime::testing::{Digest, DigestItem, Header, TestXt};
use sp_runtime::traits::{Block as BlockT, Header as _, IdentityLookup};
use sp_runtime::{BuildStorage, Perbill};
use sp_weights::Weight;
use std::marker::PhantomData;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::simd::Simd;
use std::sync::{Once, OnceLock};
use std::{iter, mem};
use subspace_archiving::archiver::{Archiver, NewArchivedSegment};
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::{
    ArchivedBlockProgress, ArchivedHistorySegment, Blake3Hash, BlockNumber, HistorySize,
    LastArchivedBlock, Piece, PieceOffset, PosSeed, PotOutput, PublicKey, Record,
    RecordedHistorySegment, SectorId, SegmentCommitment, SegmentHeader, SegmentIndex, SlotNumber,
    Solution, SolutionRange, REWARD_SIGNING_CONTEXT,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::auditing::audit_sector;
use subspace_farmer_components::plotting::{
    plot_sector, PieceGetterRetryPolicy, PlotSectorOptions,
};
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_proof_of_space::shim::ShimTable;
use subspace_proof_of_space::{Table, TableGenerator};
use subspace_verification::is_within_solution_range;

type PosTable = ShimTable;

type Block = frame_system::mocking::MockBlock<Test>;

const MAX_PIECES_IN_SECTOR: u16 = 1;

fn kzg_instance() -> &'static Kzg {
    static KZG: OnceLock<Kzg> = OnceLock::new();

    KZG.get_or_init(|| Kzg::new(embedded_kzg_settings()))
}

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

frame_support::construct_runtime!(
    pub struct Test {
        System: frame_system,
        Balances: pallet_balances,
        Subspace: pallet_subspace,
        OffencesSubspace: pallet_offences_subspace,
    }
);

parameter_types! {
    pub const DisabledValidatorsThreshold: Perbill = Perbill::from_percent(16);
    pub BlockWeights: frame_system::limits::BlockWeights =
        frame_system::limits::BlockWeights::simple_max(Weight::from_parts(1024, 0));
    pub const ExtrinsicsRootStateVersion: StateVersion = StateVersion::V0;
}

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type Nonce = u64;
    type RuntimeCall = RuntimeCall;
    type Hash = H256;
    type Version = ();
    type Hashing = sp_runtime::traits::BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<u128>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
    type ExtrinsicsRootStateVersion = ExtrinsicsRootStateVersion;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Test
where
    RuntimeCall: From<C>,
{
    type OverarchingCall = RuntimeCall;
    type Extrinsic = TestXt<RuntimeCall, ()>;
}

impl pallet_balances::Config for Test {
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type Balance = u128;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ConstU128<1>;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type RuntimeHoldReason = ();
    type MaxHolds = ();
}

impl pallet_offences_subspace::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type OnOffenceHandler = Subspace;
}

/// 1 in 6 slots (on average, not counting collisions) will have a block.
pub const SLOT_PROBABILITY: (u64, u64) = (3, 10);

pub const INITIAL_SOLUTION_RANGE: SolutionRange =
    u64::MAX / (1024 * 1024 * 1024 / Piece::SIZE as u64) * SLOT_PROBABILITY.0 / SLOT_PROBABILITY.1;

parameter_types! {
    pub const BlockAuthoringDelay: SlotNumber = 2;
    pub const PotEntropyInjectionInterval: BlockNumber = 5;
    pub const PotEntropyInjectionLookbackDepth: u8 = 2;
    pub const PotEntropyInjectionDelay: SlotNumber = 4;
    pub const EraDuration: u32 = 4;
    // 1GB
    pub const InitialSolutionRange: SolutionRange = INITIAL_SOLUTION_RANGE;
    pub const SlotProbability: (u64, u64) = SLOT_PROBABILITY;
    pub const ConfirmationDepthK: u32 = 10;
    pub const RecentSegments: HistorySize = HistorySize::new(NonZeroU64::new(5).unwrap());
    pub const RecentHistoryFraction: (HistorySize, HistorySize) = (
        HistorySize::new(NonZeroU64::new(1).unwrap()),
        HistorySize::new(NonZeroU64::new(10).unwrap()),
    );
    pub const MinSectorLifetime: HistorySize = HistorySize::new(NonZeroU64::new(4).unwrap());
    pub const RecordSize: u32 = 3840;
    pub const ExpectedVotesPerBlock: u32 = 9;
    pub const ReplicationFactor: u16 = 1;
    pub const ReportLongevity: u64 = 34;
    pub const ShouldAdjustSolutionRange: bool = false;
}

impl Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type BlockAuthoringDelay = BlockAuthoringDelay;
    type PotEntropyInjectionInterval = PotEntropyInjectionInterval;
    type PotEntropyInjectionLookbackDepth = PotEntropyInjectionLookbackDepth;
    type PotEntropyInjectionDelay = PotEntropyInjectionDelay;
    type EraDuration = EraDuration;
    type InitialSolutionRange = InitialSolutionRange;
    type SlotProbability = SlotProbability;
    type ConfirmationDepthK = ConfirmationDepthK;
    type RecentSegments = RecentSegments;
    type RecentHistoryFraction = RecentHistoryFraction;
    type MinSectorLifetime = MinSectorLifetime;
    type ExpectedVotesPerBlock = ExpectedVotesPerBlock;
    type MaxPiecesInSector = ConstU16<{ MAX_PIECES_IN_SECTOR }>;
    type ShouldAdjustSolutionRange = ShouldAdjustSolutionRange;
    type EraChangeTrigger = NormalEraChange;

    type HandleEquivocation = EquivocationHandler<OffencesSubspace, ReportLongevity>;

    type WeightInfo = ();
}

pub fn go_to_block(
    keypair: &Keypair,
    block: u64,
    slot: u64,
    reward_address: <Test as frame_system::Config>::AccountId,
) {
    use frame_support::traits::OnFinalize;

    Subspace::on_finalize(System::block_number());

    let parent_hash = if System::block_number() > 1 {
        let header = System::finalize();
        header.hash()
    } else {
        System::parent_hash()
    };

    let chunk = Default::default();

    let pre_digest = make_pre_digest(
        slot.into(),
        Solution {
            public_key: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
            reward_address,
            sector_index: 0,
            history_size: HistorySize::from(SegmentIndex::ZERO),
            piece_offset: PieceOffset::default(),
            record_commitment: Default::default(),
            record_witness: Default::default(),
            chunk,
            chunk_witness: Default::default(),
            audit_chunk_offset: 0,
            proof_of_space: Default::default(),
        },
    );

    System::reset_events();
    System::initialize(&block, &parent_hash, &pre_digest);

    Subspace::on_initialize(block);
}

/// Slots will grow accordingly to blocks
pub fn progress_to_block(
    keypair: &Keypair,
    n: u64,
    reward_address: <Test as frame_system::Config>::AccountId,
) {
    let mut slot = u64::from(Subspace::current_slot()) + 1;
    for i in System::block_number() + 1..=n {
        go_to_block(keypair, i, slot, reward_address);
        slot += 1;
    }
}

pub fn make_pre_digest(
    slot: Slot,
    solution: Solution<FarmerPublicKey, <Test as frame_system::Config>::AccountId>,
) -> Digest {
    let log = DigestItem::subspace_pre_digest(&PreDigest::V0 {
        slot,
        solution,
        pot_info: PreDigestPotInfo::V0 {
            proof_of_time: Default::default(),
            future_proof_of_time: Default::default(),
        },
    });
    Digest { logs: vec![log] }
}

pub fn allow_all_pot_extension() -> PotExtension {
    PotExtension::new(Box::new(
        |_parent_hash, _slot, _proof_of_time, _quick_verification| true,
    ))
}

pub fn new_test_ext(pot_extension: PotExtension) -> TestExternalities {
    static INITIALIZE_LOGGER: Once = Once::new();
    INITIALIZE_LOGGER.call_once(|| {
        let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("error"));
    });

    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    pallet_subspace::GenesisConfig::<Test> {
        enable_rewards: true,
        enable_storage_access: true,
        allow_authoring_by: AllowAuthoringBy::Anyone,
        pot_slot_iterations: NonZeroU32::new(100_000).unwrap(),
        phantom: PhantomData,
    }
    .assimilate_storage(&mut storage)
    .unwrap();

    let mut ext = TestExternalities::from(storage);

    ext.register_extension(KzgExtension::new(kzg_instance().clone()));
    ext.register_extension(PosExtension::new::<PosTable>());
    ext.register_extension(pot_extension);

    ext
}

/// Creates an equivocation at the current block, by generating two headers.
pub fn generate_equivocation_proof(
    keypair: &Keypair,
    slot: Slot,
) -> sp_consensus_subspace::EquivocationProof<Header> {
    let current_block = System::block_number();
    let current_slot = CurrentSlot::<Test>::get();

    let chunk = {
        let mut chunk_bytes = [0; Scalar::SAFE_BYTES];
        chunk_bytes.as_mut().iter_mut().for_each(|byte| {
            *byte = (current_block % 8) as u8;
        });

        Scalar::from(&chunk_bytes)
    };

    let public_key = FarmerPublicKey::unchecked_from(keypair.public.to_bytes());

    let make_header = |piece_offset, reward_address: <Test as frame_system::Config>::AccountId| {
        let parent_hash = System::parent_hash();
        let pre_digest = make_pre_digest(
            slot,
            Solution {
                public_key: public_key.clone(),
                reward_address,
                sector_index: 0,
                history_size: HistorySize::from(SegmentIndex::ZERO),
                piece_offset,
                record_commitment: Default::default(),
                record_witness: Default::default(),
                chunk,
                chunk_witness: Default::default(),
                audit_chunk_offset: 0,
                proof_of_space: Default::default(),
            },
        );
        System::reset_events();
        System::initialize(&current_block, &parent_hash, &pre_digest);
        System::set_block_number(current_block);
        System::finalize()
    };

    // sign the header prehash and sign it, adding it to the block as the seal
    // digest item
    let seal_header = |header: &mut Header| {
        let prehash = header.hash();
        let signature = FarmerSignature::unchecked_from(
            keypair
                .sign(
                    schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT)
                        .bytes(prehash.as_bytes()),
                )
                .to_bytes(),
        );
        let seal = DigestItem::subspace_seal(signature);
        header.digest_mut().push(seal);
    };

    // generate two headers at the current block
    let mut h1 = make_header(PieceOffset::ZERO, 0);
    let mut h2 = make_header(PieceOffset::ONE, 1);

    seal_header(&mut h1);
    seal_header(&mut h2);

    // restore previous runtime state
    go_to_block(keypair, current_block, *current_slot, 2);

    sp_consensus_subspace::EquivocationProof {
        slot,
        offender: public_key,
        first_header: h1,
        second_header: h2,
    }
}

pub fn create_segment_header(segment_index: SegmentIndex) -> SegmentHeader {
    SegmentHeader::V0 {
        segment_index,
        segment_commitment: SegmentCommitment::default(),
        prev_segment_header_hash: Blake3Hash::default(),
        last_archived_block: LastArchivedBlock {
            number: 0,
            archived_progress: ArchivedBlockProgress::Complete,
        },
    }
}

pub fn create_archived_segment() -> &'static NewArchivedSegment {
    static ARCHIVED_SEGMENT: OnceLock<NewArchivedSegment> = OnceLock::new();

    ARCHIVED_SEGMENT.get_or_init(|| {
        let mut archiver = Archiver::new(kzg_instance().clone()).unwrap();

        let mut block = vec![0u8; RecordedHistorySegment::SIZE];
        rand::thread_rng().fill(block.as_mut_slice());
        archiver
            .add_block(block, Default::default(), true)
            .into_iter()
            .next()
            .unwrap()
    })
}

#[allow(clippy::too_many_arguments)]
pub fn create_signed_vote(
    keypair: &Keypair,
    height: u64,
    parent_hash: <Block as BlockT>::Hash,
    slot: Slot,
    proof_of_time: PotOutput,
    future_proof_of_time: PotOutput,
    archived_history_segment: &ArchivedHistorySegment,
    reward_address: <Test as frame_system::Config>::AccountId,
    solution_range: SolutionRange,
    vote_solution_range: SolutionRange,
) -> SignedVote<u64, <Block as BlockT>::Hash, <Test as frame_system::Config>::AccountId> {
    let kzg = kzg_instance();
    let erasure_coding = erasure_coding_instance();
    let reward_signing_context = schnorrkel::signing_context(REWARD_SIGNING_CONTEXT);
    let public_key = PublicKey::from(keypair.public.to_bytes());

    let farmer_protocol_info = FarmerProtocolInfo {
        history_size: HistorySize::from(SegmentIndex::ZERO),
        max_pieces_in_sector: MAX_PIECES_IN_SECTOR,
        recent_segments: HistorySize::from(NonZeroU64::new(5).unwrap()),
        recent_history_fraction: (
            HistorySize::from(NonZeroU64::new(1).unwrap()),
            HistorySize::from(NonZeroU64::new(10).unwrap()),
        ),
        min_sector_lifetime: HistorySize::from(NonZeroU64::new(4).unwrap()),
    };
    let pieces_in_sector = farmer_protocol_info.max_pieces_in_sector;

    let mut table_generator = PosTable::generator();

    for sector_index in iter::from_fn(|| Some(rand::random())) {
        let mut plotted_sector_bytes = Vec::new();
        let mut plotted_sector_metadata_bytes = Vec::new();

        let plotted_sector = block_on(plot_sector::<PosTable, _>(PlotSectorOptions {
            public_key: &public_key,
            sector_index,
            piece_getter: archived_history_segment,
            piece_getter_retry_policy: PieceGetterRetryPolicy::default(),
            farmer_protocol_info: &farmer_protocol_info,
            kzg,
            erasure_coding,
            pieces_in_sector,
            sector_output: &mut plotted_sector_bytes,
            sector_metadata_output: &mut plotted_sector_metadata_bytes,
            downloading_semaphore: None,
            encoding_semaphore: None,
            table_generator: &mut table_generator,
        }))
        .unwrap();

        let global_challenge = proof_of_time
            .derive_global_randomness()
            .derive_global_challenge(slot.into());

        let maybe_audit_result = audit_sector(
            &public_key,
            sector_index,
            &global_challenge,
            vote_solution_range,
            &plotted_sector_bytes,
            &plotted_sector.sector_metadata,
        );

        let Some(audit_result) = maybe_audit_result else {
            // Sector didn't have any solutions
            continue;
        };

        let solution = audit_result
            .solution_candidates
            .into_solutions(&reward_address, kzg, erasure_coding, |seed: &PosSeed| {
                table_generator.generate_parallel(seed)
            })
            .unwrap()
            .next()
            .unwrap()
            .unwrap();

        let sector_id = SectorId::new(
            PublicKey::from(keypair.public.to_bytes()).hash(),
            solution.sector_index,
        );
        let sector_slot_challenge = sector_id.derive_sector_slot_challenge(&global_challenge);
        let masked_chunk = (Simd::from(solution.chunk.to_bytes())
            ^ Simd::from(solution.proof_of_space.hash()))
        .to_array();
        // Extract audit chunk from masked chunk
        let audit_chunk = SolutionRange::from_le_bytes(
            *masked_chunk
                .array_chunks::<{ mem::size_of::<SolutionRange>() }>()
                .nth(usize::from(solution.audit_chunk_offset))
                .unwrap(),
        );

        // Check that solution quality is not too high
        if is_within_solution_range(
            &global_challenge,
            audit_chunk,
            &sector_slot_challenge,
            solution_range,
        )
        .is_some()
        {
            continue;
        }

        let vote = Vote::<u64, <Block as BlockT>::Hash, _>::V0 {
            height,
            parent_hash,
            slot,
            solution: Solution {
                public_key: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
                reward_address: solution.reward_address,
                sector_index: solution.sector_index,
                history_size: solution.history_size,
                piece_offset: solution.piece_offset,
                record_commitment: solution.record_commitment,
                record_witness: solution.record_witness,
                chunk: solution.chunk,
                chunk_witness: solution.chunk_witness,
                audit_chunk_offset: solution.audit_chunk_offset,
                proof_of_space: solution.proof_of_space,
            },
            proof_of_time,
            future_proof_of_time,
        };

        let signature = FarmerSignature::unchecked_from(
            keypair
                .sign(reward_signing_context.bytes(vote.hash().as_ref()))
                .to_bytes(),
        );

        return SignedVote { vote, signature };
    }

    unreachable!("Will find solution before exhausting u64")
}
