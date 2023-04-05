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
    self as pallet_subspace, Config, CurrentSlot, FarmerPublicKey, NormalEraChange,
    NormalGlobalRandomnessInterval,
};
use frame_support::pallet_prelude::Weight;
use frame_support::parameter_types;
use frame_support::traits::{ConstU128, ConstU32, ConstU64, GenesisBuild, OnInitialize};
use rand::Rng;
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{CompatibleDigestItem, PreDigest};
use sp_consensus_subspace::{FarmerSignature, KzgExtension, SignedVote, Vote};
use sp_core::crypto::UncheckedFrom;
use sp_core::H256;
use sp_io::TestExternalities;
use sp_runtime::testing::{Digest, DigestItem, Header, TestXt};
use sp_runtime::traits::{Block as BlockT, Header as _, IdentityLookup};
use sp_runtime::Perbill;
use std::num::NonZeroU64;
use std::sync::Once;
use subspace_archiving::archiver::{Archiver, NewArchivedSegment};
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg, Witness};
use subspace_core_primitives::crypto::{blake2b_256_254_hash_to_scalar, kzg, ScalarLegacy};
use subspace_core_primitives::{
    ArchivedBlockProgress, Blake2b256Hash, LastArchivedBlock, Piece, PieceArray, PieceIndex,
    Randomness, RecordedHistorySegment, SegmentCommitment, SegmentHeader, SegmentIndex, Solution,
    SolutionRange,
};
use subspace_solving::{create_chunk_signature, derive_global_challenge, REWARD_SIGNING_CONTEXT};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub struct Test
    where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system,
        Balances: pallet_balances,
        Subspace: pallet_subspace,
        OffencesSubspace: pallet_offences_subspace,
        Timestamp: pallet_timestamp,
    }
);

parameter_types! {
    pub const DisabledValidatorsThreshold: Perbill = Perbill::from_percent(16);
    pub BlockWeights: frame_system::limits::BlockWeights =
        frame_system::limits::BlockWeights::simple_max(Weight::from_parts(1024, 0));
}

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type Index = u64;
    type BlockNumber = u64;
    type RuntimeCall = RuntimeCall;
    type Hash = H256;
    type Version = ();
    type Hashing = sp_runtime::traits::BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
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
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Test
where
    RuntimeCall: From<C>,
{
    type OverarchingCall = RuntimeCall;
    type Extrinsic = TestXt<RuntimeCall, ()>;
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = Subspace;
    type MinimumPeriod = ConstU64<1>;
    type WeightInfo = ();
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
    type HoldIdentifier = ();
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
    pub const GlobalRandomnessUpdateInterval: u64 = 10;
    pub const EraDuration: u32 = 4;
    // 1GB
    pub const InitialSolutionRange: SolutionRange = INITIAL_SOLUTION_RANGE;
    pub const SlotProbability: (u64, u64) = SLOT_PROBABILITY;
    pub const ConfirmationDepthK: u32 = 10;
    pub const RecordSize: u32 = 3840;
    pub const ExpectedVotesPerBlock: u32 = 9;
    pub const ReplicationFactor: u16 = 1;
    pub const ReportLongevity: u64 = 34;
    pub const ShouldAdjustSolutionRange: bool = false;
}

impl Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type GlobalRandomnessUpdateInterval = GlobalRandomnessUpdateInterval;
    type EraDuration = EraDuration;
    type InitialSolutionRange = InitialSolutionRange;
    type SlotProbability = SlotProbability;
    type ExpectedBlockTime = ConstU64<1>;
    type ConfirmationDepthK = ConfirmationDepthK;
    type ExpectedVotesPerBlock = ExpectedVotesPerBlock;
    type GlobalRandomnessIntervalTrigger = NormalGlobalRandomnessInterval;
    type EraChangeTrigger = NormalEraChange;

    type HandleEquivocation = EquivocationHandler<OffencesSubspace, ReportLongevity>;

    type WeightInfo = ();
    type ShouldAdjustSolutionRange = ShouldAdjustSolutionRange;
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
        let hdr = System::finalize();
        hdr.hash()
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
            total_pieces: NonZeroU64::new(1).unwrap(),
            piece_offset: PieceIndex::default(),
            record_commitment_hash: Default::default(),
            piece_witness: Default::default(),
            chunk_offset: 0,
            chunk,
            chunk_signature: create_chunk_signature(keypair, &chunk.to_bytes()),
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
    let log = DigestItem::subspace_pre_digest(&PreDigest { slot, solution });
    Digest { logs: vec![log] }
}

pub fn new_test_ext() -> TestExternalities {
    static INITIALIZE_LOGGER: Once = Once::new();
    INITIALIZE_LOGGER.call_once(|| {
        let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("error"));
    });

    let mut storage = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();

    GenesisBuild::<Test>::assimilate_storage(
        &pallet_subspace::GenesisConfig::default(),
        &mut storage,
    )
    .unwrap();

    let mut ext = TestExternalities::from(storage);

    ext.register_extension(KzgExtension::new(Kzg::new(embedded_kzg_settings())));

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
        let mut chunk_bytes = [0; ScalarLegacy::SAFE_BYTES];
        chunk_bytes.as_mut().iter_mut().for_each(|byte| {
            *byte = (current_block % 8) as u8;
        });

        ScalarLegacy::from(&chunk_bytes)
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
                total_pieces: NonZeroU64::new(1).unwrap(),
                piece_offset,
                record_commitment_hash: Default::default(),
                piece_witness: Default::default(),
                chunk_offset: 0,
                chunk,
                chunk_signature: create_chunk_signature(keypair, &chunk.to_bytes()),
            },
        );
        System::reset_events();
        System::initialize(&current_block, &parent_hash, &pre_digest);
        System::set_block_number(current_block);
        Timestamp::set_timestamp(*current_slot * Subspace::slot_duration());
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
    let mut h1 = make_header(PieceIndex::ZERO, 0);
    let mut h2 = make_header(PieceIndex::ONE, 1);

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
        prev_segment_header_hash: Blake2b256Hash::default(),
        last_archived_block: LastArchivedBlock {
            number: 0,
            archived_progress: ArchivedBlockProgress::Complete,
        },
    }
}

pub fn create_archived_segment() -> NewArchivedSegment {
    let kzg = Kzg::new(kzg::embedded_kzg_settings());
    let mut archiver = Archiver::new(kzg).unwrap();

    let mut block = vec![0u8; RecordedHistorySegment::SIZE];
    rand::thread_rng().fill(block.as_mut_slice());
    archiver
        .add_block(block, Default::default())
        .into_iter()
        .next()
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
pub fn create_signed_vote(
    keypair: &Keypair,
    height: u64,
    parent_hash: <Block as BlockT>::Hash,
    slot: Slot,
    global_randomnesses: &Randomness,
    piece: &PieceArray,
    reward_address: <Test as frame_system::Config>::AccountId,
) -> SignedVote<u64, <Block as BlockT>::Hash, <Test as frame_system::Config>::AccountId> {
    let reward_signing_context = schnorrkel::signing_context(REWARD_SIGNING_CONTEXT);

    // TODO: global challenge will be necessary in the future when we actually verify the chunk
    let _global_challenge = derive_global_challenge(global_randomnesses, slot.into());

    let chunk = Default::default();

    let vote = Vote::<u64, <Block as BlockT>::Hash, _>::V0 {
        height,
        parent_hash,
        slot,
        solution: Solution {
            public_key: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
            reward_address,
            sector_index: 0,
            total_pieces: NonZeroU64::new(1).unwrap(),
            piece_offset: PieceIndex::default(),
            record_commitment_hash: blake2b_256_254_hash_to_scalar(piece.commitment().as_ref()),
            piece_witness: Witness::try_from_bytes(piece.witness()).unwrap(),
            chunk_offset: 0,
            chunk,
            chunk_signature: create_chunk_signature(keypair, &chunk.to_bytes()),
        },
    };

    let signature = FarmerSignature::unchecked_from(
        keypair
            .sign(reward_signing_context.bytes(vote.hash().as_ref()))
            .to_bytes(),
    );

    SignedVote { vote, signature }
}
