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

use crate::{
    self as pallet_subspace, Config, CurrentSlot, FarmerPublicKey, NormalEonChange,
    NormalEpochChange, NormalEraChange,
};
use codec::Encode;
use frame_support::{parameter_types, traits::OnInitialize};
use frame_system::InitKind;
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{PreDigest, Solution};
use sp_core::sr25519::Pair;
use sp_core::{Pair as PairTrait, Public, H256};
use sp_io;
use sp_runtime::{
    testing::{Digest, DigestItem, Header, TestXt},
    traits::{Header as _, IdentityLookup},
    Perbill,
};
use subspace_core_primitives::{LastArchivedBlock, Piece, RootBlock, Sha256Hash, Tag};
use subspace_solving::{SubspaceCodec, SOLUTION_SIGNING_CONTEXT};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
        Subspace: pallet_subspace::{Pallet, Call, Storage, Config, Event, ValidateUnsigned},
        OffencesSubspace: pallet_offences_subspace::{Pallet, Storage, Event},
        Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent},
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const DisabledValidatorsThreshold: Perbill = Perbill::from_percent(16);
    pub BlockWeights: frame_system::limits::BlockWeights =
        frame_system::limits::BlockWeights::simple_max(1024);
}

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type Origin = Origin;
    type Index = u64;
    type BlockNumber = u64;
    type Call = Call;
    type Hash = H256;
    type Version = ();
    type Hashing = sp_runtime::traits::BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = Event;
    type BlockHashCount = BlockHashCount;
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<u128>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
    type OnSetCode = ();
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Test
where
    Call: From<C>,
{
    type OverarchingCall = Call;
    type Extrinsic = TestXt<Call, ()>;
}
parameter_types! {
    pub const UncleGenerations: u64 = 0;
}

parameter_types! {
    pub const MinimumPeriod: u64 = 1;
}

impl pallet_timestamp::Config for Test {
    type Moment = u64;
    type OnTimestampSet = Subspace;
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

parameter_types! {
    pub const ExistentialDeposit: u128 = 1;
}

impl pallet_balances::Config for Test {
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type Balance = u128;
    type DustRemoval = ();
    type Event = Event;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
}

impl pallet_offences_subspace::Config for Test {
    type Event = Event;
    type OnOffenceHandler = Subspace;
}

/// 1 in 6 slots (on average, not counting collisions) will have a block.
pub const SLOT_PROBABILITY: (u64, u64) = (3, 10);

pub const INITIAL_SOLUTION_RANGE: u64 =
    u64::MAX / (1024 * 1024 * 1024 / 4096) * SLOT_PROBABILITY.0 / SLOT_PROBABILITY.1;

parameter_types! {
    pub const EpochDuration: u64 = 3;
    pub const EraDuration: u32 = 4;
    pub const EonDuration: u32 = 5;
    // 1GB
    pub const InitialSolutionRange: u64 = INITIAL_SOLUTION_RANGE;
    pub const SlotProbability: (u64, u64) = SLOT_PROBABILITY;
    pub const ExpectedBlockTime: u64 = 1;
    pub const ConfirmationDepthK: u32 = 10;
    pub const RecordSize: u32 = 3840;
    pub const RecordedHistorySegmentSize: u32 = 3840 * 256 / 2;
    pub const PreGenesisObjectSize: u32 = 3840 * 256 / 2;
    pub const PreGenesisObjectCount: u32 = 5;
    pub const PreGenesisObjectSeed: &'static [u8] = b"subspace";
    pub const ReportLongevity: u64 = 34;
}

impl Config for Test {
    type Event = Event;
    type EpochDuration = EpochDuration;
    type EraDuration = EraDuration;
    type EonDuration = EonDuration;
    type InitialSolutionRange = InitialSolutionRange;
    type SlotProbability = SlotProbability;
    type ExpectedBlockTime = ExpectedBlockTime;
    type ConfirmationDepthK = ConfirmationDepthK;
    type RecordSize = RecordSize;
    type RecordedHistorySegmentSize = RecordedHistorySegmentSize;
    type PreGenesisObjectSize = PreGenesisObjectSize;
    type PreGenesisObjectCount = PreGenesisObjectCount;
    type PreGenesisObjectSeed = PreGenesisObjectSeed;
    type EpochChangeTrigger = NormalEpochChange;
    type EraChangeTrigger = NormalEraChange;
    type EonChangeTrigger = NormalEonChange;

    type HandleEquivocation =
        crate::equivocation::EquivocationHandler<OffencesSubspace, ReportLongevity>;

    type WeightInfo = ();
}

pub fn go_to_block(keypair: &Keypair, block: u64, slot: u64) {
    use frame_support::traits::OnFinalize;

    Subspace::on_finalize(System::block_number());

    let parent_hash = if System::block_number() > 1 {
        let hdr = System::finalize();
        hdr.hash()
    } else {
        System::parent_hash()
    };

    let subspace_solving = SubspaceCodec::new(&keypair.public);
    let ctx = schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT);
    let piece_index = 0;
    let mut piece: Piece = [0u8; 4096];
    subspace_solving.encode(piece_index, &mut piece).unwrap();
    let tag: Tag = subspace_solving::create_tag(&piece, Subspace::salt().to_le_bytes());

    let pre_digest = make_pre_digest(
        slot.into(),
        Solution {
            public_key: FarmerPublicKey::from_slice(&keypair.public.to_bytes()),
            piece_index: 0,
            encoding: piece.to_vec(),
            signature: keypair.sign(ctx.bytes(&tag)).to_bytes().to_vec(),
            tag,
        },
    );

    System::initialize(&block, &parent_hash, &pre_digest, InitKind::Full);

    Subspace::on_initialize(block);
}

/// Slots will grow accordingly to blocks
pub fn progress_to_block(keypair: &Keypair, n: u64) {
    let mut slot = u64::from(Subspace::current_slot()) + 1;
    for i in System::block_number() + 1..=n {
        go_to_block(keypair, i, slot);
        slot += 1;
    }
}

pub fn make_pre_digest(slot: Slot, solution: Solution) -> Digest {
    let digest_data = PreDigest { slot, solution };
    let log = DigestItem::PreRuntime(
        sp_consensus_subspace::SUBSPACE_ENGINE_ID,
        digest_data.encode(),
    );
    Digest { logs: vec![log] }
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap()
        .into()
}

/// Creates an equivocation at the current block, by generating two headers.
pub fn generate_equivocation_proof(
    keypair: &Keypair,
    slot: Slot,
) -> sp_consensus_subspace::EquivocationProof<Header> {
    use sp_consensus_subspace::digests::CompatibleDigestItem;

    let current_block = System::block_number();
    let current_slot = CurrentSlot::<Test>::get();

    let ctx = schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT);
    let encoding: Piece = [0u8; 4096];
    let tag: Tag = [(current_block % 8) as u8; 8];

    let public_key = FarmerPublicKey::from_slice(&keypair.public.to_bytes());
    let signature = keypair.sign(ctx.bytes(&tag)).to_bytes().to_vec();

    let make_header = |piece_index| {
        let parent_hash = System::parent_hash();
        let pre_digest = make_pre_digest(
            slot,
            Solution {
                public_key: public_key.clone(),
                piece_index,
                encoding: encoding.to_vec(),
                signature: signature.clone(),
                tag,
            },
        );
        System::initialize(&current_block, &parent_hash, &pre_digest, InitKind::Full);
        System::set_block_number(current_block);
        Timestamp::set_timestamp(current_block);
        System::finalize()
    };

    // sign the header prehash and sign it, adding it to the block as the seal
    // digest item
    let seal_header = |header: &mut Header| {
        let prehash = header.hash();
        let signature = Pair::from(keypair.secret.clone()).sign(prehash.as_ref());
        let seal = <DigestItem as CompatibleDigestItem>::subspace_seal(signature.into());
        header.digest_mut().push(seal);
    };

    // generate two headers at the current block
    let mut h1 = make_header(0);
    let mut h2 = make_header(1);

    seal_header(&mut h1);
    seal_header(&mut h2);

    // restore previous runtime state
    go_to_block(keypair, current_block, *current_slot);

    sp_consensus_subspace::EquivocationProof {
        slot,
        offender: public_key,
        first_header: h1,
        second_header: h2,
    }
}

pub fn create_root_block(segment_index: u64) -> RootBlock {
    RootBlock::V0 {
        segment_index,
        records_root: Sha256Hash::default(),
        prev_root_block_hash: Sha256Hash::default(),
        last_archived_block: LastArchivedBlock {
            number: 0,
            partial_archived: None,
        },
    }
}
