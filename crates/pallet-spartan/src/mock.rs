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
    self as pallet_spartan, Config, CurrentSlot, FarmerId, NormalEonChange, NormalEpochChange,
    NormalEraChange,
};
use codec::Encode;
use frame_support::{parameter_types, traits::OnInitialize};
use frame_system::InitKind;
use ring::{digest, hmac};
use schnorrkel::{Keypair, PublicKey};
use sp_consensus_poc::digests::{PreDigest, Solution};
use sp_consensus_poc::Slot;
use sp_consensus_spartan::spartan::{Tag, SIGNING_CONTEXT};
use sp_core::sr25519::Pair;
use sp_core::{Pair as PairTrait, Public, H256};
use sp_io;
use sp_runtime::{
    testing::{Digest, DigestItem, Header, TestXt},
    traits::{Header as _, IdentityLookup},
    Perbill,
};
use std::convert::TryInto;
use subspace_core_primitives::{LastArchivedBlock, Piece, RootBlock, Sha256Hash, PRIME_SIZE};

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
        Spartan: pallet_spartan::{Pallet, Call, Storage, Config, Event, ValidateUnsigned},
        OffencesPoC: pallet_offences_poc::{Pallet, Storage, Event},
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
    type OnTimestampSet = Spartan;
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

impl pallet_offences_poc::Config for Test {
    type Event = Event;
    type OnOffenceHandler = Spartan;
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
    type EpochChangeTrigger = NormalEpochChange;
    type EraChangeTrigger = NormalEraChange;
    type EonChangeTrigger = NormalEonChange;

    type HandleEquivocation = super::EquivocationHandler<OffencesPoC, ReportLongevity>;

    type WeightInfo = ();
}

pub fn go_to_block(keypair: &Keypair, block: u64, slot: u64) {
    use frame_support::traits::OnFinalize;

    Spartan::on_finalize(System::block_number());

    let parent_hash = if System::block_number() > 1 {
        let hdr = System::finalize();
        hdr.hash()
    } else {
        System::parent_hash()
    };

    let spartan = subspace_codec::Spartan::new();
    let public_key_hash = hash_public_key(&keypair.public);
    let ctx = schnorrkel::context::signing_context(SIGNING_CONTEXT);
    let nonce = 0;
    let encoding: Piece = spartan.encode(public_key_hash, nonce);
    let tag: Tag = create_tag(&encoding, &Spartan::salt().to_le_bytes());

    let pre_digest = make_pre_digest(
        slot.into(),
        Solution {
            public_key: FarmerId::from_slice(&keypair.public.to_bytes()),
            nonce: 0,
            encoding: encoding.to_vec(),
            signature: keypair.sign(ctx.bytes(&tag)).to_bytes().to_vec(),
            tag,
        },
    );

    System::initialize(&block, &parent_hash, &pre_digest, InitKind::Full);

    Spartan::on_initialize(block);
}

fn hash_public_key(public_key: &PublicKey) -> [u8; PRIME_SIZE] {
    let mut array = [0u8; PRIME_SIZE];
    let hash = digest::digest(&digest::SHA256, public_key.as_ref());
    array.copy_from_slice(&hash.as_ref()[..PRIME_SIZE]);
    array
}

fn create_tag(encoding: &[u8], salt: &[u8]) -> Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    hmac::sign(&key, encoding).as_ref()[0..8]
        .try_into()
        .unwrap()
}

/// Slots will grow accordingly to blocks
pub fn progress_to_block(keypair: &Keypair, n: u64) {
    let mut slot = u64::from(Spartan::current_slot()) + 1;
    for i in System::block_number() + 1..=n {
        go_to_block(keypair, i, slot);
        slot += 1;
    }
}

pub fn make_pre_digest(slot: Slot, solution: Solution) -> Digest {
    let digest_data = PreDigest { slot, solution };
    let log = DigestItem::PreRuntime(sp_consensus_poc::POC_ENGINE_ID, digest_data.encode());
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
) -> sp_consensus_poc::EquivocationProof<Header> {
    use sp_consensus_poc::digests::CompatibleDigestItem;

    let current_block = System::block_number();
    let current_slot = CurrentSlot::<Test>::get();

    let ctx = schnorrkel::context::signing_context(SIGNING_CONTEXT);
    let encoding: Piece = [0u8; 4096];
    let tag: Tag = [(current_block % 8) as u8; 8];

    let public_key = FarmerId::from_slice(&keypair.public.to_bytes());
    let signature = keypair.sign(ctx.bytes(&tag)).to_bytes().to_vec();

    let make_header = |nonce| {
        let parent_hash = System::parent_hash();
        let pre_digest = make_pre_digest(
            slot,
            Solution {
                public_key: public_key.clone(),
                nonce,
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
        let seal = <DigestItem as CompatibleDigestItem>::poc_seal(signature.into());
        header.digest_mut().push(seal);
    };

    // generate two headers at the current block
    let mut h1 = make_header(0);
    let mut h2 = make_header(1);

    seal_header(&mut h1);
    seal_header(&mut h2);

    // restore previous runtime state
    go_to_block(keypair, current_block, *current_slot);

    sp_consensus_poc::EquivocationProof {
        slot,
        offender: public_key,
        first_header: h1,
        second_header: h2,
    }
}

pub fn create_root_block(segment_index: u64) -> RootBlock {
    RootBlock::V0 {
        segment_index,
        merkle_tree_root: Sha256Hash::default(),
        prev_root_block_hash: Sha256Hash::default(),
        last_archived_block: LastArchivedBlock {
            number: 0,
            bytes: None,
        },
    }
}
