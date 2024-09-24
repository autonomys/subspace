// Copyright (C) 2018-2021 Parity Technologies (UK) Ltd.
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

#![cfg(test)]

use crate as pallet_offences_subspace;
use crate::Config;
use codec::Encode;
use frame_support::derive_impl;
use frame_support::weights::constants::ParityDbWeight;
use frame_support::weights::Weight;
use sp_consensus_subspace::offence::{self, Kind, OffenceDetails};
use sp_core::H256;
use sp_runtime::{BuildStorage, Perbill};
use std::cell::RefCell;
use subspace_core_primitives::PublicKey;

pub struct OnOffenceHandler;

thread_local! {
    pub static ON_OFFENCE_PERBILL: RefCell<Vec<Perbill>> = RefCell::new(Default::default());
    pub static OFFENCE_WEIGHT: RefCell<Weight> = RefCell::new(Default::default());
}

impl<Offender> offence::OnOffenceHandler<Offender> for OnOffenceHandler {
    fn on_offence(_offenders: &[OffenceDetails<Offender>]) {
        ON_OFFENCE_PERBILL.with(|f| {
            *f.borrow_mut() = vec![Perbill::from_percent(25)];
        });
    }
}

pub fn with_on_offence_fractions<R, F: FnOnce(&mut Vec<Perbill>) -> R>(f: F) -> R {
    ON_OFFENCE_PERBILL.with(|fractions| f(fractions.borrow_mut().as_mut()))
}

type Block = frame_system::mocking::MockBlock<Runtime>;

frame_support::construct_runtime!(
    pub struct Runtime {
        System: frame_system,
        OffencesSubspace: pallet_offences_subspace,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Runtime {
    type Block = Block;
    type DbWeight = ParityDbWeight;
}

impl Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnOffenceHandler = OnOffenceHandler;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .unwrap();
    let mut ext = sp_io::TestExternalities::new(t);
    ext.execute_with(|| System::set_block_number(1));
    ext
}

pub const KIND: [u8; 16] = *b"test_report_1234";

/// Returns all offence details for the specific `kind` happened at the specific time slot.
pub fn offence_reports(kind: Kind, time_slot: u128) -> Vec<OffenceDetails<PublicKey>> {
    <crate::ConcurrentReportsIndex<Runtime>>::get(kind, time_slot.encode())
        .into_iter()
        .map(|report_id| {
            <crate::Reports<Runtime>>::get(report_id)
                .expect("dangling report id is found in ConcurrentReportsIndex")
        })
        .collect()
}

#[derive(Clone)]
pub struct Offence<T> {
    pub offenders: Vec<T>,
    pub time_slot: u128,
}

impl<T: Clone> offence::Offence<T> for Offence<T> {
    const ID: offence::Kind = KIND;
    type TimeSlot = u128;

    fn offenders(&self) -> Vec<T> {
        self.offenders.clone()
    }

    fn time_slot(&self) -> u128 {
        self.time_slot
    }
}

/// Create the report id for the given `offender` and `time_slot` combination.
pub fn report_id(time_slot: u128, offender: PublicKey) -> H256 {
    OffencesSubspace::report_id::<Offence<PublicKey>>(&time_slot, &offender)
}
