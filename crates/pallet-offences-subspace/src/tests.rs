// Copyright (C) 2017-2021 Parity Technologies (UK) Ltd.
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

//! Tests for the offences module.

#![cfg(test)]

use crate::mock::{
    new_test_ext, offence_reports, report_id, with_on_offence_fractions, Offence, OffencesSubspace,
    RuntimeEvent, System, KIND,
};
use codec::{Decode, Encode};
use frame_system::{EventRecord, Phase};
use schnorrkel::Keypair;
use sp_consensus_subspace::offence::{OffenceDetails, OffenceError, ReportOffence};
use sp_runtime::Perbill;
use subspace_core_primitives::PublicKey;

fn generate_farmer_public_key() -> PublicKey {
    let keypair = Keypair::generate();
    PublicKey::from(keypair.public.to_bytes())
}

#[test]
fn should_report_an_farmer_and_trigger_on_offence() {
    new_test_ext().execute_with(|| {
        // given
        let time_slot = 42;
        assert_eq!(offence_reports(KIND, time_slot), vec![]);

        let offence = Offence {
            time_slot,
            offenders: vec![generate_farmer_public_key()],
        };

        // when
        OffencesSubspace::report_offence(offence).unwrap();

        // then
        with_on_offence_fractions(|f| {
            assert_eq!(f.clone(), vec![Perbill::from_percent(25)]);
        });
    });
}

#[test]
fn should_not_report_the_same_farmer_twice_in_the_same_slot() {
    new_test_ext().execute_with(|| {
        // given
        let time_slot = 42;
        assert_eq!(offence_reports(KIND, time_slot), vec![]);

        let offence = Offence {
            time_slot,
            offenders: vec![generate_farmer_public_key()],
        };
        OffencesSubspace::report_offence(offence.clone()).unwrap();
        with_on_offence_fractions(|f| {
            assert_eq!(f.clone(), vec![Perbill::from_percent(25)]);
            f.clear();
        });

        // when
        // report for the second time
        assert_eq!(
            OffencesSubspace::report_offence(offence),
            Err(OffenceError::DuplicateReport)
        );

        // then
        with_on_offence_fractions(|f| {
            assert_eq!(f.clone(), vec![]);
        });
    });
}

#[test]
fn should_report_in_different_time_slot() {
    new_test_ext().execute_with(|| {
        // given
        let time_slot = 42;
        assert_eq!(offence_reports(KIND, time_slot), vec![]);

        let mut offence = Offence {
            time_slot,
            offenders: vec![generate_farmer_public_key()],
        };
        OffencesSubspace::report_offence(offence.clone()).unwrap();
        with_on_offence_fractions(|f| {
            assert_eq!(f.clone(), vec![Perbill::from_percent(25)]);
            f.clear();
        });

        // when
        // report for the second time
        offence.time_slot += 1;
        OffencesSubspace::report_offence(offence).unwrap();

        // then
        with_on_offence_fractions(|f| {
            assert_eq!(f.clone(), vec![Perbill::from_percent(25)]);
        });
    });
}

#[test]
fn should_deposit_event() {
    new_test_ext().execute_with(|| {
        // given
        let time_slot = 42;
        assert_eq!(offence_reports(KIND, time_slot), vec![]);

        let offence = Offence {
            time_slot,
            offenders: vec![generate_farmer_public_key()],
        };

        // when
        OffencesSubspace::report_offence(offence).unwrap();

        // then
        assert_eq!(
            System::events(),
            vec![EventRecord {
                phase: Phase::Initialization,
                event: RuntimeEvent::OffencesSubspace(crate::Event::Offence {
                    kind: KIND,
                    timeslot: time_slot.encode()
                }),
                topics: vec![],
            }]
        );
    });
}

#[test]
fn doesnt_deposit_event_for_dups() {
    new_test_ext().execute_with(|| {
        // given
        let time_slot = 42;
        assert_eq!(offence_reports(KIND, time_slot), vec![]);

        let offence = Offence {
            time_slot,
            offenders: vec![generate_farmer_public_key()],
        };
        OffencesSubspace::report_offence(offence.clone()).unwrap();
        with_on_offence_fractions(|f| {
            assert_eq!(f.clone(), vec![Perbill::from_percent(25)]);
            f.clear();
        });

        // when
        // report for the second time
        assert_eq!(
            OffencesSubspace::report_offence(offence),
            Err(OffenceError::DuplicateReport)
        );

        // then
        // there is only one event.
        assert_eq!(
            System::events(),
            vec![EventRecord {
                phase: Phase::Initialization,
                event: RuntimeEvent::OffencesSubspace(crate::Event::Offence {
                    kind: KIND,
                    timeslot: time_slot.encode()
                }),
                topics: vec![],
            }]
        );
    });
}

#[test]
fn reports_if_an_offence_is_dup() {
    type TestOffence = Offence<PublicKey>;

    new_test_ext().execute_with(|| {
        let time_slot = 42;
        assert_eq!(offence_reports(KIND, time_slot), vec![]);

        let farmer_0 = generate_farmer_public_key();
        let farmer_1 = generate_farmer_public_key();

        let offence = |time_slot, offenders| TestOffence {
            time_slot,
            offenders,
        };

        let mut test_offence = offence(time_slot, vec![farmer_0]);

        // the report for farmer 0 at time slot 42 should not be a known
        // offence
        assert!(
            !<OffencesSubspace as ReportOffence<_, TestOffence>>::is_known_offence(
                &test_offence.offenders,
                &test_offence.time_slot
            )
        );

        // we report an offence for farmer 0 at time slot 42
        OffencesSubspace::report_offence(test_offence.clone()).unwrap();

        // the same report should be a known offence now
        assert!(
            <OffencesSubspace as ReportOffence<_, TestOffence>>::is_known_offence(
                &test_offence.offenders,
                &test_offence.time_slot
            )
        );

        // and reporting it again should yield a duplicate report error
        assert_eq!(
            OffencesSubspace::report_offence(test_offence.clone()),
            Err(OffenceError::DuplicateReport)
        );

        // after adding a new offender to the offence report
        test_offence.offenders.push(farmer_1);

        // it should not be a known offence anymore
        assert!(
            !<OffencesSubspace as ReportOffence<_, TestOffence>>::is_known_offence(
                &test_offence.offenders,
                &test_offence.time_slot
            )
        );

        // and reporting it again should work without any error
        assert_eq!(
            OffencesSubspace::report_offence(test_offence.clone()),
            Ok(())
        );

        // creating a new offence for the same farmers on the next slot
        // should be considered a new offence and therefore not known
        let test_offence_next_slot = offence(time_slot + 1, vec![farmer_0, farmer_1]);
        assert!(
            !<OffencesSubspace as ReportOffence<_, TestOffence>>::is_known_offence(
                &test_offence_next_slot.offenders,
                &test_offence_next_slot.time_slot
            )
        );
    });
}

#[test]
fn should_properly_count_offences() {
    // We report two different farmers for the same issue. Ultimately, the 1st farmer
    // should have `count` equal 2 and the count of the 2nd one should be equal to 1.
    new_test_ext().execute_with(|| {
        // given
        let time_slot = 42;
        assert_eq!(offence_reports(KIND, time_slot), vec![]);

        let farmer_1 = generate_farmer_public_key();
        let farmer_2 = generate_farmer_public_key();

        let offence1 = Offence {
            time_slot,
            offenders: vec![farmer_1],
        };
        let offence2 = Offence {
            time_slot,
            offenders: vec![farmer_2],
        };
        OffencesSubspace::report_offence(offence1).unwrap();
        with_on_offence_fractions(|f| {
            assert_eq!(f.clone(), vec![Perbill::from_percent(25)]);
            f.clear();
        });

        // when
        // report for the second time
        OffencesSubspace::report_offence(offence2).unwrap();

        // then
        // the 1st farmer should have count 2 and the 2nd one should be reported only once.
        assert_eq!(
            offence_reports(KIND, time_slot),
            vec![
                OffenceDetails { offender: farmer_1 },
                OffenceDetails { offender: farmer_2 },
            ]
        );
    });
}

/// We insert offences in sorted order using the time slot in the `same_kind_reports`.
/// This test ensures that it works as expected.
#[test]
fn should_properly_sort_offences() {
    new_test_ext().execute_with(|| {
        // given
        let time_slot = 42;
        assert_eq!(offence_reports(KIND, time_slot), vec![]);

        let farmer_5 = generate_farmer_public_key();
        let farmer_4 = generate_farmer_public_key();
        let farmer_6 = generate_farmer_public_key();
        let farmer_7 = generate_farmer_public_key();
        let farmer_3 = generate_farmer_public_key();

        let offence1 = Offence {
            time_slot,
            offenders: vec![farmer_5],
        };
        let offence2 = Offence {
            time_slot,
            offenders: vec![farmer_4],
        };
        let offence3 = Offence {
            time_slot: time_slot + 1,
            offenders: vec![farmer_6, farmer_7],
        };
        let offence4 = Offence {
            time_slot: time_slot - 1,
            offenders: vec![farmer_3],
        };
        OffencesSubspace::report_offence(offence1).unwrap();
        with_on_offence_fractions(|f| {
            assert_eq!(f.clone(), vec![Perbill::from_percent(25)]);
            f.clear();
        });

        // when
        // report for the second time
        OffencesSubspace::report_offence(offence2).unwrap();
        OffencesSubspace::report_offence(offence3).unwrap();
        OffencesSubspace::report_offence(offence4).unwrap();

        // then
        let same_kind_reports = Vec::<(u128, sp_core::H256)>::decode(
            &mut &crate::ReportsByKindIndex::<crate::mock::Runtime>::get(KIND)[..],
        )
        .unwrap();
        assert_eq!(
            same_kind_reports,
            vec![
                (time_slot - 1, report_id(time_slot - 1, farmer_3)),
                (time_slot, report_id(time_slot, farmer_5)),
                (time_slot, report_id(time_slot, farmer_4)),
                (time_slot + 1, report_id(time_slot + 1, farmer_6)),
                (time_slot + 1, report_id(time_slot + 1, farmer_7)),
            ]
        );
    });
}
