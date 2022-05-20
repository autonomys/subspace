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

//! Consensus extension module tests for Subspace consensus.

use crate::mock::{
    create_root_block, generate_equivocation_proof, go_to_block, new_test_ext, progress_to_block,
    Event, Origin, ReportLongevity, Subspace, System, Test, INITIAL_SOLUTION_RANGE,
    SLOT_PROBABILITY,
};
use crate::{Call, Config, CurrentSlot, Error, WeightInfo};
use codec::Encode;
use frame_support::weights::{GetDispatchInfo, Pays};
use frame_support::{assert_err, assert_ok};
use frame_system::{EventRecord, Phase};
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{FarmerPublicKey, GlobalRandomnesses, Salts, SolutionRanges};
use sp_core::crypto::UncheckedFrom;
use sp_runtime::traits::Header;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionSource, ValidTransaction,
};

#[test]
fn genesis_slot_is_correct() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        // this sets the genesis slot to 6;
        go_to_block(&keypair, 1, 6);
        assert_eq!(*Subspace::genesis_slot(), 6);
    })
}

#[test]
fn can_update_global_randomness() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        assert_eq!(<Test as Config>::GlobalRandomnessUpdateInterval::get(), 10);

        let initial_randomnesses = GlobalRandomnesses {
            current: Default::default(),
            next: None,
        };
        assert_eq!(Subspace::global_randomnesses(), initial_randomnesses);

        // Progress to almost interval edge
        progress_to_block(&keypair, 9);
        // Still no randomness update
        assert_eq!(Subspace::global_randomnesses(), initial_randomnesses);

        // Global randomness update interval edge
        progress_to_block(&keypair, 10);
        // Next randomness should be updated, but current is still unchanged
        let updated_randomnesses = Subspace::global_randomnesses();
        assert_eq!(updated_randomnesses.current, initial_randomnesses.current);
        assert!(updated_randomnesses.next.is_some());

        progress_to_block(&keypair, 11);
        // Next randomness should become current
        assert_eq!(
            Subspace::global_randomnesses(),
            GlobalRandomnesses {
                current: updated_randomnesses.next.unwrap(),
                next: None
            }
        );
    })
}

#[test]
fn can_update_solution_range_on_era_change() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        assert_eq!(<Test as Config>::EraDuration::get(), 4);
        assert_eq!(
            <Test as Config>::InitialSolutionRange::get(),
            INITIAL_SOLUTION_RANGE
        );
        let initial_solution_ranges = SolutionRanges {
            current: INITIAL_SOLUTION_RANGE,
            next: None,
            voting_current: INITIAL_SOLUTION_RANGE,
            voting_next: None,
        };
        assert_eq!(Subspace::solution_ranges(), initial_solution_ranges);
        // enable solution range adjustment
        assert_ok!(Subspace::enable_solution_range_adjustment(Origin::root()));

        // Progress to almost era edge
        progress_to_block(&keypair, 3);
        // No solution range update
        assert_eq!(Subspace::solution_ranges(), initial_solution_ranges);

        // Era edge
        progress_to_block(&keypair, 4);
        // Next solution range should be updated, but current is still unchanged
        let updated_solution_ranges = Subspace::solution_ranges();
        assert_eq!(
            updated_solution_ranges.current,
            initial_solution_ranges.current
        );
        assert!(updated_solution_ranges.next.is_some());

        progress_to_block(&keypair, 5);
        // Next solution range should become current
        assert_eq!(
            Subspace::solution_ranges(),
            SolutionRanges {
                current: updated_solution_ranges.next.unwrap(),
                next: None,
                voting_current: updated_solution_ranges
                    .next
                    .unwrap()
                    .saturating_mul(u64::from(<Test as Config>::ExpectedVotesPerBlock::get()) + 1),
                voting_next: None,
            }
        );

        // Because blocks were produced on every slot, apparent pledged space must increase and
        // solution range should decrease
        let last_solution_range = Subspace::solution_ranges().current;
        assert!(last_solution_range < INITIAL_SOLUTION_RANGE);

        // Progress to era edge such that it takes more slots than expected
        go_to_block(
            &keypair,
            8,
            u64::from(Subspace::current_slot())
                + (4 * SLOT_PROBABILITY.1 / SLOT_PROBABILITY.0 + 10),
        );
        // This should cause solution range to increase as apparent pledged space decreased
        assert!(Subspace::solution_ranges().next.unwrap() > last_solution_range);
    })
}

#[test]
fn solution_range_should_not_update_when_disabled() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        assert_eq!(<Test as Config>::EraDuration::get(), 4);
        assert_eq!(
            <Test as Config>::InitialSolutionRange::get(),
            INITIAL_SOLUTION_RANGE
        );
        let initial_solution_ranges = SolutionRanges {
            current: INITIAL_SOLUTION_RANGE,
            next: None,
            voting_current: INITIAL_SOLUTION_RANGE,
            voting_next: None,
        };
        assert_eq!(Subspace::solution_ranges(), initial_solution_ranges);

        // Progress to almost era edge
        progress_to_block(&keypair, 3);
        // No solution range update
        assert_eq!(Subspace::solution_ranges(), initial_solution_ranges);

        // Era edge
        progress_to_block(&keypair, 4);
        // Next solution range should be updated, but current is still unchanged
        let updated_solution_ranges = Subspace::solution_ranges();
        assert_eq!(
            updated_solution_ranges.current,
            initial_solution_ranges.current
        );
        assert!(updated_solution_ranges.next.is_some());

        progress_to_block(&keypair, 5);
        // Next solution range should become current
        assert_eq!(
            Subspace::solution_ranges(),
            SolutionRanges {
                current: updated_solution_ranges.next.unwrap(),
                next: None,
                voting_current: updated_solution_ranges.next.unwrap(),
                voting_next: None,
            }
        );

        // since solution range adjustment was disabled, solution range will remain the same
        let last_solution_range = Subspace::solution_ranges().current;
        assert_eq!(last_solution_range, INITIAL_SOLUTION_RANGE);

        // Progress to era edge such that it takes more slots than expected
        go_to_block(
            &keypair,
            8,
            u64::from(Subspace::current_slot())
                + (4 * SLOT_PROBABILITY.1 / SLOT_PROBABILITY.0 + 10),
        );
        // Solution rage will still be the same even after the apparent pledged space has decreased
        // since adjustment is disabled
        assert_eq!(
            Subspace::solution_ranges().next.unwrap(),
            INITIAL_SOLUTION_RANGE
        );
    })
}

#[test]
fn can_update_salt_on_eon_change() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        assert_eq!(<Test as Config>::EonDuration::get(), 5);
        assert_eq!(<Test as Config>::EonNextSaltReveal::get(), 3);
        let initial_salts = Salts::default();
        assert_eq!(Subspace::salts(), initial_salts);

        // Almost salt reveal
        progress_to_block(&keypair, 3);
        // No salts update
        assert_eq!(Subspace::salts(), initial_salts);

        // Salt reveal
        progress_to_block(&keypair, 4);
        // Next salt should be revealed, but current is still unchanged and it is not yet scheduled
        // for switch in the next block.
        let revealed_salts = Subspace::salts();
        assert_eq!(revealed_salts.current, initial_salts.current);
        assert!(revealed_salts.next.is_some());
        assert!(!revealed_salts.switch_next_block);

        // Almost eon edge
        progress_to_block(&keypair, 5);
        // No changes from before
        assert_eq!(Subspace::salts(), revealed_salts);

        // Eon edge
        progress_to_block(&keypair, 6);
        // Same salts, scheduled to be updated in the next block
        assert_eq!(
            Subspace::salts(),
            Salts {
                current: revealed_salts.current,
                next: revealed_salts.next,
                switch_next_block: true
            }
        );

        progress_to_block(&keypair, 7);
        // Salts switched
        assert_eq!(
            Subspace::salts(),
            Salts {
                current: revealed_salts.next.unwrap(),
                next: None,
                switch_next_block: false
            }
        );
    })
}

#[test]
fn report_equivocation_current_session_works() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        progress_to_block(&keypair, 1);

        let farmer_public_key = FarmerPublicKey::unchecked_from(keypair.public.to_bytes());

        // generate an equivocation proof. it creates two headers at the given
        // slot with different block hashes and signed by the given key
        let equivocation_proof = generate_equivocation_proof(&keypair, CurrentSlot::<Test>::get());

        assert!(!Subspace::is_in_block_list(&farmer_public_key));

        // report the equivocation
        Subspace::report_equivocation(Origin::none(), Box::new(equivocation_proof)).unwrap();

        progress_to_block(&keypair, 2);

        // check that farmer was added to block list
        assert!(Subspace::is_in_block_list(&farmer_public_key));
    });
}

#[test]
fn report_equivocation_old_session_works() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        progress_to_block(&keypair, 1);

        let farmer_public_key = FarmerPublicKey::unchecked_from(keypair.public.to_bytes());

        // generate an equivocation proof at the current slot
        let equivocation_proof = generate_equivocation_proof(&keypair, CurrentSlot::<Test>::get());

        // create new block and report the equivocation
        // from the previous block
        progress_to_block(&keypair, 2);

        assert!(!Subspace::is_in_block_list(&farmer_public_key));

        // report the equivocation
        Subspace::report_equivocation(Origin::none(), Box::new(equivocation_proof)).unwrap();

        progress_to_block(&keypair, 3);

        // check that farmer was added to block list
        assert!(Subspace::is_in_block_list(&farmer_public_key));
    })
}

#[test]
fn report_equivocation_invalid_equivocation_proof() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        progress_to_block(&keypair, 1);

        let assert_invalid_equivocation = |equivocation_proof| {
            assert_err!(
                Subspace::report_equivocation(Origin::none(), Box::new(equivocation_proof),),
                Error::<Test>::InvalidEquivocationProof,
            )
        };

        // both headers have the same hash, no equivocation.
        let mut equivocation_proof =
            generate_equivocation_proof(&keypair, CurrentSlot::<Test>::get());
        equivocation_proof.second_header = equivocation_proof.first_header.clone();
        assert_invalid_equivocation(equivocation_proof);

        // missing preruntime digest from one header
        let mut equivocation_proof =
            generate_equivocation_proof(&keypair, CurrentSlot::<Test>::get());
        equivocation_proof.first_header.digest_mut().logs.remove(0);
        assert_invalid_equivocation(equivocation_proof);

        // missing seal from one header
        let mut equivocation_proof =
            generate_equivocation_proof(&keypair, CurrentSlot::<Test>::get());
        equivocation_proof.first_header.digest_mut().logs.remove(1);
        assert_invalid_equivocation(equivocation_proof);

        // invalid slot number in proof compared to runtime digest
        let mut equivocation_proof =
            generate_equivocation_proof(&keypair, CurrentSlot::<Test>::get());
        equivocation_proof.slot = Slot::from(0);
        assert_invalid_equivocation(equivocation_proof.clone());

        // different slot numbers in headers
        let h1 = equivocation_proof.first_header;
        let mut equivocation_proof =
            generate_equivocation_proof(&keypair, CurrentSlot::<Test>::get() + 1);

        // use the header from the previous equivocation generated
        // at the previous slot
        equivocation_proof.first_header = h1.clone();

        assert_invalid_equivocation(equivocation_proof);

        // invalid seal signature
        let mut equivocation_proof =
            generate_equivocation_proof(&keypair, CurrentSlot::<Test>::get() + 1);

        // replace the seal digest with the digest from the
        // previous header at the previous slot
        equivocation_proof.first_header.digest_mut().pop();
        equivocation_proof
            .first_header
            .digest_mut()
            .push(h1.digest().logs().last().unwrap().clone());

        assert_invalid_equivocation(equivocation_proof.clone());
    })
}

#[test]
fn report_equivocation_validate_unsigned_prevents_duplicates() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        progress_to_block(&keypair, 1);

        let farmer_public_key = FarmerPublicKey::unchecked_from(keypair.public.to_bytes());

        let equivocation_proof = generate_equivocation_proof(&keypair, CurrentSlot::<Test>::get());

        let inner = Call::report_equivocation {
            equivocation_proof: Box::new(equivocation_proof.clone()),
        };

        // Only local/in block reports are allowed
        assert_eq!(
            <Subspace as sp_runtime::traits::ValidateUnsigned>::validate_unsigned(
                TransactionSource::External,
                &inner,
            ),
            InvalidTransaction::Call.into(),
        );

        // The transaction is valid when passed as local
        let tx_tag = (farmer_public_key, CurrentSlot::<Test>::get());
        assert_eq!(
            <Subspace as sp_runtime::traits::ValidateUnsigned>::validate_unsigned(
                TransactionSource::Local,
                &inner,
            ),
            Ok(ValidTransaction {
                priority: TransactionPriority::MAX,
                requires: vec![],
                provides: vec![("SubspaceEquivocation", tx_tag).encode()],
                longevity: ReportLongevity::get(),
                propagate: false,
            })
        );

        // The pre dispatch checks should also pass
        assert_ok!(<Subspace as sp_runtime::traits::ValidateUnsigned>::pre_dispatch(&inner));

        // Submit the report
        Subspace::report_equivocation(Origin::none(), Box::new(equivocation_proof)).unwrap();

        // The report should now be considered stale and the transaction is invalid.
        // The check for staleness should be done on both `validate_unsigned` and on `pre_dispatch`
        assert_err!(
            <Subspace as sp_runtime::traits::ValidateUnsigned>::validate_unsigned(
                TransactionSource::Local,
                &inner,
            ),
            InvalidTransaction::Stale,
        );

        assert_err!(
            <Subspace as sp_runtime::traits::ValidateUnsigned>::pre_dispatch(&inner),
            InvalidTransaction::Stale,
        );
    });
}

#[test]
fn report_equivocation_has_valid_weight() {
    // the weight is always the same.
    assert!((1..=1000)
        .map(|_| { <Test as Config>::WeightInfo::report_equivocation() })
        .all(|w| w == 10_000));
}

#[test]
fn valid_equivocation_reports_dont_pay_fees() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        progress_to_block(&keypair, 1);

        // generate an equivocation proof.
        let equivocation_proof = generate_equivocation_proof(&keypair, CurrentSlot::<Test>::get());

        // check the dispatch info for the call.
        let info = Call::<Test>::report_equivocation {
            equivocation_proof: Box::new(equivocation_proof.clone()),
        }
        .get_dispatch_info();

        // it should have non-zero weight and the fee has to be paid.
        assert!(info.weight > 0);
        assert_eq!(info.pays_fee, Pays::Yes);

        // report the equivocation.
        let post_info =
            Subspace::report_equivocation(Origin::none(), Box::new(equivocation_proof.clone()))
                .unwrap();

        // the original weight should be kept, but given that the report
        // is valid the fee is waived.
        assert!(post_info.actual_weight.is_none());
        assert_eq!(post_info.pays_fee, Pays::No);

        // report the equivocation again which is invalid now since it is
        // duplicate.
        let post_info = Subspace::report_equivocation(Origin::none(), Box::new(equivocation_proof))
            .err()
            .unwrap()
            .post_info;

        // the fee is not waived and the original weight is kept.
        assert!(post_info.actual_weight.is_none());
        assert_eq!(post_info.pays_fee, Pays::Yes);
    })
}

#[test]
fn store_root_block_works() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        progress_to_block(&keypair, 1);

        let root_block = create_root_block(0);

        let call = Call::<Test>::store_root_blocks {
            root_blocks: vec![root_block],
        };
        // Root blocks don't require fee
        assert_eq!(call.get_dispatch_info().pays_fee, Pays::No);

        Subspace::store_root_blocks(Origin::none(), vec![root_block]).unwrap();
        assert_eq!(
            System::events(),
            vec![EventRecord {
                phase: Phase::Initialization,
                event: Event::Subspace(crate::Event::RootBlockStored { root_block }),
                topics: vec![],
            }]
        );
    });
}

#[test]
fn store_root_block_validate_unsigned_prevents_duplicates() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        progress_to_block(&keypair, 1);

        let root_block = create_root_block(0);

        let inner = Call::store_root_blocks {
            root_blocks: vec![root_block],
        };

        // Only local/in block reports are allowed
        assert_eq!(
            <Subspace as sp_runtime::traits::ValidateUnsigned>::validate_unsigned(
                TransactionSource::External,
                &inner,
            ),
            InvalidTransaction::Call.into(),
        );

        // The transaction is valid when passed as local
        assert_eq!(
            <Subspace as sp_runtime::traits::ValidateUnsigned>::validate_unsigned(
                TransactionSource::Local,
                &inner,
            ),
            Ok(ValidTransaction {
                priority: TransactionPriority::MAX,
                requires: vec![],
                provides: vec![],
                longevity: 0,
                propagate: false,
            })
        );

        // The pre dispatch checks should also pass
        assert_ok!(<Subspace as sp_runtime::traits::ValidateUnsigned>::pre_dispatch(&inner));

        // Submit the report
        Subspace::store_root_blocks(Origin::none(), vec![root_block]).unwrap();

        // The report should now be considered stale and the transaction is invalid.
        // The check for staleness should be done on both `validate_unsigned` and on `pre_dispatch`
        assert_err!(
            <Subspace as sp_runtime::traits::ValidateUnsigned>::validate_unsigned(
                TransactionSource::Local,
                &inner,
            ),
            InvalidTransaction::BadMandatory,
        );
        assert_err!(
            <Subspace as sp_runtime::traits::ValidateUnsigned>::pre_dispatch(&inner),
            InvalidTransaction::BadMandatory,
        );

        let inner2 = Call::store_root_blocks {
            root_blocks: vec![create_root_block(1), create_root_block(1)],
        };

        // Same root block can't be included twice even in the same extrinsic
        assert_err!(
            <Subspace as sp_runtime::traits::ValidateUnsigned>::validate_unsigned(
                TransactionSource::Local,
                &inner2,
            ),
            InvalidTransaction::BadMandatory,
        );
        assert_err!(
            <Subspace as sp_runtime::traits::ValidateUnsigned>::pre_dispatch(&inner2),
            InvalidTransaction::BadMandatory,
        );
    });
}
