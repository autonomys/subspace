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
    create_archived_segment, create_root_block, create_signed_vote, extract_piece,
    generate_equivocation_proof, go_to_block, new_test_ext, progress_to_block, EonDuration, Event,
    GlobalRandomnessUpdateInterval, Origin, ReportLongevity, Subspace, System, Test,
    INITIAL_SOLUTION_RANGE, SLOT_PROBABILITY,
};
use crate::{
    BlockList, Call, CheckVoteError, Config, CurrentBlockAuthorInfo, CurrentBlockVoters,
    CurrentSlot, Error, ParentBlockAuthorInfo, ParentBlockVoters, RecordsRoot, WeightInfo,
};
use codec::Encode;
use frame_support::weights::{GetDispatchInfo, Pays};
use frame_support::{assert_err, assert_ok};
use frame_system::{EventRecord, Phase};
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::verification::VerificationError;
use sp_consensus_subspace::{
    FarmerPublicKey, FarmerSignature, GlobalRandomnesses, Salts, SolutionRanges, Vote,
};
use sp_core::crypto::UncheckedFrom;
use sp_runtime::traits::Header;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionSource, ValidTransaction,
};
use std::assert_matches::assert_matches;
use std::collections::BTreeMap;
use subspace_runtime_primitives::{FindBlockRewardAddress, FindVotingRewardAddresses};
use subspace_solving::REWARD_SIGNING_CONTEXT;

#[test]
fn genesis_slot_is_correct() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        // this sets the genesis slot to 6;
        go_to_block(&keypair, 1, 6, 1);
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
        progress_to_block(&keypair, 9, 1);
        // Still no randomness update
        assert_eq!(Subspace::global_randomnesses(), initial_randomnesses);

        // Global randomness update interval edge
        progress_to_block(&keypair, 10, 1);
        // Next randomness should be updated, but current is still unchanged
        let updated_randomnesses = Subspace::global_randomnesses();
        assert_eq!(updated_randomnesses.current, initial_randomnesses.current);
        assert!(updated_randomnesses.next.is_some());

        progress_to_block(&keypair, 11, 1);
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
        progress_to_block(&keypair, 3, 1);
        // No solution range update
        assert_eq!(Subspace::solution_ranges(), initial_solution_ranges);

        // Era edge
        progress_to_block(&keypair, 4, 1);
        // Next solution range should be updated, but current is still unchanged
        let updated_solution_ranges = Subspace::solution_ranges();
        assert_eq!(
            updated_solution_ranges.current,
            initial_solution_ranges.current
        );
        assert!(updated_solution_ranges.next.is_some());

        progress_to_block(&keypair, 5, 1);
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
            1,
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
        progress_to_block(&keypair, 3, 1);
        // No solution range update
        assert_eq!(Subspace::solution_ranges(), initial_solution_ranges);

        // Era edge
        progress_to_block(&keypair, 4, 1);
        // Next solution range should be updated, but current is still unchanged
        let updated_solution_ranges = Subspace::solution_ranges();
        assert_eq!(
            updated_solution_ranges.current,
            initial_solution_ranges.current
        );
        assert!(updated_solution_ranges.next.is_some());

        progress_to_block(&keypair, 5, 1);
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
            1,
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

        assert_eq!(<Test as Config>::EonDuration::get(), 6);
        assert_eq!(<Test as Config>::EonNextSaltReveal::get(), 3);
        let initial_salts = Salts::default();
        assert_eq!(Subspace::salts(), initial_salts);

        // Almost salt reveal
        progress_to_block(&keypair, 3, 1);
        // No salts update
        assert_eq!(Subspace::salts(), initial_salts);

        // Salt reveal
        progress_to_block(&keypair, 5, 1);
        // Next salt should be revealed, but current is still unchanged and it is not yet scheduled
        // for switch in the next block.
        let revealed_salts = Subspace::salts();
        assert_eq!(revealed_salts.current, initial_salts.current);
        assert!(revealed_salts.next.is_some());
        assert!(!revealed_salts.switch_next_block);

        // Almost eon edge
        progress_to_block(&keypair, 6, 1);
        // No changes from before
        assert_eq!(Subspace::salts(), revealed_salts);

        // Eon edge
        progress_to_block(&keypair, 7, 1);
        // Same salts, scheduled to be updated in the next block
        assert_eq!(
            Subspace::salts(),
            Salts {
                current: revealed_salts.current,
                next: revealed_salts.next,
                switch_next_block: true
            }
        );

        progress_to_block(&keypair, 8, 1);
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

        progress_to_block(&keypair, 1, 1);

        let farmer_public_key = FarmerPublicKey::unchecked_from(keypair.public.to_bytes());

        // generate an equivocation proof. it creates two headers at the given
        // slot with different block hashes and signed by the given key
        let equivocation_proof = generate_equivocation_proof(&keypair, CurrentSlot::<Test>::get());

        assert!(!Subspace::is_in_block_list(&farmer_public_key));

        // report the equivocation
        Subspace::report_equivocation(Origin::none(), Box::new(equivocation_proof)).unwrap();

        progress_to_block(&keypair, 2, 1);

        // check that farmer was added to block list
        assert!(Subspace::is_in_block_list(&farmer_public_key));
    });
}

#[test]
fn report_equivocation_old_session_works() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        progress_to_block(&keypair, 1, 1);

        let farmer_public_key = FarmerPublicKey::unchecked_from(keypair.public.to_bytes());

        // generate an equivocation proof at the current slot
        let equivocation_proof = generate_equivocation_proof(&keypair, CurrentSlot::<Test>::get());

        // create new block and report the equivocation
        // from the previous block
        progress_to_block(&keypair, 2, 1);

        assert!(!Subspace::is_in_block_list(&farmer_public_key));

        // report the equivocation
        Subspace::report_equivocation(Origin::none(), Box::new(equivocation_proof)).unwrap();

        progress_to_block(&keypair, 3, 1);

        // check that farmer was added to block list
        assert!(Subspace::is_in_block_list(&farmer_public_key));
    })
}

#[test]
fn report_equivocation_invalid_equivocation_proof() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();

        progress_to_block(&keypair, 1, 1);

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

        progress_to_block(&keypair, 1, 1);

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

        progress_to_block(&keypair, 1, 1);

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

        progress_to_block(&keypair, 1, 1);

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

        progress_to_block(&keypair, 1, 1);

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

#[test]
fn vote_block_listed() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        BlockList::<Test>::insert(
            FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
            (),
        );

        // Can't submit vote right after genesis block
        let signed_vote = create_signed_vote(
            &keypair,
            0,
            <Test as frame_system::Config>::Hash::default(),
            Subspace::current_slot() + 1,
            &Subspace::global_randomnesses().current,
            Subspace::salts().current,
            piece,
            1,
        );

        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::BlockListed
        );
    });
}

#[test]
fn vote_after_genesis() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        // Can't submit vote right after genesis block
        let signed_vote = create_signed_vote(
            &keypair,
            0,
            <Test as frame_system::Config>::Hash::default(),
            Subspace::current_slot() + 1,
            &Subspace::global_randomnesses().current,
            Subspace::salts().current,
            piece,
            1,
        );

        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::UnexpectedBeforeHeightTwo
        );
    });
}

#[test]
fn vote_too_low_height() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 1, 1);

        // Can't submit vote with height lower than 2

        for height in 0..2 {
            let signed_vote = create_signed_vote(
                &keypair,
                height,
                <Test as frame_system::Config>::Hash::default(),
                Subspace::current_slot() + 1,
                &Subspace::global_randomnesses().current,
                Subspace::salts().current,
                piece.clone(),
                1,
            );

            assert_err!(
                super::check_vote::<Test>(&signed_vote, false),
                CheckVoteError::UnexpectedBeforeHeightTwo
            );
        }
    });
}

#[test]
fn vote_past_future_height() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 4, 1);

        // Height must be either the same as current block or older by one (this tests future vote)
        {
            let signed_vote = create_signed_vote(
                &keypair,
                5,
                <Test as frame_system::Config>::Hash::default(),
                Subspace::current_slot() + 1,
                &Subspace::global_randomnesses().current,
                Subspace::salts().current,
                piece.clone(),
                1,
            );

            assert_err!(
                super::check_vote::<Test>(&signed_vote, false),
                CheckVoteError::HeightInTheFuture
            );
        }

        // Height must be either the same as current block or older by one (this tests past vote)
        {
            let signed_vote = create_signed_vote(
                &keypair,
                2,
                <Test as frame_system::Config>::Hash::default(),
                Subspace::current_slot() + 1,
                &Subspace::global_randomnesses().current,
                Subspace::salts().current,
                piece,
                1,
            );

            assert_err!(
                super::check_vote::<Test>(&signed_vote, false),
                CheckVoteError::HeightInThePast
            );
        }
    });
}

#[test]
fn vote_wrong_parent() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 2, 1);

        // Vote must point to real parent hash
        let signed_vote = create_signed_vote(
            &keypair,
            2,
            <Test as frame_system::Config>::Hash::default(),
            Subspace::current_slot() + 1,
            &Subspace::global_randomnesses().current,
            Subspace::salts().current,
            piece,
            1,
        );

        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::IncorrectParentHash
        );
    });
}

#[test]
fn vote_past_future_slot() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 3, 1);

        // Vote slot must be after slot of the parent block
        {
            let signed_vote = create_signed_vote(
                &keypair,
                3,
                frame_system::Pallet::<Test>::block_hash(2),
                2.into(),
                &Subspace::global_randomnesses().current,
                Subspace::salts().current,
                piece.clone(),
                1,
            );

            assert_err!(
                super::check_vote::<Test>(&signed_vote, false),
                CheckVoteError::SlotInThePast
            );
        }

        // Vote slot must be before the slot of the new block
        {
            let signed_vote = create_signed_vote(
                &keypair,
                3,
                frame_system::Pallet::<Test>::block_hash(2),
                4.into(),
                &Subspace::global_randomnesses().current,
                Subspace::salts().current,
                piece,
                1,
            );

            assert_err!(
                super::check_vote::<Test>(&signed_vote, true),
                CheckVoteError::SlotInTheFuture
            );
        }
    });
}

#[test]
fn vote_same_slot() {
    new_test_ext().execute_with(|| {
        let block_keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        // Move to the block 3, but time slot 4, but in two time slots
        go_to_block(&block_keypair, 3, 4, 1);

        RecordsRoot::<Test>::insert(
            archived_segment.root_block.segment_index(),
            archived_segment.root_block.records_root(),
        );

        // Reset so that any solution works for votes
        crate::pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.voting_current = u64::MAX;
        });

        // Same time slot in the vote as in the block is fine if height is the same (pre-dispatch)
        {
            let keypair = Keypair::generate();
            let piece = extract_piece(&keypair, &archived_segment, 0);
            let signed_vote = create_signed_vote(
                &keypair,
                3,
                frame_system::Pallet::<Test>::block_hash(2),
                Subspace::current_slot(),
                &Subspace::global_randomnesses().current,
                Subspace::salts().current,
                piece,
                1,
            );

            assert_ok!(super::check_vote::<Test>(&signed_vote, true));
        }

        // Same time slot in the vote as in the block is not fine if height is different though
        // (pre-dispatch)
        {
            let keypair = Keypair::generate();
            let piece = extract_piece(&keypair, &archived_segment, 0);
            let signed_vote = create_signed_vote(
                &keypair,
                2,
                frame_system::Pallet::<Test>::block_hash(1),
                Subspace::current_slot(),
                &Subspace::global_randomnesses().current,
                Subspace::salts().current,
                piece,
                1,
            );

            assert_err!(
                super::check_vote::<Test>(&signed_vote, true),
                CheckVoteError::SlotInTheFuture
            );
        }
    });
}

#[test]
fn vote_bad_reward_signature() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 2, 1);

        // Vote must be signed correctly
        let mut signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            Subspace::current_slot() + 1,
            &Subspace::global_randomnesses().current,
            Subspace::salts().current,
            piece,
            1,
        );

        signed_vote.signature = FarmerSignature::unchecked_from(rand::random::<[u8; 64]>());

        assert_matches!(
            super::check_vote::<Test>(&signed_vote, false),
            Err(CheckVoteError::BadRewardSignature(_))
        );
    });
}

#[test]
fn vote_unknown_records_root() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 2, 1);

        // There must be record root corresponding to the piece used
        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            Subspace::current_slot() + 1,
            &Subspace::global_randomnesses().current,
            Subspace::salts().current,
            piece,
            1,
        );

        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::UnknownRecordsRoot
        );
    });
}

#[test]
fn vote_outside_of_solution_range() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 2, 1);

        RecordsRoot::<Test>::insert(
            archived_segment.root_block.segment_index(),
            archived_segment.root_block.records_root(),
        );

        // Solution must be within solution range
        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            Subspace::current_slot() + 1,
            &Subspace::global_randomnesses().current,
            Subspace::salts().current,
            piece,
            1,
        );

        assert_matches!(
            super::check_vote::<Test>(&signed_vote, false),
            Err(CheckVoteError::InvalidSolution(
                VerificationError::OutsideOfSolutionRange(_)
            ))
        );
    });
}

#[test]
fn vote_invalid_solution_signature() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 2, 1);

        RecordsRoot::<Test>::insert(
            archived_segment.root_block.segment_index(),
            archived_segment.root_block.records_root(),
        );

        // Reset so that any solution works for votes
        crate::pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.voting_current = u64::MAX;
        });

        // Solution signature must be correct
        let mut signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            Subspace::current_slot() + 1,
            &Subspace::global_randomnesses().current,
            Subspace::salts().current,
            piece,
            1,
        );

        let Vote::V0 { solution, .. } = &mut signed_vote.vote;
        solution.signature = rand::random::<[u8; 64]>().into();

        // Fix signed vote signature after changed contents
        signed_vote.signature = FarmerSignature::unchecked_from(
            keypair
                .sign(
                    schnorrkel::signing_context(REWARD_SIGNING_CONTEXT)
                        .bytes(signed_vote.vote.hash().as_ref()),
                )
                .to_bytes(),
        );

        assert_matches!(
            super::check_vote::<Test>(&signed_vote, false),
            Err(CheckVoteError::InvalidSolution(
                VerificationError::BadSolutionSignature(_, _)
            ))
        );
    });
}

#[test]
fn vote_correct_signature() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 2, 1);

        RecordsRoot::<Test>::insert(
            archived_segment.root_block.segment_index(),
            archived_segment.root_block.records_root(),
        );

        // Reset so that any solution works for votes
        crate::pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.voting_current = u64::MAX;
        });

        // Finally correct signature
        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            Subspace::current_slot() + 1,
            &Subspace::global_randomnesses().current,
            Subspace::salts().current,
            piece,
            1,
        );

        assert_ok!(super::check_vote::<Test>(&signed_vote, false));
    });
}

#[test]
fn vote_randomness_update() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        RecordsRoot::<Test>::insert(
            archived_segment.root_block.segment_index(),
            archived_segment.root_block.records_root(),
        );

        progress_to_block(&keypair, GlobalRandomnessUpdateInterval::get(), 1);

        // Reset so that any solution works for votes
        crate::pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.voting_current = u64::MAX;
        });

        // On the edge of change of global randomness, salt or solution range vote must be validated
        // with correct data (in this test case randomness just updated)
        let signed_vote = create_signed_vote(
            &keypair,
            GlobalRandomnessUpdateInterval::get(),
            frame_system::Pallet::<Test>::block_hash(GlobalRandomnessUpdateInterval::get() - 1),
            Subspace::current_slot() + 1,
            &Subspace::global_randomnesses().next.unwrap(),
            {
                let salts = Subspace::salts();
                if salts.switch_next_block {
                    salts.next.unwrap()
                } else {
                    salts.current
                }
            },
            piece,
            1,
        );

        assert_ok!(super::check_vote::<Test>(&signed_vote, false));
    });
}

#[test]
fn vote_salt_update() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        RecordsRoot::<Test>::insert(
            archived_segment.root_block.segment_index(),
            archived_segment.root_block.records_root(),
        );

        // Reset so that any solution works for votes
        crate::pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.voting_current = u64::MAX;
        });

        // Jump to the edge of the eon where salt update happens
        go_to_block(
            &keypair,
            u64::from(EonDuration::get() - 1),
            u64::from(
                (u64::from(Subspace::current_slot()) as u32 / EonDuration::get() + 1)
                    * EonDuration::get(),
            ),
            1,
        );

        // On the edge of change of global randomness, salt or solution range vote must be validated
        // with correct data (in this test case salt just updated)
        let signed_vote = create_signed_vote(
            &keypair,
            u64::from(EonDuration::get() - 1),
            frame_system::Pallet::<Test>::block_hash(u64::from(EonDuration::get() - 2)),
            Subspace::current_slot() + 1,
            &Subspace::global_randomnesses().current,
            {
                let salts = Subspace::salts();
                if salts.switch_next_block {
                    salts.next.unwrap()
                } else {
                    salts.current
                }
            },
            piece,
            1,
        );

        assert_ok!(super::check_vote::<Test>(&signed_vote, false));
    });
}

#[test]
fn vote_equivocation_current_block_plus_vote() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 2, 1);

        RecordsRoot::<Test>::insert(
            archived_segment.root_block.segment_index(),
            archived_segment.root_block.records_root(),
        );

        // Reset so that any solution works for votes
        crate::pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.voting_current = u64::MAX;
        });

        // Current block author + slot matches that of the vote
        let slot = Subspace::current_slot() + 1;
        let reward_address = 0;

        CurrentBlockAuthorInfo::<Test>::put((
            FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
            slot,
            reward_address,
        ));

        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            slot,
            &Subspace::global_randomnesses().current,
            Subspace::salts().current,
            piece,
            reward_address,
        );

        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::Equivocated
        );
    });
}

#[test]
fn vote_equivocation_parent_block_plus_vote() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 2, 1);

        RecordsRoot::<Test>::insert(
            archived_segment.root_block.segment_index(),
            archived_segment.root_block.records_root(),
        );

        // Reset so that any solution works for votes
        crate::pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.voting_current = u64::MAX;
        });

        // Parent block author + slot matches that of the vote

        let slot = Subspace::current_slot() + 1;
        let reward_address = 1;
        ParentBlockAuthorInfo::<Test>::put((
            FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
            slot,
        ));

        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            slot,
            &Subspace::global_randomnesses().current,
            Subspace::salts().current,
            piece,
            reward_address,
        );

        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::Equivocated
        );

        // Block author doesn't get reward after equivocation
        assert_matches!(Subspace::find_block_reward_address(), None);
    });
}

#[test]
fn vote_equivocation_current_voters_duplicate() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 2, 1);

        RecordsRoot::<Test>::insert(
            archived_segment.root_block.segment_index(),
            archived_segment.root_block.records_root(),
        );

        // Reset so that any solution works for votes
        crate::pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.voting_current = u64::MAX;
        });

        // Current block author + slot matches that of the vote
        let slot = Subspace::current_slot() + 1;
        let reward_address = 0;

        CurrentBlockVoters::<Test>::put({
            let mut map = BTreeMap::new();
            map.insert(
                (
                    FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
                    slot,
                ),
                reward_address,
            );
            map
        });

        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            slot,
            &Subspace::global_randomnesses().current,
            Subspace::salts().current,
            piece,
            reward_address,
        );

        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::Equivocated
        );

        // Voter doesn't get reward after equivocation
        assert_eq!(Subspace::find_voting_reward_addresses().len(), 0);
    });
}

#[test]
fn vote_equivocation_parent_voters_duplicate() {
    new_test_ext().execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();
        let piece = extract_piece(&keypair, &archived_segment, 0);

        progress_to_block(&keypair, 2, 1);

        RecordsRoot::<Test>::insert(
            archived_segment.root_block.segment_index(),
            archived_segment.root_block.records_root(),
        );

        // Reset so that any solution works for votes
        crate::pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.voting_current = u64::MAX;
        });

        // Current block author + slot matches that of the vote
        let slot = Subspace::current_slot() + 1;
        let reward_address = 1;

        ParentBlockVoters::<Test>::put({
            let mut map = BTreeMap::new();
            map.insert(
                (
                    FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
                    slot,
                ),
                reward_address,
            );
            map
        });

        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            slot,
            &Subspace::global_randomnesses().current,
            Subspace::salts().current,
            piece,
            reward_address,
        );

        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::Equivocated
        );
    });
}
