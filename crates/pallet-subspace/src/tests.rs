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
    allow_all_pot_extension, create_archived_segment, create_segment_header, create_signed_vote,
    go_to_block, new_test_ext, progress_to_block, BlockAuthoringDelay, RuntimeEvent, RuntimeOrigin,
    Subspace, System, Test, INITIAL_SOLUTION_RANGE, SLOT_PROBABILITY,
};
use crate::{
    pallet, AllowAuthoringByAnyone, Call, CheckVoteError, Config, CurrentBlockAuthorInfo,
    CurrentBlockVoters, EnableRewardsAt, ParentBlockAuthorInfo, ParentBlockVoters,
    PotSlotIterations, PotSlotIterationsValue, SegmentCommitment,
};
use frame_support::{assert_err, assert_ok};
use frame_system::{EventRecord, Phase};
use rand::prelude::*;
use schnorrkel::Keypair;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{PotExtension, SolutionRanges};
use sp_runtime::traits::BlockNumberProvider;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionSource, ValidTransaction,
};
use sp_runtime::DispatchError;
use std::assert_matches::assert_matches;
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::pieces::PieceOffset;
use subspace_core_primitives::pot::PotOutput;
use subspace_core_primitives::segments::SegmentIndex;
use subspace_core_primitives::{PublicKey, RewardSignature, SolutionRange};
use subspace_runtime_primitives::{FindBlockRewardAddress, FindVotingRewardAddresses};

#[test]
fn can_update_solution_range_on_era_change() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
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
        assert_ok!(Subspace::enable_solution_range_adjustment(
            RuntimeOrigin::root(),
            None,
            None
        ));

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
fn can_override_solution_range_update() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();

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
        let random_solution_range = rand::random();
        let random_voting_solution_range = random_solution_range + 5;
        assert_ok!(Subspace::enable_solution_range_adjustment(
            RuntimeOrigin::root(),
            Some(random_solution_range),
            Some(random_voting_solution_range),
        ));

        // Solution range must be updated instantly
        let updated_solution_ranges = Subspace::solution_ranges();
        assert_eq!(updated_solution_ranges.current, random_solution_range);
        assert_eq!(
            updated_solution_ranges.voting_current,
            random_voting_solution_range
        );

        // Era edge
        progress_to_block(&keypair, <Test as Config>::EraDuration::get().into(), 1);
        // Next solution range should be updated to the same value as current due to override
        let updated_solution_ranges = Subspace::solution_ranges();
        assert_eq!(updated_solution_ranges.current, random_solution_range);
        assert_eq!(
            updated_solution_ranges.voting_current,
            random_voting_solution_range
        );
        assert_eq!(updated_solution_ranges.next, Some(random_solution_range));
        assert_eq!(
            updated_solution_ranges.voting_next,
            Some(random_voting_solution_range)
        );
    })
}

#[test]
fn solution_range_should_not_update_when_disabled() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
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
fn store_segment_header_works() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();

        progress_to_block(&keypair, 1, 1);

        let segment_header = create_segment_header(SegmentIndex::ZERO);

        Subspace::store_segment_headers(RuntimeOrigin::none(), vec![segment_header]).unwrap();
        assert_eq!(
            System::events(),
            vec![EventRecord {
                phase: Phase::Initialization,
                event: RuntimeEvent::Subspace(crate::Event::SegmentHeaderStored { segment_header }),
                topics: vec![],
            }]
        );
    });
}

#[test]
fn store_segment_header_validate_unsigned_prevents_duplicates() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();

        progress_to_block(&keypair, 1, 1);

        let segment_header = create_segment_header(SegmentIndex::ZERO);

        let inner = Call::store_segment_headers {
            segment_headers: vec![segment_header],
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
        Subspace::store_segment_headers(RuntimeOrigin::none(), vec![segment_header]).unwrap();

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

        let inner2 = Call::store_segment_headers {
            segment_headers: vec![
                create_segment_header(SegmentIndex::ONE),
                create_segment_header(SegmentIndex::ONE),
            ],
        };

        // Same segment header can't be included twice even in the same extrinsic
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
fn vote_after_genesis() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        // Can't submit vote right after genesis block
        let signed_vote = create_signed_vote(
            &keypair,
            0,
            <Test as frame_system::Config>::Hash::default(),
            Subspace::current_slot() + 1,
            Default::default(),
            Default::default(),
            &archived_segment.pieces,
            1,
            SolutionRange::MIN,
            SolutionRange::MAX,
        );

        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::UnexpectedBeforeHeightTwo
        );
    });
}

#[test]
fn vote_too_low_height() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        progress_to_block(&keypair, 1, 1);

        // Can't submit vote with height lower than 2

        for height in 0..2 {
            let signed_vote = create_signed_vote(
                &keypair,
                height,
                <Test as frame_system::Config>::Hash::default(),
                Subspace::current_slot() + 1,
                Default::default(),
                Default::default(),
                &archived_segment.pieces,
                1,
                SolutionRange::MIN,
                SolutionRange::MAX,
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
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        progress_to_block(&keypair, 4, 1);

        // Height must be either the same as current block or older by one (this tests future vote)
        {
            let signed_vote = create_signed_vote(
                &keypair,
                5,
                <Test as frame_system::Config>::Hash::default(),
                Subspace::current_slot() + 1,
                Default::default(),
                Default::default(),
                &archived_segment.pieces,
                1,
                SolutionRange::MIN,
                SolutionRange::MAX,
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
                Default::default(),
                Default::default(),
                &archived_segment.pieces,
                1,
                SolutionRange::MIN,
                SolutionRange::MAX,
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
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        progress_to_block(&keypair, 2, 1);

        // Vote must point to real parent hash
        let signed_vote = create_signed_vote(
            &keypair,
            2,
            <Test as frame_system::Config>::Hash::default(),
            Subspace::current_slot() + 1,
            Default::default(),
            Default::default(),
            &archived_segment.pieces,
            1,
            SolutionRange::MIN,
            SolutionRange::MAX,
        );

        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::IncorrectParentHash
        );
    });
}

#[test]
fn vote_past_future_slot() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        SegmentCommitment::<Test>::insert(
            archived_segment.segment_header.segment_index(),
            archived_segment.segment_header.segment_commitment(),
        );

        // Reset so that any solution works for votes
        pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.current = u64::MIN;
            solution_ranges.voting_current = u64::MAX;
        });

        progress_to_block(&keypair, 3, 1);

        // Vote slot must be after slot of the parent block
        {
            let signed_vote = create_signed_vote(
                &keypair,
                3,
                frame_system::Pallet::<Test>::block_hash(2),
                2.into(),
                Default::default(),
                Default::default(),
                &archived_segment.pieces,
                1,
                pallet::SolutionRanges::<Test>::get().current,
                pallet::SolutionRanges::<Test>::get().voting_current,
            );

            assert_err!(
                super::check_vote::<Test>(&signed_vote, false),
                CheckVoteError::SlotInThePast
            );
            assert_err!(
                super::check_vote::<Test>(&signed_vote, true),
                CheckVoteError::SlotInThePast
            );
        }

        // Vote slot must be before the slot of the new block (pre-dispatch)
        {
            let signed_vote = create_signed_vote(
                &keypair,
                3,
                frame_system::Pallet::<Test>::block_hash(2),
                4.into(),
                Default::default(),
                Default::default(),
                &archived_segment.pieces,
                1,
                pallet::SolutionRanges::<Test>::get().current,
                pallet::SolutionRanges::<Test>::get().voting_current,
            );

            assert_err!(
                super::check_vote::<Test>(&signed_vote, true),
                CheckVoteError::SlotInTheFuture
            );
        }

        // Slot is in the past comparing to current block, but it is built on top of older block and
        // in that context it is valid
        {
            let keypair = Keypair::generate();

            let signed_vote = create_signed_vote(
                &keypair,
                2,
                frame_system::Pallet::<Test>::block_hash(1),
                2.into(),
                Default::default(),
                Default::default(),
                &archived_segment.pieces,
                1,
                pallet::SolutionRanges::<Test>::get().current,
                pallet::SolutionRanges::<Test>::get().voting_current,
            );

            assert_ok!(super::check_vote::<Test>(&signed_vote, false));
            assert_ok!(super::check_vote::<Test>(&signed_vote, true));
        }
    });
}

#[test]
fn vote_same_slot() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let block_keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        // Move to the block 3, but time slot 4, but in two time slots
        go_to_block(&block_keypair, 3, 4, 1);

        SegmentCommitment::<Test>::insert(
            archived_segment.segment_header.segment_index(),
            archived_segment.segment_header.segment_commitment(),
        );

        // Reset so that any solution works for votes
        pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.current = u64::MIN;
            solution_ranges.voting_current = u64::MAX;
        });

        // Same time slot in the vote as in the block is fine if height is the same (pre-dispatch)
        {
            let keypair = Keypair::generate();
            let signed_vote = create_signed_vote(
                &keypair,
                3,
                frame_system::Pallet::<Test>::block_hash(2),
                Subspace::current_slot(),
                Default::default(),
                Default::default(),
                &archived_segment.pieces,
                1,
                pallet::SolutionRanges::<Test>::get().current,
                pallet::SolutionRanges::<Test>::get().voting_current,
            );

            assert_ok!(super::check_vote::<Test>(&signed_vote, true));
        }

        // Same time slot in the vote as in the block is not fine if height is different though
        // (pre-dispatch)
        {
            let keypair = Keypair::generate();
            let signed_vote = create_signed_vote(
                &keypair,
                2,
                frame_system::Pallet::<Test>::block_hash(1),
                Subspace::current_slot(),
                Default::default(),
                Default::default(),
                &archived_segment.pieces,
                1,
                pallet::SolutionRanges::<Test>::get().current,
                pallet::SolutionRanges::<Test>::get().voting_current,
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
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        progress_to_block(&keypair, 2, 1);

        // Vote must be signed correctly
        let mut signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            Subspace::current_slot() + 1,
            Default::default(),
            Default::default(),
            &archived_segment.pieces,
            1,
            SolutionRange::MIN,
            SolutionRange::MAX,
        );

        signed_vote.signature = RewardSignature::from(rand::random::<[u8; 64]>());

        assert_matches!(
            super::check_vote::<Test>(&signed_vote, false),
            Err(CheckVoteError::BadRewardSignature(_))
        );
    });
}

#[test]
fn vote_unknown_segment_commitment() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        progress_to_block(&keypair, 2, 1);

        // There must be segment commitment corresponding to the piece used
        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            Subspace::current_slot() + 1,
            Default::default(),
            Default::default(),
            &archived_segment.pieces,
            1,
            SolutionRange::MIN,
            SolutionRange::MAX,
        );

        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::UnknownSegmentCommitment
        );
    });
}

#[test]
fn vote_outside_of_solution_range() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        progress_to_block(&keypair, 2, 1);

        SegmentCommitment::<Test>::insert(
            archived_segment.segment_header.segment_index(),
            archived_segment.segment_header.segment_commitment(),
        );

        // Solution must be within solution range
        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            Subspace::current_slot() + 1,
            Default::default(),
            Default::default(),
            &archived_segment.pieces,
            1,
            SolutionRange::MIN,
            SolutionRange::MAX,
        );

        let result = super::check_vote::<Test>(&signed_vote, false);
        assert_matches!(result, Err(CheckVoteError::InvalidSolution(_)));
        if let Err(CheckVoteError::InvalidSolution(error)) = result {
            assert!(error.contains("is outside of solution range"));
        }
    });
}

#[test]
fn vote_solution_quality_too_high() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        progress_to_block(&keypair, 2, 1);

        SegmentCommitment::<Test>::insert(
            archived_segment.segment_header.segment_index(),
            archived_segment.segment_header.segment_commitment(),
        );

        // Reset so that any solution works for votes, but also block solution range is almost the
        // same, resulting in quality being too high
        pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.current = u64::MAX / 5;
            solution_ranges.voting_current = u64::MAX;
        });

        {
            let signed_vote = create_signed_vote(
                &keypair,
                2,
                frame_system::Pallet::<Test>::block_hash(1),
                Subspace::current_slot() + 1,
                Default::default(),
                Default::default(),
                &archived_segment.pieces,
                1,
                pallet::SolutionRanges::<Test>::get().current,
                pallet::SolutionRanges::<Test>::get().voting_current,
            );

            // Good solution quality
            assert_ok!(super::check_vote::<Test>(&signed_vote, false));
        }

        {
            let signed_vote = create_signed_vote(
                &keypair,
                2,
                frame_system::Pallet::<Test>::block_hash(1),
                Subspace::current_slot() + 1,
                Default::default(),
                Default::default(),
                &archived_segment.pieces,
                1,
                SolutionRange::MIN,
                // Create vote for block level of quality
                pallet::SolutionRanges::<Test>::get().current,
            );

            // Quality is too high
            assert_matches!(
                super::check_vote::<Test>(&signed_vote, false),
                Err(CheckVoteError::QualityTooHigh)
            );
        }
    });
}

#[test]
fn vote_invalid_proof_of_time() {
    let correct_proofs_of_time = Arc::new(Mutex::new(Vec::new()));
    let pot_extension = PotExtension::new(Box::new({
        let correct_proofs_of_time = Arc::clone(&correct_proofs_of_time);
        move |parent_hash, slot, proof_of_time, quick_verification| {
            correct_proofs_of_time.lock().unwrap().contains(&(
                parent_hash,
                slot,
                proof_of_time,
                quick_verification,
            ))
        }
    }));
    new_test_ext(pot_extension).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        progress_to_block(&keypair, 2, 1);

        SegmentCommitment::<Test>::insert(
            archived_segment.segment_header.segment_index(),
            archived_segment.segment_header.segment_commitment(),
        );

        // Reset so that any solution works for votes
        pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.current = u64::MIN;
            solution_ranges.voting_current = u64::MAX;
        });

        let current_block_number = frame_system::Pallet::<Test>::current_block_number();
        let block_one_hash = frame_system::Pallet::<Test>::block_hash(1);
        let slot = Subspace::current_slot();

        let mut test_proof_of_time = PotOutput::default();
        rand::thread_rng().fill(test_proof_of_time.as_mut_slice());
        let mut test_future_proof_of_time = PotOutput::default();
        rand::thread_rng().fill(test_future_proof_of_time.as_mut_slice());

        // Proof of time not valid yet for votes before block is produced
        {
            let signed_vote = create_signed_vote(
                &keypair,
                current_block_number,
                block_one_hash,
                slot + 1,
                test_proof_of_time,
                Default::default(),
                &archived_segment.pieces,
                1,
                pallet::SolutionRanges::<Test>::get().current,
                pallet::SolutionRanges::<Test>::get().voting_current,
            );

            assert_err!(
                super::check_vote::<Test>(&signed_vote, false),
                CheckVoteError::InvalidProofOfTime
            );
        }

        correct_proofs_of_time.lock().unwrap().push((
            block_one_hash.into(),
            *slot + 1,
            test_proof_of_time,
            true,
        ));

        // Proof of time is valid for votes before block is produced
        {
            let signed_vote = create_signed_vote(
                &keypair,
                current_block_number,
                block_one_hash,
                slot + 1,
                test_proof_of_time,
                Default::default(),
                &archived_segment.pieces,
                1,
                pallet::SolutionRanges::<Test>::get().current,
                pallet::SolutionRanges::<Test>::get().voting_current,
            );

            assert_ok!(super::check_vote::<Test>(&signed_vote, false));
        }

        // Proof of time not valid yet during pre-dispatch
        {
            let signed_vote = create_signed_vote(
                &keypair,
                current_block_number,
                block_one_hash,
                slot,
                test_proof_of_time,
                Default::default(),
                &archived_segment.pieces,
                1,
                pallet::SolutionRanges::<Test>::get().current,
                pallet::SolutionRanges::<Test>::get().voting_current,
            );

            assert_err!(
                super::check_vote::<Test>(&signed_vote, true),
                CheckVoteError::InvalidProofOfTime
            );
        }

        correct_proofs_of_time.lock().unwrap().push((
            block_one_hash.into(),
            *slot,
            test_proof_of_time,
            false,
        ));

        // Proof of time is valid during pre-dispatch, but not future proof of time yet
        {
            let signed_vote = create_signed_vote(
                &keypair,
                current_block_number,
                block_one_hash,
                slot,
                test_proof_of_time,
                Default::default(),
                &archived_segment.pieces,
                1,
                pallet::SolutionRanges::<Test>::get().current,
                pallet::SolutionRanges::<Test>::get().voting_current,
            );

            assert_err!(
                super::check_vote::<Test>(&signed_vote, true),
                CheckVoteError::InvalidFutureProofOfTime
            );
        }

        correct_proofs_of_time.lock().unwrap().push((
            block_one_hash.into(),
            *slot + BlockAuthoringDelay::get(),
            test_future_proof_of_time,
            false,
        ));

        // Both proof of time and future proof of time are valid during pre-dispatch
        {
            let signed_vote = create_signed_vote(
                &keypair,
                current_block_number,
                block_one_hash,
                slot,
                test_proof_of_time,
                test_future_proof_of_time,
                &archived_segment.pieces,
                1,
                pallet::SolutionRanges::<Test>::get().current,
                pallet::SolutionRanges::<Test>::get().voting_current,
            );

            assert_ok!(super::check_vote::<Test>(&signed_vote, true));
        }
    });
}

#[test]
fn vote_correct_signature() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        progress_to_block(&keypair, 2, 1);

        SegmentCommitment::<Test>::insert(
            archived_segment.segment_header.segment_index(),
            archived_segment.segment_header.segment_commitment(),
        );

        // Reset so that any solution works for votes
        pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.current = u64::MIN;
            solution_ranges.voting_current = u64::MAX;
        });

        // Finally correct signature
        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            Subspace::current_slot() + 1,
            Default::default(),
            Default::default(),
            &archived_segment.pieces,
            1,
            pallet::SolutionRanges::<Test>::get().current,
            pallet::SolutionRanges::<Test>::get().voting_current,
        );

        assert_ok!(super::check_vote::<Test>(&signed_vote, false));
    });
}

#[test]
fn vote_equivocation_current_block_plus_vote() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        progress_to_block(&keypair, 2, 1);

        SegmentCommitment::<Test>::insert(
            archived_segment.segment_header.segment_index(),
            archived_segment.segment_header.segment_commitment(),
        );

        // Reset so that any solution works for votes
        pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.current = u64::MIN;
            solution_ranges.voting_current = u64::MAX;
        });

        let slot = Subspace::current_slot() + 1;
        let reward_address = 0;

        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            slot,
            Default::default(),
            Default::default(),
            &archived_segment.pieces,
            reward_address,
            pallet::SolutionRanges::<Test>::get().current,
            pallet::SolutionRanges::<Test>::get().voting_current,
        );

        // Parent block author + sector index + chunk + slot matches that of the vote
        CurrentBlockAuthorInfo::<Test>::put((
            PublicKey::from(keypair.public.to_bytes()),
            signed_vote.vote.solution().sector_index,
            signed_vote.vote.solution().piece_offset,
            signed_vote.vote.solution().chunk,
            slot,
            Some(reward_address),
        ));

        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::Equivocated {
                slot,
                offender: PublicKey::from(keypair.public.to_bytes())
            }
        );

        // Block author doesn't get reward after equivocation
        assert_matches!(Subspace::find_block_reward_address(), None);
    });
}

#[test]
fn vote_equivocation_parent_block_plus_vote() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        progress_to_block(&keypair, 2, 1);

        SegmentCommitment::<Test>::insert(
            archived_segment.segment_header.segment_index(),
            archived_segment.segment_header.segment_commitment(),
        );

        // Reset so that any solution works for votes
        pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.current = u64::MIN;
            solution_ranges.voting_current = u64::MAX;
        });

        let slot = Subspace::current_slot();
        let reward_address = 1;

        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            slot,
            Default::default(),
            Default::default(),
            &archived_segment.pieces,
            reward_address,
            pallet::SolutionRanges::<Test>::get().current,
            pallet::SolutionRanges::<Test>::get().voting_current,
        );

        // Parent block author + sector index + chunk + slot matches that of the vote
        ParentBlockAuthorInfo::<Test>::put((
            PublicKey::from(keypair.public.to_bytes()),
            signed_vote.vote.solution().sector_index,
            signed_vote.vote.solution().piece_offset,
            signed_vote.vote.solution().chunk,
            slot,
        ));

        assert_err!(
            super::check_vote::<Test>(&signed_vote, true),
            CheckVoteError::Equivocated {
                slot,
                offender: PublicKey::from(keypair.public.to_bytes())
            }
        );

        Subspace::pre_dispatch_vote(&signed_vote).unwrap();

        // Block author doesn't get reward after equivocation
        assert_matches!(Subspace::find_block_reward_address(), None);
    });
}

#[test]
fn vote_equivocation_current_voters_duplicate() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let archived_segment = create_archived_segment();

        progress_to_block(&Keypair::generate(), 2, 1);

        SegmentCommitment::<Test>::insert(
            archived_segment.segment_header.segment_index(),
            archived_segment.segment_header.segment_commitment(),
        );

        // Reset so that any solution works for votes
        pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.current = u64::MIN;
            solution_ranges.voting_current = u64::MAX;
        });

        // Current block author + slot matches that of the vote
        let voter_keypair = Keypair::generate();
        let slot = Subspace::current_slot();
        let reward_address = 0;

        let signed_vote = create_signed_vote(
            &voter_keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            slot,
            Default::default(),
            Default::default(),
            &archived_segment.pieces,
            reward_address,
            pallet::SolutionRanges::<Test>::get().current,
            pallet::SolutionRanges::<Test>::get().voting_current,
        );

        CurrentBlockVoters::<Test>::put({
            let mut map = BTreeMap::new();
            map.insert(
                (
                    PublicKey::from(voter_keypair.public.to_bytes()),
                    signed_vote.vote.solution().sector_index,
                    signed_vote.vote.solution().piece_offset,
                    signed_vote.vote.solution().chunk,
                    slot,
                ),
                (Some(reward_address), signed_vote.signature),
            );
            map
        });

        // Identical vote submitted twice leads to duplicate error
        assert_err!(
            super::check_vote::<Test>(&signed_vote, true),
            CheckVoteError::DuplicateVote
        );

        CurrentBlockVoters::<Test>::put({
            let mut map = BTreeMap::new();
            map.insert(
                (
                    PublicKey::from(voter_keypair.public.to_bytes()),
                    signed_vote.vote.solution().sector_index,
                    signed_vote.vote.solution().piece_offset,
                    signed_vote.vote.solution().chunk,
                    slot,
                ),
                (Some(reward_address), RewardSignature::from([0; 64])),
            );
            map
        });

        // Different vote for the same sector index and time slot leads to equivocation
        Subspace::pre_dispatch_vote(&signed_vote).unwrap();

        // Voter doesn't get reward after equivocation
        assert_eq!(Subspace::find_voting_reward_addresses().len(), 0);
    });
}

#[test]
fn vote_equivocation_parent_voters_duplicate() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();
        let archived_segment = create_archived_segment();

        progress_to_block(&keypair, 2, 1);

        SegmentCommitment::<Test>::insert(
            archived_segment.segment_header.segment_index(),
            archived_segment.segment_header.segment_commitment(),
        );

        // Reset so that any solution works for votes
        pallet::SolutionRanges::<Test>::mutate(|solution_ranges| {
            solution_ranges.current = u64::MIN;
            solution_ranges.voting_current = u64::MAX;
        });

        // Current block author + sector index + slot matches that of the vote
        let slot = Subspace::current_slot() + 1;
        let reward_address = 1;

        let signed_vote = create_signed_vote(
            &keypair,
            2,
            frame_system::Pallet::<Test>::block_hash(1),
            slot,
            Default::default(),
            Default::default(),
            &archived_segment.pieces,
            reward_address,
            pallet::SolutionRanges::<Test>::get().current,
            pallet::SolutionRanges::<Test>::get().voting_current,
        );

        ParentBlockVoters::<Test>::put({
            let mut map = BTreeMap::new();
            map.insert(
                (
                    PublicKey::from(keypair.public.to_bytes()),
                    signed_vote.vote.solution().sector_index,
                    signed_vote.vote.solution().piece_offset,
                    signed_vote.vote.solution().chunk,
                    slot,
                ),
                (Some(reward_address), signed_vote.signature),
            );
            map
        });

        // Identical vote submitted twice leads to duplicate error
        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::DuplicateVote
        );

        ParentBlockVoters::<Test>::put({
            let mut map = BTreeMap::new();
            map.insert(
                (
                    PublicKey::from(keypair.public.to_bytes()),
                    signed_vote.vote.solution().sector_index,
                    signed_vote.vote.solution().piece_offset,
                    signed_vote.vote.solution().chunk,
                    slot,
                ),
                (Some(reward_address), RewardSignature::from([0; 64])),
            );
            map
        });

        // Different vote for the same time slot leads to equivocation
        assert_err!(
            super::check_vote::<Test>(&signed_vote, false),
            CheckVoteError::Equivocated {
                slot,
                offender: PublicKey::from(keypair.public.to_bytes())
            }
        );

        // Voter doesn't get reward after equivocation
        assert_eq!(Subspace::find_voting_reward_addresses().len(), 0);
    });
}

// TODO: Test for `CheckVoteError::InvalidHistorySize`

#[test]
fn enabling_block_rewards_works() {
    fn set_block_rewards() {
        CurrentBlockAuthorInfo::<Test>::put((
            PublicKey::from(Keypair::generate().public.to_bytes()),
            0,
            PieceOffset::ZERO,
            Scalar::default(),
            Subspace::current_slot(),
            Some(1),
        ));
        CurrentBlockVoters::<Test>::put({
            let mut map = BTreeMap::new();
            map.insert(
                (
                    PublicKey::from(Keypair::generate().public.to_bytes()),
                    0,
                    PieceOffset::ZERO,
                    Scalar::default(),
                    Subspace::current_slot(),
                ),
                (Some(2), RewardSignature::from([0; 64])),
            );
            map
        });
    }
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair = Keypair::generate();

        progress_to_block(&keypair, 1, 1);

        set_block_rewards();

        // Rewards are enabled by default
        assert_matches!(Subspace::find_block_reward_address(), Some(1));
        assert_eq!(Subspace::find_voting_reward_addresses(), vec![2]);

        // Disable rewards
        crate::EnableRewards::<Test>::take();
        // No rewards
        assert_matches!(Subspace::find_block_reward_address(), None);
        assert_eq!(Subspace::find_voting_reward_addresses().len(), 0);

        // Enable since next block only rewards
        assert_ok!(Subspace::enable_rewards_at(
            RuntimeOrigin::root(),
            EnableRewardsAt::Height(Some(
                frame_system::Pallet::<Test>::current_block_number() + 1,
            )),
        ));
        // No rewards yet
        assert_matches!(Subspace::find_block_reward_address(), None);
        assert_eq!(Subspace::find_voting_reward_addresses().len(), 0);

        // Move to the next block
        progress_to_block(
            &keypair,
            frame_system::Pallet::<Test>::current_block_number() + 1,
            1,
        );
        set_block_rewards();
        // Rewards kick in
        assert_matches!(Subspace::find_block_reward_address(), Some(1));
        assert_eq!(Subspace::find_voting_reward_addresses(), vec![2]);
    });
}

#[test]
fn enabling_block_rewards_at_solution_range_works() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
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
        assert_ok!(Subspace::enable_solution_range_adjustment(
            RuntimeOrigin::root(),
            None,
            None
        ));
        // Disable rewards
        crate::EnableRewards::<Test>::take();
        // Enable rewards below current solution range
        assert_ok!(Subspace::enable_rewards_at(
            RuntimeOrigin::root(),
            EnableRewardsAt::SolutionRange(INITIAL_SOLUTION_RANGE - 1),
        ));

        // Progress to almost era edge
        progress_to_block(&keypair, 3, 1);
        // No solution range update
        assert_eq!(Subspace::solution_ranges(), initial_solution_ranges);
        // Rewards are not enabled
        assert_eq!(crate::EnableRewards::<Test>::get(), None);

        // Era edge
        progress_to_block(&keypair, 4, 1);
        // Next solution range should be updated, but current is still unchanged
        let updated_solution_ranges = Subspace::solution_ranges();
        assert_eq!(
            updated_solution_ranges.current,
            initial_solution_ranges.current
        );
        assert!(updated_solution_ranges.next.is_some());
        // Rewards will be enabled in the next block
        assert_eq!(
            crate::EnableRewards::<Test>::get(),
            Some(frame_system::Pallet::<Test>::current_block_number() + 1)
        );
    })
}

#[test]
fn allow_authoring_by_anyone_works() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();

        // By default block authoring is allowed by the pallet
        progress_to_block(
            &keypair1,
            frame_system::Pallet::<Test>::current_block_number() + 1,
            1,
        );
        progress_to_block(
            &keypair2,
            frame_system::Pallet::<Test>::current_block_number() + 1,
            1,
        );

        // Disable default behavior
        AllowAuthoringByAnyone::<Test>::put(false);
        // First author can produce blocks
        progress_to_block(
            &keypair1,
            frame_system::Pallet::<Test>::current_block_number() + 1,
            1,
        );
        progress_to_block(
            &keypair1,
            frame_system::Pallet::<Test>::current_block_number() + 1,
            1,
        );
        // However authoring with a different public key panics (client error)
        assert!(std::panic::catch_unwind(|| {
            progress_to_block(
                &keypair2,
                frame_system::Pallet::<Test>::current_block_number() + 1,
                1,
            );
        })
        .is_err());

        // Unlock authoring by anyone
        assert_err!(
            Subspace::enable_authoring_by_anyone(RuntimeOrigin::signed(1)),
            DispatchError::BadOrigin
        );
        Subspace::enable_authoring_by_anyone(RuntimeOrigin::root()).unwrap();
        // Both must be able to create blocks again
        progress_to_block(
            &keypair1,
            frame_system::Pallet::<Test>::current_block_number() + 1,
            1,
        );
        progress_to_block(
            &keypair2,
            frame_system::Pallet::<Test>::current_block_number() + 1,
            1,
        );
    });
}

#[test]
fn set_pot_slot_iterations_works() {
    new_test_ext(allow_all_pot_extension()).execute_with(|| {
        PotSlotIterations::<Test>::put(PotSlotIterationsValue {
            slot_iterations: NonZeroU32::new(100_000_000).unwrap(),
            update: None,
        });

        // Only root can do this
        assert_err!(
            Subspace::set_pot_slot_iterations(
                RuntimeOrigin::signed(1),
                NonZeroU32::new(100_000_000).unwrap()
            ),
            DispatchError::BadOrigin
        );

        // Must increase
        assert_matches!(
            Subspace::set_pot_slot_iterations(
                RuntimeOrigin::root(),
                NonZeroU32::new(100_000_000).unwrap()
            ),
            Err(DispatchError::Module(_))
        );

        // Must be multiple of PotCheckpoints iterations times two
        assert_matches!(
            Subspace::set_pot_slot_iterations(
                RuntimeOrigin::root(),
                NonZeroU32::new(100_000_001).unwrap()
            ),
            Err(DispatchError::Module(_))
        );

        // Now it succeeds
        Subspace::set_pot_slot_iterations(
            RuntimeOrigin::root(),
            NonZeroU32::new(110_000_000).unwrap(),
        )
        .unwrap();

        // Subsequent calls succeed too
        Subspace::set_pot_slot_iterations(
            RuntimeOrigin::root(),
            NonZeroU32::new(120_000_000).unwrap(),
        )
        .unwrap();

        // Unless update is already scheduled to be applied
        pallet::PotSlotIterations::<Test>::mutate(|pot_slot_iterations| {
            pot_slot_iterations
                .as_mut()
                .unwrap()
                .update
                .as_mut()
                .unwrap()
                .target_slot
                .replace(Slot::from(1));
        });
        assert_matches!(
            Subspace::set_pot_slot_iterations(
                RuntimeOrigin::root(),
                NonZeroU32::new(130_000_000).unwrap()
            ),
            Err(DispatchError::Module(_))
        );
    });
}
