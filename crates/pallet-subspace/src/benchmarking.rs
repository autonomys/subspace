//! Benchmarking for `pallet-subspace`.

#[cfg(not(feature = "std"))]
extern crate alloc;

use frame_benchmarking::v2::*;

#[benchmarks]
mod benchmarks {
    use crate::{
        AllowAuthoringByAnyone, Call, Config, EnableRewards, EnableRewardsAt,
        NextSolutionRangeOverride, Pallet, PotSlotIterations, PotSlotIterationsUpdate,
        PotSlotIterationsValue, SegmentCommitment, ShouldAdjustSolutionRange, SolutionRanges,
    };
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    use frame_benchmarking::v2::*;
    use frame_support::traits::Get;
    use frame_system::pallet_prelude::*;
    use frame_system::{Pallet as System, RawOrigin};
    use sp_consensus_subspace::{SignedVote, Vote};
    use sp_std::boxed::Box;
    use sp_std::num::NonZeroU32;
    use subspace_core_primitives::hashes::Blake3Hash;
    use subspace_core_primitives::pot::{PotCheckpoints, PotOutput};
    use subspace_core_primitives::segments::{
        ArchivedBlockProgress, LastArchivedBlock, SegmentHeader, SegmentIndex,
    };
    use subspace_core_primitives::solutions::{RewardSignature, Solution, SolutionRange};
    use subspace_core_primitives::PublicKey;

    const SEED: u32 = 0;

    #[benchmark]
    fn store_segment_headers(x: Linear<1, 20>) {
        let segment_headers: Vec<SegmentHeader> = (0..x as u64)
            .map(|i| create_segment_header(i.into()))
            .collect();

        #[extrinsic_call]
        _(RawOrigin::None, segment_headers);

        assert_eq!(SegmentCommitment::<T>::count(), x);
    }

    /// Benchmark `enable_solution_range_adjustment` extrinsic with the worst possible conditions,
    /// where both `SolutionRanges` and `NextSolutionRangeOverride` are overridden.
    #[benchmark]
    fn enable_solution_range_adjustment() {
        let solution_range_override: SolutionRange = 10;
        let voting_solution_range_override =
            solution_range_override.saturating_mul(u64::from(T::ExpectedVotesPerBlock::get()) + 1);

        // Set `voting_solution_range_override` parameter to None to compute the `voting_solution_range`
        // in the call
        #[extrinsic_call]
        _(RawOrigin::Root, Some(solution_range_override), None);

        assert!(ShouldAdjustSolutionRange::<T>::get());

        let solution_range = SolutionRanges::<T>::get();
        assert_eq!(solution_range.current, solution_range_override);
        assert_eq!(
            solution_range.voting_current,
            voting_solution_range_override
        );

        let next_solution_range_override = NextSolutionRangeOverride::<T>::get()
            .expect("NextSolutionRangeOverride should be filled");
        assert_eq!(
            next_solution_range_override.solution_range,
            solution_range_override
        );
        assert_eq!(
            next_solution_range_override.voting_solution_range,
            voting_solution_range_override
        );
    }

    #[benchmark]
    fn vote() {
        // Construct a dummy vote which is invalid but it is okay because the vote is not validated
        // during the call
        let unsigned_vote: Vote<BlockNumberFor<T>, T::Hash, T::AccountId> = Vote::V0 {
            height: System::<T>::block_number(),
            parent_hash: System::<T>::parent_hash(),
            slot: Pallet::<T>::current_slot(),
            solution: Solution::genesis_solution(
                PublicKey::from([1u8; 32]),
                account("user1", 1, SEED),
            ),
            proof_of_time: PotOutput::default(),
            future_proof_of_time: PotOutput::default(),
        };
        let signature = RewardSignature::from([2u8; 64]);
        let signed_vote = SignedVote {
            vote: unsigned_vote,
            signature,
        };

        #[extrinsic_call]
        _(RawOrigin::None, Box::new(signed_vote));
    }

    #[benchmark]
    fn enable_rewards_at() {
        EnableRewards::<T>::take();

        #[extrinsic_call]
        _(
            RawOrigin::Root,
            EnableRewardsAt::Height(Some(100u32.into())),
        );

        assert_eq!(EnableRewards::<T>::get(), Some(100u32.into()));
    }

    #[benchmark]
    fn enable_authoring_by_anyone() {
        #[extrinsic_call]
        _(RawOrigin::Root);

        assert!(AllowAuthoringByAnyone::<T>::get());
        assert!(Pallet::<T>::root_plot_public_key().is_none());
    }

    #[benchmark]
    fn set_pot_slot_iterations() {
        let slot_iterations = NonZeroU32::new(PotCheckpoints::NUM_CHECKPOINTS.get() as u32 * 2)
            .expect("NUM_CHECKPOINTS is non-zero");
        let next_slot_iterations = slot_iterations
            .checked_mul(NonZeroU32::new(2).expect("2 is non-zero"))
            .expect("Not overflow");

        PotSlotIterations::<T>::put(PotSlotIterationsValue {
            slot_iterations,
            update: None,
        });

        #[extrinsic_call]
        _(RawOrigin::Root, next_slot_iterations);

        assert_eq!(
            PotSlotIterations::<T>::get(),
            Some(PotSlotIterationsValue {
                slot_iterations,
                update: Some(PotSlotIterationsUpdate {
                    target_slot: None,
                    slot_iterations: next_slot_iterations,
                }),
            })
        );
    }

    // Create a dummy segment header
    fn create_segment_header(segment_index: SegmentIndex) -> SegmentHeader {
        SegmentHeader::V0 {
            segment_index,
            segment_commitment: subspace_core_primitives::segments::SegmentCommitment::default(),
            prev_segment_header_hash: Blake3Hash::default(),
            last_archived_block: LastArchivedBlock {
                number: 0,
                archived_progress: ArchivedBlockProgress::Complete,
            },
        }
    }

    impl_benchmark_test_suite!(
        Pallet,
        crate::mock::new_test_ext(crate::mock::allow_all_pot_extension()),
        crate::mock::Test
    );
}
