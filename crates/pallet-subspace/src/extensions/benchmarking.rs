//! Benchmarks for Subspace extension

use crate::extensions::SubspaceExtension;
use crate::pallet::{
    BlockSlots, CurrentBlockAuthorInfo, CurrentBlockVoters, ParentVoteVerificationData,
    SegmentCommitment as SubspaceSegmentCommitment, SolutionRanges,
};
use crate::{Config, Pallet as Subspace, VoteVerificationData};
use frame_benchmarking::v2::*;
use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use frame_system::pallet_prelude::RuntimeCallFor;
use parity_scale_codec::{Decode, Encode};
use scale_info::prelude::fmt;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::SignedVote;
use sp_runtime::Weight;
use sp_runtime::traits::{AsSystemOriginSigner, Dispatchable, NumberFor};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidityError, UnknownTransaction,
    ValidTransaction,
};
use sp_std::collections::btree_map::BTreeMap;
use subspace_core_primitives::pieces::PieceOffset;
use subspace_core_primitives::sectors::SectorIndex;
use subspace_core_primitives::segments::{SegmentCommitment, SegmentIndex};
use subspace_core_primitives::solutions::RewardSignature;
use subspace_core_primitives::{PublicKey, ScalarBytes};

/// Hard-coded data used to benchmark check_vote
#[derive(Encode, Decode)]
struct VoteData<T: frame_system::Config> {
    pub segment_index: SegmentIndex,
    pub segment_commitment: SegmentCommitment,
    pub signed_vote: SignedVote<NumberFor<T::Block>, T::Hash, T::AccountId>,
    pub public_key: PublicKey,
    pub parent_block_data: (NumberFor<T::Block>, T::Hash),
    pub current_block_number: NumberFor<T::Block>,
    pub vote_verification_data: VoteVerificationData,
    pub current_slot: Slot,
    pub reward_address: T::AccountId,
}

pub struct Pallet<T: Config>(Subspace<T>);

#[allow(clippy::multiple_bound_locations)]
#[benchmarks(where
	T: Send + Sync + scale_info::TypeInfo + fmt::Debug,
    RuntimeCallFor<T>: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
	<RuntimeCallFor<T> as Dispatchable>::RuntimeOrigin: AsSystemOriginSigner<<T as frame_system::Config>::AccountId> + Clone)
]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn vote() {
        let VoteData {
            segment_index,
            segment_commitment,
            signed_vote,
            public_key: _,
            parent_block_data,
            current_block_number,
            vote_verification_data,
            current_slot,
            reward_address: _,
        } = VoteData::<T>::decode(&mut include_bytes!("./fixtures/vote.data").as_slice()).unwrap();

        SubspaceSegmentCommitment::<T>::insert(segment_index, segment_commitment);

        // Reset so that any solution works for votes
        SolutionRanges::<T>::mutate(|solution_ranges| {
            solution_ranges.current = u64::MIN;
            solution_ranges.voting_current = u64::MAX;
        });

        frame_system::Pallet::<T>::set_block_number(current_block_number);
        frame_system::pallet::BlockHash::<T>::insert(parent_block_data.0, parent_block_data.1);
        ParentVoteVerificationData::<T>::put(vote_verification_data);
        BlockSlots::<T>::mutate(|block_slots| {
            block_slots
                .try_insert(current_block_number, current_slot)
                .expect("one entry just removed before inserting; qed");
        });
        CurrentBlockVoters::<T>::put(BTreeMap::<
            (PublicKey, SectorIndex, PieceOffset, ScalarBytes, Slot),
            (Option<T::AccountId>, RewardSignature),
        >::default());

        let result;
        #[block]
        {
            result =
                SubspaceExtension::<T>::do_check_vote(&signed_vote, TransactionSource::InBlock);
        };

        handle_error(result);
    }

    #[benchmark]
    fn vote_with_equivocation() {
        let VoteData {
            segment_index,
            segment_commitment,
            signed_vote,
            public_key,
            parent_block_data,
            current_block_number,
            vote_verification_data,
            current_slot,
            reward_address,
        } = VoteData::<T>::decode(&mut include_bytes!("./fixtures/vote.data").as_slice()).unwrap();

        SubspaceSegmentCommitment::<T>::insert(segment_index, segment_commitment);

        // Reset so that any solution works for votes
        SolutionRanges::<T>::mutate(|solution_ranges| {
            solution_ranges.current = u64::MIN;
            solution_ranges.voting_current = u64::MAX;
        });

        frame_system::Pallet::<T>::set_block_number(current_block_number);
        frame_system::pallet::BlockHash::<T>::insert(parent_block_data.0, parent_block_data.1);
        ParentVoteVerificationData::<T>::put(vote_verification_data);
        BlockSlots::<T>::mutate(|block_slots| {
            block_slots
                .try_insert(current_block_number, current_slot)
                .expect("one entry just removed before inserting; qed");
        });
        CurrentBlockVoters::<T>::put(BTreeMap::<
            (PublicKey, SectorIndex, PieceOffset, ScalarBytes, Slot),
            (Option<T::AccountId>, RewardSignature),
        >::default());

        CurrentBlockAuthorInfo::<T>::put((
            public_key,
            signed_vote.vote.solution().sector_index,
            signed_vote.vote.solution().piece_offset,
            signed_vote.vote.solution().chunk,
            *signed_vote.vote.slot(),
            Some(reward_address),
        ));

        let result;
        #[block]
        {
            result =
                SubspaceExtension::<T>::do_check_vote(&signed_vote, TransactionSource::InBlock);
        };

        handle_error(result);
    }

    impl_benchmark_test_suite!(
        Pallet,
        crate::mock::new_test_ext(crate::mock::allow_all_pot_extension()),
        crate::mock::Test
    );
}

fn handle_error(result: Result<(ValidTransaction, Weight), TransactionValidityError>) {
    // This exhaustive match is required because the production runtime does not generate debug impls.
    if let Err(e) = result {
        match e {
            TransactionValidityError::Invalid(e) => match e {
                InvalidTransaction::Call => {
                    log::error!("Invalid transaction: Call");
                }
                InvalidTransaction::Payment => {
                    log::error!("Invalid transaction: Payment");
                    panic!("Invalid transaction: Payment");
                }
                InvalidTransaction::Future => {
                    log::error!("Invalid transaction: Future");
                }
                InvalidTransaction::Stale => {
                    log::error!("Invalid transaction: Stale");
                }
                InvalidTransaction::BadProof => {
                    log::error!("Invalid transaction: BadProof");
                }
                InvalidTransaction::AncientBirthBlock => {
                    log::error!("Invalid transaction: AncientBirthBlock");
                }
                InvalidTransaction::ExhaustsResources => {
                    log::error!("Invalid transaction: ExhaustsResources");
                }
                InvalidTransaction::Custom(e) => {
                    log::error!("Invalid transaction: Custom({})", e);
                }
                InvalidTransaction::BadMandatory => {
                    log::error!("Invalid transaction: BadMandatory");
                }
                InvalidTransaction::MandatoryValidation => {
                    log::error!("Invalid transaction: MandatoryValidation");
                }
                InvalidTransaction::BadSigner => {
                    log::error!("Invalid transaction: BadSigner");
                }
                InvalidTransaction::IndeterminateImplicit => {
                    log::error!("Invalid transaction: IndeterminateImplicit");
                }
                InvalidTransaction::UnknownOrigin => {
                    log::error!("Invalid transaction: UnknownOrigin");
                }
            },
            TransactionValidityError::Unknown(e) => match e {
                UnknownTransaction::CannotLookup => {
                    log::error!("Unknown transaction: CannotLookup");
                }
                UnknownTransaction::NoUnsignedValidator => {
                    log::error!("Unknown transaction: NoUnsignedValidator");
                }
                UnknownTransaction::Custom(e) => {
                    log::error!("Unknown transaction: Custom({})", e);
                }
            },
        }
        panic!("Error: {e:?}");
    }
}
