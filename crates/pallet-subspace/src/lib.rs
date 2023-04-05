#![feature(assert_matches)]
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
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused_must_use, unsafe_code, unused_variables, unused_must_use)]

extern crate alloc;

mod default_weights;
pub mod equivocation;

#[cfg(all(feature = "std", test))]
mod mock;
#[cfg(all(feature = "std", test))]
mod tests;

use alloc::string::String;
use codec::{Decode, Encode, MaxEncodedLen};
use core::num::NonZeroU64;
use equivocation::{HandleEquivocation, SubspaceEquivocationOffence};
use frame_support::dispatch::{DispatchResult, DispatchResultWithPostInfo, Pays};
use frame_support::traits::{Get, OnTimestampSet};
use frame_support::weights::Weight;
use frame_system::offchain::{SendTransactionTypes, SubmitTransaction};
use log::{debug, error, warn};
pub use pallet::*;
use scale_info::TypeInfo;
use schnorrkel::SignatureError;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::consensus::verify_solution;
use sp_consensus_subspace::digests::CompatibleDigestItem;
use sp_consensus_subspace::offence::{OffenceDetails, OffenceError, OnOffenceHandler};
use sp_consensus_subspace::{
    ChainConstants, EquivocationProof, FarmerPublicKey, FarmerSignature, SignedVote, Vote,
};
use sp_runtime::generic::DigestItem;
use sp_runtime::traits::{BlockNumberProvider, Hash, One, SaturatedConversion, Saturating, Zero};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
    TransactionValidityError, ValidTransaction,
};
use sp_runtime::DispatchError;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::prelude::*;
use subspace_core_primitives::{
    ArchivedHistorySegment, PublicKey, Randomness, RewardSignature, SectorId, SectorIndex,
    SegmentHeader, SegmentIndex, SolutionRange,
};
use subspace_solving::REWARD_SIGNING_CONTEXT;
use subspace_verification::{
    check_reward_signature, derive_next_solution_range, derive_randomness, PieceCheckParams,
    VerifySolutionParams,
};

pub trait WeightInfo {
    fn report_equivocation() -> Weight;
    fn store_segment_headers(segment_headers_count: usize) -> Weight;
    fn vote() -> Weight;
}

/// Trigger global randomness every interval.
pub trait GlobalRandomnessIntervalTrigger {
    /// Trigger a global randomness update. This should be called during every block, after
    /// initialization is done.
    fn trigger<T: Config>(block_number: T::BlockNumber, por_randomness: Randomness);
}

/// A type signifying to Subspace that it should perform a global randomness update with an internal
/// trigger.
pub struct NormalGlobalRandomnessInterval;

impl GlobalRandomnessIntervalTrigger for NormalGlobalRandomnessInterval {
    fn trigger<T: Config>(block_number: T::BlockNumber, por_randomness: Randomness) {
        if <Pallet<T>>::should_update_global_randomness(block_number) {
            <Pallet<T>>::enact_update_global_randomness(block_number, por_randomness);
        }
    }
}

/// Trigger an era change, if any should take place.
pub trait EraChangeTrigger {
    /// Trigger an era change, if any should take place. This should be called
    /// during every block, after initialization is done.
    fn trigger<T: Config>(block_number: T::BlockNumber);
}

/// A type signifying to Subspace that it should perform era changes with an internal trigger.
pub struct NormalEraChange;

impl EraChangeTrigger for NormalEraChange {
    fn trigger<T: Config>(block_number: T::BlockNumber) {
        if <Pallet<T>>::should_era_change(block_number) {
            <Pallet<T>>::enact_era_change();
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Encode, Decode, MaxEncodedLen, TypeInfo)]
struct VoteVerificationData {
    global_randomness: Randomness,
    solution_range: SolutionRange,
    current_slot: Slot,
    parent_slot: Slot,
}

/// Simple wrapper for chunk offset in a sector for readability purposes
#[derive(
    Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
struct ChunkOffset(u32);

#[frame_support::pallet]
mod pallet {
    use super::{
        ChunkOffset, EraChangeTrigger, GlobalRandomnessIntervalTrigger, VoteVerificationData,
        WeightInfo,
    };
    use crate::equivocation::HandleEquivocation;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_consensus_slots::Slot;
    use sp_consensus_subspace::digests::CompatibleDigestItem;
    use sp_consensus_subspace::inherents::{InherentError, InherentType, INHERENT_IDENTIFIER};
    use sp_consensus_subspace::{EquivocationProof, FarmerPublicKey, FarmerSignature, SignedVote};
    use sp_runtime::DigestItem;
    use sp_std::collections::btree_map::BTreeMap;
    use sp_std::prelude::*;
    use subspace_core_primitives::{
        Randomness, SectorIndex, SegmentHeader, SegmentIndex, SolutionRange,
    };

    pub(super) struct InitialSolutionRanges<T: Config> {
        _config: T,
    }

    impl<T: Config> Get<sp_consensus_subspace::SolutionRanges> for InitialSolutionRanges<T> {
        fn get() -> sp_consensus_subspace::SolutionRanges {
            sp_consensus_subspace::SolutionRanges {
                current: T::InitialSolutionRange::get(),
                next: None,
                voting_current: if T::ShouldAdjustSolutionRange::get() {
                    T::InitialSolutionRange::get()
                        .saturating_mul(u64::from(T::ExpectedVotesPerBlock::get()) + 1)
                } else {
                    T::InitialSolutionRange::get()
                },
                voting_next: None,
            }
        }
    }

    /// Override for next solution range adjustment
    #[derive(Debug, Encode, Decode, TypeInfo)]
    pub struct SolutionRangeOverride {
        /// Value that should be set as solution range
        pub solution_range: SolutionRange,
        /// Value that should be set as voting solution range
        pub voting_solution_range: SolutionRange,
    }

    /// The Subspace Pallet
    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::config]
    #[pallet::disable_frame_system_supertrait_check]
    pub trait Config: pallet_timestamp::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// The amount of time, in blocks, between updates of global randomness.
        #[pallet::constant]
        type GlobalRandomnessUpdateInterval: Get<Self::BlockNumber>;

        /// The amount of time, in blocks, that each era should last.
        /// NOTE: Currently it is not possible to change the era duration after
        /// the chain has started. Attempting to do so will brick block production.
        #[pallet::constant]
        type EraDuration: Get<Self::BlockNumber>;

        /// Initial solution range used for challenges during the very first era.
        #[pallet::constant]
        type InitialSolutionRange: Get<SolutionRange>;

        /// How often in slots slots (on average, not counting collisions) will have a block.
        ///
        /// Expressed as a rational where the first member of the tuple is the
        /// numerator and the second is the denominator. The rational should
        /// represent a value between 0 and 1.
        #[pallet::constant]
        type SlotProbability: Get<(u64, u64)>;

        /// The expected average block time at which Subspace should be creating blocks. Since
        /// Subspace is probabilistic it is not trivial to figure out what the expected average
        /// block time should be based on the slot duration and the security parameter `c` (where
        /// `1 - c` represents the probability of a slot being empty).
        #[pallet::constant]
        type ExpectedBlockTime: Get<Self::Moment>;

        /// Depth `K` after which a block enters the recorded history (a global constant, as opposed
        /// to the client-dependent transaction confirmation depth `k`).
        #[pallet::constant]
        type ConfirmationDepthK: Get<Self::BlockNumber>;

        /// Number of votes expected per block.
        ///
        /// This impacts solution range for votes in consensus.
        #[pallet::constant]
        type ExpectedVotesPerBlock: Get<u32>;

        type ShouldAdjustSolutionRange: Get<bool>;

        /// Subspace requires periodic global randomness update.
        type GlobalRandomnessIntervalTrigger: GlobalRandomnessIntervalTrigger;

        /// Subspace requires some logic to be triggered on every block to query for whether an era
        /// has ended and to perform the transition to the next era.
        ///
        /// Era is normally used to update solution range used for challenges.
        type EraChangeTrigger: EraChangeTrigger;

        /// The equivocation handling subsystem, defines methods to report an offence (after the
        /// equivocation has been validated) and for submitting a transaction to report an
        /// equivocation (from an offchain context).
        ///
        /// NOTE: when enabling equivocation handling (i.e. this type isn't set to `()`) you must
        /// use this pallet's `ValidateUnsigned` in the runtime definition.
        type HandleEquivocation: HandleEquivocation<Self>;

        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    #[derive(Debug, Default, Encode, Decode, TypeInfo)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub enum AllowAuthoringBy {
        /// Anyone can author new blocks at genesis.
        #[default]
        Anyone,
        /// Author of the first block will be able to author blocks going forward unless unlocked
        /// for everyone.
        FirstFarmer,
        /// Specified root farmer is allowed to author blocks unless unlocked for everyone.
        RootFarmer(FarmerPublicKey),
    }

    #[pallet::genesis_config]
    pub struct GenesisConfig {
        /// Whether rewards should be enabled.
        pub enable_rewards: bool,
        /// Whether storage access should be enabled.
        pub enable_storage_access: bool,
        /// Who can author blocks at genesis.
        pub allow_authoring_by: AllowAuthoringBy,
    }

    #[cfg(feature = "std")]
    impl Default for GenesisConfig {
        fn default() -> Self {
            Self {
                enable_rewards: true,
                enable_storage_access: true,
                allow_authoring_by: AllowAuthoringBy::Anyone,
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig {
        fn build(&self) {
            if self.enable_rewards {
                EnableRewards::<T>::put::<T::BlockNumber>(sp_runtime::traits::One::one());
            }
            IsStorageAccessEnabled::<T>::put(self.enable_storage_access);
            match &self.allow_authoring_by {
                AllowAuthoringBy::Anyone => {
                    AllowAuthoringByAnyone::<T>::put(true);
                }
                AllowAuthoringBy::FirstFarmer => {
                    AllowAuthoringByAnyone::<T>::put(false);
                }
                AllowAuthoringBy::RootFarmer(root_farmer) => {
                    AllowAuthoringByAnyone::<T>::put(false);
                    RootPlotPublicKey::<T>::put(root_farmer.clone());
                }
            }
        }
    }

    /// Events type.
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Segment header was stored in blockchain history.
        SegmentHeaderStored { segment_header: SegmentHeader },
        /// Farmer vote.
        FarmerVote {
            public_key: FarmerPublicKey,
            reward_address: T::AccountId,
            height: T::BlockNumber,
            parent_hash: T::Hash,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// An equivocation proof provided as part of an equivocation report is invalid.
        InvalidEquivocationProof,
        /// A given equivocation report is valid but already previously reported.
        DuplicateOffenceReport,
        /// Solution range adjustment already enabled.
        SolutionRangeAdjustmentAlreadyEnabled,
        /// Rewards already active.
        RewardsAlreadyEnabled,
    }

    /// The slot at which the first block was created. This is 0 until the first block of the chain.
    #[pallet::storage]
    #[pallet::getter(fn genesis_slot)]
    pub type GenesisSlot<T> = StorageValue<_, Slot, ValueQuery>;

    /// Current slot number.
    #[pallet::storage]
    #[pallet::getter(fn current_slot)]
    pub type CurrentSlot<T> = StorageValue<_, Slot, ValueQuery>;

    /// Global randomnesses derived from from PoR signature and used for deriving global challenges.
    #[pallet::storage]
    #[pallet::getter(fn global_randomnesses)]
    pub(super) type GlobalRandomnesses<T> =
        StorageValue<_, sp_consensus_subspace::GlobalRandomnesses, ValueQuery>;

    /// Solution ranges used for challenges.
    #[pallet::storage]
    #[pallet::getter(fn solution_ranges)]
    pub(super) type SolutionRanges<T: Config> = StorageValue<
        _,
        sp_consensus_subspace::SolutionRanges,
        ValueQuery,
        InitialSolutionRanges<T>,
    >;

    /// Storage to check if the solution range is to be adjusted for next era
    #[pallet::storage]
    #[pallet::getter(fn should_adjust_solution_range)]
    pub type ShouldAdjustSolutionRange<T: Config> =
        StorageValue<_, bool, ValueQuery, T::ShouldAdjustSolutionRange>;

    /// Override solution range during next update
    #[pallet::storage]
    pub type NextSolutionRangeOverride<T> = StorageValue<_, SolutionRangeOverride>;

    /// Slot at which current era started.
    #[pallet::storage]
    pub type EraStartSlot<T> = StorageValue<_, Slot>;

    /// A set of blocked farmers keyed by their public key.
    #[pallet::storage]
    pub(super) type BlockList<T> = StorageMap<_, Twox64Concat, FarmerPublicKey, ()>;

    /// Mapping from segment index to corresponding segment commitment of contained records.
    #[pallet::storage]
    #[pallet::getter(fn segment_commitment)]
    pub(super) type SegmentCommitment<T> = CountedStorageMap<
        _,
        Twox64Concat,
        SegmentIndex,
        subspace_core_primitives::SegmentCommitment,
    >;

    /// Storage of previous vote verification data, updated on each block during finalization.
    #[pallet::storage]
    pub(super) type ParentVoteVerificationData<T> = StorageValue<_, VoteVerificationData>;

    /// Parent block author information.
    #[pallet::storage]
    pub(super) type ParentBlockAuthorInfo<T> =
        StorageValue<_, (FarmerPublicKey, SectorIndex, ChunkOffset, Slot)>;

    /// Enable rewards since specified block number.
    #[pallet::storage]
    pub(super) type EnableRewards<T: Config> = StorageValue<_, T::BlockNumber>;

    /// Temporary value (cleared at block finalization) with block author information.
    #[pallet::storage]
    pub(super) type CurrentBlockAuthorInfo<T: Config> = StorageValue<
        _,
        (
            FarmerPublicKey,
            SectorIndex,
            ChunkOffset,
            Slot,
            T::AccountId,
        ),
    >;

    /// Voters in the parent block (set at the end of the block with current values).
    #[pallet::storage]
    pub(super) type ParentBlockVoters<T: Config> = StorageValue<
        _,
        BTreeMap<
            (FarmerPublicKey, SectorIndex, ChunkOffset, Slot),
            (T::AccountId, FarmerSignature),
        >,
        ValueQuery,
    >;

    /// Temporary value (cleared at block finalization) with voters in the current block thus far.
    #[pallet::storage]
    pub(super) type CurrentBlockVoters<T: Config> = StorageValue<
        _,
        BTreeMap<
            (FarmerPublicKey, SectorIndex, ChunkOffset, Slot),
            (T::AccountId, FarmerSignature),
        >,
    >;

    /// Temporary value (cleared at block finalization) which contains current block PoR randomness.
    #[pallet::storage]
    pub(super) type PorRandomness<T> = StorageValue<_, Randomness>;

    /// Enable storage access for all users.
    #[pallet::storage]
    #[pallet::getter(fn is_storage_access_enabled)]
    pub(super) type IsStorageAccessEnabled<T> = StorageValue<_, bool, ValueQuery>;

    /// Allow block authoring by anyone or just root.
    #[pallet::storage]
    pub(super) type AllowAuthoringByAnyone<T> = StorageValue<_, bool, ValueQuery>;

    /// Root plot public key.
    ///
    /// Set just once to make sure no one else can author blocks until allowed for anyone.
    #[pallet::storage]
    #[pallet::getter(fn root_plot_public_key)]
    pub(super) type RootPlotPublicKey<T> = StorageValue<_, FarmerPublicKey>;

    #[pallet::hooks]
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_initialize(block_number: T::BlockNumber) -> Weight {
            Self::do_initialize(block_number);
            Weight::zero()
        }

        fn on_finalize(block_number: T::BlockNumber) {
            Self::do_finalize(block_number)
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Report farmer equivocation/misbehavior. This method will verify the equivocation proof.
        /// If valid, the offence will be reported.
        ///
        /// This extrinsic must be called unsigned and it is expected that only block authors will
        /// call it (validated in `ValidateUnsigned`), as such if the block author is defined it
        /// will be defined as the equivocation reporter.
        #[pallet::call_index(0)]
        #[pallet::weight((<T as Config>::WeightInfo::report_equivocation(), DispatchClass::Operational))]
        // Suppression because the custom syntax will also generate an enum and we need enum to have
        // boxed value.
        #[allow(clippy::boxed_local)]
        pub fn report_equivocation(
            origin: OriginFor<T>,
            equivocation_proof: Box<EquivocationProof<T::Header>>,
        ) -> DispatchResultWithPostInfo {
            ensure_none(origin)?;

            Self::do_report_equivocation(*equivocation_proof)
        }

        /// Submit new segment header to the blockchain. This is an inherent extrinsic and part of
        /// the Subspace consensus logic.
        #[pallet::call_index(1)]
        #[pallet::weight((<T as Config>::WeightInfo::store_segment_headers(segment_headers.len()), DispatchClass::Mandatory, Pays::No))]
        pub fn store_segment_headers(
            origin: OriginFor<T>,
            segment_headers: Vec<SegmentHeader>,
        ) -> DispatchResult {
            ensure_none(origin)?;
            Self::do_store_segment_headers(segment_headers)
        }

        /// Enable solution range adjustment after every era.
        /// Note: No effect on the solution range for the current era
        #[pallet::call_index(2)]
        #[pallet::weight(T::DbWeight::get().writes(1))]
        pub fn enable_solution_range_adjustment(
            origin: OriginFor<T>,
            solution_range_override: Option<u64>,
            voting_solution_range_override: Option<u64>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            Self::do_enable_solution_range_adjustment(
                solution_range_override,
                voting_solution_range_override,
            )?;

            frame_system::Pallet::<T>::deposit_log(
                DigestItem::enable_solution_range_adjustment_and_override(solution_range_override),
            );

            Ok(())
        }

        /// Farmer vote, currently only used for extra rewards to farmers.
        // TODO: Proper weight
        #[pallet::call_index(3)]
        #[pallet::weight((<T as Config>::WeightInfo::vote(), DispatchClass::Operational, Pays::No))]
        // Suppression because the custom syntax will also generate an enum and we need enum to have
        // boxed value.
        #[allow(clippy::boxed_local)]
        pub fn vote(
            origin: OriginFor<T>,
            signed_vote: Box<SignedVote<T::BlockNumber, T::Hash, T::AccountId>>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            Self::do_vote(*signed_vote)
        }

        /// Enable rewards for blocks and votes at specified block height.
        #[pallet::call_index(4)]
        #[pallet::weight(T::DbWeight::get().writes(1))]
        pub fn enable_rewards(
            origin: OriginFor<T>,
            height: Option<T::BlockNumber>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            Self::do_enable_rewards(height)
        }

        /// Enable storage access for all users.
        #[pallet::call_index(5)]
        #[pallet::weight(T::DbWeight::get().writes(1))]
        pub fn enable_storage_access(origin: OriginFor<T>) -> DispatchResult {
            ensure_root(origin)?;

            IsStorageAccessEnabled::<T>::put(true);

            Ok(())
        }

        /// Enable storage access for all users.
        #[pallet::call_index(6)]
        #[pallet::weight(T::DbWeight::get().writes(1))]
        pub fn enable_authoring_by_anyone(origin: OriginFor<T>) -> DispatchResult {
            ensure_root(origin)?;

            AllowAuthoringByAnyone::<T>::put(true);
            RootPlotPublicKey::<T>::take();
            // Deposit root plot public key update such that light client can validate blocks later.
            frame_system::Pallet::<T>::deposit_log(DigestItem::root_plot_public_key_update(None));

            Ok(())
        }
    }

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = InherentError;
        const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

        fn create_inherent(data: &InherentData) -> Option<Self::Call> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Subspace inherent data not correctly encoded")
                .expect("Subspace inherent data must be provided");

            let segment_headers = inherent_data.segment_headers;
            if segment_headers.is_empty() {
                None
            } else {
                Some(Call::store_segment_headers { segment_headers })
            }
        }

        fn is_inherent_required(data: &InherentData) -> Result<Option<Self::Error>, Self::Error> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Subspace inherent data not correctly encoded")
                .expect("Subspace inherent data must be provided");

            Ok(if inherent_data.segment_headers.is_empty() {
                None
            } else {
                Some(InherentError::MissingSegmentHeadersList)
            })
        }

        fn check_inherent(call: &Self::Call, data: &InherentData) -> Result<(), Self::Error> {
            if let Call::store_segment_headers { segment_headers } = call {
                let inherent_data = data
                    .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                    .expect("Subspace inherent data not correctly encoded")
                    .expect("Subspace inherent data must be provided");

                if segment_headers != &inherent_data.segment_headers {
                    return Err(InherentError::IncorrectSegmentHeadersList {
                        expected: inherent_data.segment_headers,
                        actual: segment_headers.clone(),
                    });
                }
            }

            Ok(())
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::store_segment_headers { .. })
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
        fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::report_equivocation { equivocation_proof } => {
                    Self::validate_equivocation_report(source, equivocation_proof)
                }
                Call::store_segment_headers { segment_headers } => {
                    Self::validate_segment_header(source, segment_headers)
                }
                Call::vote { signed_vote } => Self::validate_vote(signed_vote),
                _ => InvalidTransaction::Call.into(),
            }
        }

        fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
            match call {
                Call::report_equivocation { equivocation_proof } => {
                    Self::pre_dispatch_equivocation_report(equivocation_proof)
                }
                Call::store_segment_headers { segment_headers } => {
                    Self::pre_dispatch_segment_header(segment_headers)
                }
                Call::vote { signed_vote } => Self::pre_dispatch_vote(signed_vote),
                _ => Err(InvalidTransaction::Call.into()),
            }
        }
    }
}

impl<T: Config> Pallet<T> {
    /// Determine the Subspace slot duration based on the Timestamp module configuration.
    pub fn slot_duration() -> T::Moment {
        // we double the minimum block-period so each author can always propose within
        // the majority of their slot.
        <T as pallet_timestamp::Config>::MinimumPeriod::get().saturating_mul(2u32.into())
    }

    /// Total number of pieces in the blockchain
    pub fn total_pieces() -> NonZeroU64 {
        // Chain starts with one segment plotted, even if it is not recorded in the runtime yet
        let number_of_segments = u64::from(SegmentCommitment::<T>::count()).max(1);
        NonZeroU64::new(number_of_segments * ArchivedHistorySegment::NUM_PIECES as u64)
            .expect("Neither of multiplied values is zero; qed")
    }

    /// Determine whether a randomness update should take place at this block.
    /// Assumes that initialization has already taken place.
    fn should_update_global_randomness(block_number: T::BlockNumber) -> bool {
        block_number % T::GlobalRandomnessUpdateInterval::get() == Zero::zero()
    }

    /// Determine whether an era change should take place at this block.
    /// Assumes that initialization has already taken place.
    fn should_era_change(block_number: T::BlockNumber) -> bool {
        block_number % T::EraDuration::get() == Zero::zero()
    }

    /// DANGEROUS: Enact update of global randomness. Should be done on every block where `should_update_global_randomness`
    /// has returned `true`, and the caller is the only caller of this function.
    fn enact_update_global_randomness(_block_number: T::BlockNumber, por_randomness: Randomness) {
        GlobalRandomnesses::<T>::mutate(|global_randomnesses| {
            global_randomnesses.next = Some(por_randomness);
        });
    }

    /// DANGEROUS: Enact era change. Should be done on every block where `should_era_change` has
    /// returned `true`, and the caller is the only caller of this function.
    ///
    /// This will update solution range used in consensus.
    fn enact_era_change() {
        let slot_probability = T::SlotProbability::get();

        let current_slot = Self::current_slot();

        SolutionRanges::<T>::mutate(|solution_ranges| {
            let next_solution_range;
            let next_voting_solution_range;
            // Check if the solution range should be adjusted for next era.
            if !ShouldAdjustSolutionRange::<T>::get() {
                next_solution_range = solution_ranges.current;
                next_voting_solution_range = solution_ranges.current;
            } else if let Some(solution_range_override) = NextSolutionRangeOverride::<T>::take() {
                next_solution_range = solution_range_override.solution_range;
                next_voting_solution_range = solution_range_override.voting_solution_range;
            } else {
                next_solution_range = derive_next_solution_range(
                    // If Era start slot is not found it means we have just finished the first era
                    u64::from(EraStartSlot::<T>::get().unwrap_or_else(GenesisSlot::<T>::get)),
                    u64::from(current_slot),
                    slot_probability,
                    solution_ranges.current,
                    T::EraDuration::get()
                        .try_into()
                        .unwrap_or_else(|_| panic!("Era duration is always within u64; qed")),
                );

                next_voting_solution_range = next_solution_range
                    .saturating_mul(u64::from(T::ExpectedVotesPerBlock::get()) + 1);
            };
            solution_ranges.next.replace(next_solution_range);
            solution_ranges
                .voting_next
                .replace(next_voting_solution_range);
        });

        EraStartSlot::<T>::put(current_slot);
    }

    fn do_initialize(block_number: T::BlockNumber) {
        let pre_digest = <frame_system::Pallet<T>>::digest()
            .logs
            .iter()
            .find_map(|s| s.as_subspace_pre_digest::<T::AccountId>())
            .expect("Block must always have pre-digest");

        // On the first non-zero block (i.e. block #1) we need to adjust internal storage
        // accordingly.
        if *GenesisSlot::<T>::get() == 0 {
            GenesisSlot::<T>::put(pre_digest.slot);
            debug_assert_ne!(*GenesisSlot::<T>::get(), 0);
        }

        // The slot number of the current block being initialized.
        CurrentSlot::<T>::put(pre_digest.slot);

        {
            let farmer_public_key = pre_digest.solution.public_key.clone();

            // Optional restriction for block authoring to the root user
            if !AllowAuthoringByAnyone::<T>::get() {
                RootPlotPublicKey::<T>::mutate(|maybe_root_plot_public_key| {
                    if let Some(root_plot_public_key) = maybe_root_plot_public_key {
                        if root_plot_public_key != &farmer_public_key {
                            panic!("Client bug, authoring must be only done by the root user");
                        }
                    } else {
                        maybe_root_plot_public_key.replace(farmer_public_key.clone());
                        // Deposit root plot public key update such that light client can validate
                        // blocks later.
                        frame_system::Pallet::<T>::deposit_log(
                            DigestItem::root_plot_public_key_update(Some(
                                farmer_public_key.clone(),
                            )),
                        );
                    }
                });
            }

            let key = (
                farmer_public_key,
                pre_digest.solution.sector_index,
                ChunkOffset(pre_digest.solution.chunk_offset),
                pre_digest.slot,
            );
            if ParentBlockVoters::<T>::get().contains_key(&key) {
                let (public_key, _sector_index, _chunk_offset, slot) = key;

                let offence = SubspaceEquivocationOffence {
                    slot,
                    offender: public_key,
                };

                // Report equivocation, we don't care about duplicate report here
                if let Err(OffenceError::Other(code)) =
                    T::HandleEquivocation::report_offence(offence)
                {
                    warn!(
                        target: "runtime::subspace",
                        "Failed to submit block author offence report with code {code}"
                    );
                }
            } else {
                let (public_key, sector_index, chunk_offset, slot) = key;

                CurrentBlockAuthorInfo::<T>::put((
                    public_key,
                    sector_index,
                    chunk_offset,
                    slot,
                    pre_digest.solution.reward_address,
                ));
            }
        }
        CurrentBlockVoters::<T>::put(BTreeMap::<
            (FarmerPublicKey, SectorIndex, ChunkOffset, Slot),
            (T::AccountId, FarmerSignature),
        >::default());

        // If global randomness was updated in previous block, set it as current.
        if let Some(next_randomness) = GlobalRandomnesses::<T>::get().next {
            GlobalRandomnesses::<T>::put(sp_consensus_subspace::GlobalRandomnesses {
                current: next_randomness,
                next: None,
            });
        }

        // If solution range was updated in previous block, set it as current.
        if let sp_consensus_subspace::SolutionRanges {
            next: Some(next),
            voting_next: Some(voting_next),
            ..
        } = SolutionRanges::<T>::get()
        {
            SolutionRanges::<T>::put(sp_consensus_subspace::SolutionRanges {
                current: next,
                next: None,
                voting_current: voting_next,
                voting_next: None,
            });
        }

        // Extract PoR randomness from pre-digest.
        // Tag signature is validated by the client and is always valid here.
        let por_randomness: Randomness = derive_randomness(
            &PublicKey::from(&pre_digest.solution.public_key),
            &pre_digest.solution.chunk.to_bytes(),
            &pre_digest.solution.chunk_signature,
        )
        .expect("Tag signature is verified by the client and is always valid; qed");
        // Store PoR randomness for block duration as it might be useful.
        PorRandomness::<T>::put(por_randomness);

        // Deposit global randomness data such that light client can validate blocks later.
        frame_system::Pallet::<T>::deposit_log(DigestItem::global_randomness(
            GlobalRandomnesses::<T>::get().current,
        ));
        // Deposit solution range data such that light client can validate blocks later.
        frame_system::Pallet::<T>::deposit_log(DigestItem::solution_range(
            SolutionRanges::<T>::get().current,
        ));

        // Enact global randomness update, if necessary.
        T::GlobalRandomnessIntervalTrigger::trigger::<T>(block_number, por_randomness);
        // Enact era change, if necessary.
        T::EraChangeTrigger::trigger::<T>(block_number);

        if let Some(next_global_randomness) = GlobalRandomnesses::<T>::get().next {
            // Deposit next global randomness data such that light client can validate blocks later.
            frame_system::Pallet::<T>::deposit_log(DigestItem::next_global_randomness(
                next_global_randomness,
            ));
        }
    }

    fn do_finalize(_block_number: T::BlockNumber) {
        // Deposit the next solution range in the block finalization to account for solution range override extrinsic and
        // era change happens in the same block.
        if let Some(next_solution_range) = SolutionRanges::<T>::get().next {
            // Deposit next solution range data such that light client can validate blocks later.
            frame_system::Pallet::<T>::deposit_log(DigestItem::next_solution_range(
                next_solution_range,
            ));
        }

        PorRandomness::<T>::take();

        if let Some((public_key, sector_index, chunk_offset, slot, _reward_address)) =
            CurrentBlockAuthorInfo::<T>::take()
        {
            ParentBlockAuthorInfo::<T>::put((public_key, sector_index, chunk_offset, slot));
        }

        ParentVoteVerificationData::<T>::put(current_vote_verification_data::<T>(true));

        ParentBlockVoters::<T>::put(CurrentBlockVoters::<T>::take().unwrap_or_default());
    }

    fn do_report_equivocation(
        equivocation_proof: EquivocationProof<T::Header>,
    ) -> DispatchResultWithPostInfo {
        let offender = equivocation_proof.offender.clone();
        let slot = equivocation_proof.slot;

        // validate the equivocation proof
        if !sp_consensus_subspace::is_equivocation_proof_valid::<_, T::AccountId>(
            equivocation_proof,
        ) {
            return Err(Error::<T>::InvalidEquivocationProof.into());
        }

        let offence = SubspaceEquivocationOffence { slot, offender };

        T::HandleEquivocation::report_offence(offence)
            .map_err(|_| Error::<T>::DuplicateOffenceReport)?;

        // waive the fee since the report is valid and beneficial
        Ok(Pays::No.into())
    }

    fn do_store_segment_headers(segment_headers: Vec<SegmentHeader>) -> DispatchResult {
        for segment_header in segment_headers {
            SegmentCommitment::<T>::insert(
                segment_header.segment_index(),
                segment_header.segment_commitment(),
            );
            // Deposit global randomness data such that light client can validate blocks later.
            frame_system::Pallet::<T>::deposit_log(DigestItem::segment_commitment(
                segment_header.segment_index(),
                segment_header.segment_commitment(),
            ));
            Self::deposit_event(Event::SegmentHeaderStored { segment_header });
        }
        Ok(())
    }

    fn do_enable_solution_range_adjustment(
        solution_range_override: Option<u64>,
        voting_solution_range_override: Option<u64>,
    ) -> DispatchResult {
        if ShouldAdjustSolutionRange::<T>::get() {
            return Err(Error::<T>::SolutionRangeAdjustmentAlreadyEnabled.into());
        }

        ShouldAdjustSolutionRange::<T>::put(true);

        if let Some(solution_range) = solution_range_override {
            let voting_solution_range = voting_solution_range_override.unwrap_or_else(|| {
                solution_range.saturating_mul(u64::from(T::ExpectedVotesPerBlock::get()) + 1)
            });
            SolutionRanges::<T>::mutate(|solution_ranges| {
                // If solution range update is already scheduled, just update values
                if solution_ranges.next.is_some() {
                    solution_ranges.next.replace(solution_range);
                    solution_ranges.voting_next.replace(voting_solution_range);
                } else {
                    solution_ranges.current = solution_range;
                    solution_ranges.voting_current = voting_solution_range;

                    // Solution range can re-adjust very soon, make sure next re-adjustment is
                    // also overridden
                    NextSolutionRangeOverride::<T>::put(SolutionRangeOverride {
                        solution_range,
                        voting_solution_range,
                    });
                    frame_system::Pallet::<T>::deposit_log(DigestItem::next_solution_range(
                        solution_range,
                    ));
                }
            });
        }

        Ok(())
    }

    fn do_vote(signed_vote: SignedVote<T::BlockNumber, T::Hash, T::AccountId>) -> DispatchResult {
        let Vote::V0 {
            height,
            parent_hash,
            solution,
            ..
        } = signed_vote.vote;

        if BlockList::<T>::contains_key(&solution.public_key) {
            Err(DispatchError::Other("Equivocated"))
        } else {
            Self::deposit_event(Event::FarmerVote {
                public_key: solution.public_key,
                reward_address: solution.reward_address,
                height,
                parent_hash,
            });

            Ok(())
        }
    }

    fn do_enable_rewards(height: Option<T::BlockNumber>) -> DispatchResult {
        if EnableRewards::<T>::get().is_some() {
            return Err(Error::<T>::RewardsAlreadyEnabled.into());
        }

        // Enable rewards at a particular block height (default to the next block after this)
        let next_block_number = frame_system::Pallet::<T>::current_block_number() + One::one();
        EnableRewards::<T>::put(height.unwrap_or(next_block_number).max(next_block_number));

        Ok(())
    }

    /// Submits an extrinsic to report an equivocation. This method will create an unsigned
    /// extrinsic with a call to `report_equivocation` and will push the transaction to the pool.
    /// Only useful in an offchain context.
    pub fn submit_equivocation_report(
        equivocation_proof: EquivocationProof<T::Header>,
    ) -> Option<()> {
        T::HandleEquivocation::submit_equivocation_report(equivocation_proof).ok()
    }

    /// Just stores offender from equivocation report in block list, only used for tests.
    pub fn submit_test_equivocation_report(
        equivocation_proof: EquivocationProof<T::Header>,
    ) -> Option<()> {
        BlockList::<T>::insert(equivocation_proof.offender, ());
        Some(())
    }

    /// Check if `farmer_public_key` is in block list (due to equivocation)
    pub fn is_in_block_list(farmer_public_key: &FarmerPublicKey) -> bool {
        BlockList::<T>::contains_key(farmer_public_key)
    }

    /// Size of the archived history of the blockchain in bytes
    pub fn archived_history_size() -> u64 {
        let archived_segments = SegmentCommitment::<T>::count();

        u64::from(archived_segments) * ArchivedHistorySegment::SIZE as u64
    }

    pub fn chain_constants() -> ChainConstants {
        ChainConstants::V0 {
            confirmation_depth_k: T::ConfirmationDepthK::get()
                .try_into()
                .unwrap_or_else(|_| panic!("Block number always fits in BlockNumber; qed")),
            global_randomness_interval: T::GlobalRandomnessUpdateInterval::get()
                .try_into()
                .unwrap_or_else(|_| panic!("Block number always fits in BlockNumber; qed")),
            era_duration: T::EraDuration::get()
                .try_into()
                .unwrap_or_else(|_| panic!("Block number always fits in BlockNumber; qed")),
            slot_probability: T::SlotProbability::get(),
        }
    }
}

impl<T> Pallet<T>
where
    T: Config + SendTransactionTypes<Call<T>>,
{
    /// Submit farmer vote vote that is essentially a header with bigger solution range than
    /// acceptable for block authoring.
    pub fn submit_vote(signed_vote: SignedVote<T::BlockNumber, T::Hash, T::AccountId>) {
        let call = Call::vote {
            signed_vote: Box::new(signed_vote),
        };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                debug!(target: "runtime::subspace", "Submitted Subspace vote");
            }
            Err(()) => {
                error!(target: "runtime::subspace", "Error submitting Subspace vote");
            }
        }
    }
}

/// Methods for the `ValidateUnsigned` implementation:
/// It restricts calls to `store_segment_header` to local calls (i.e. extrinsics generated on this
/// node) or that already in a block. This guarantees that only block authors can include root
/// blocks.
impl<T: Config> Pallet<T> {
    fn validate_segment_header(
        source: TransactionSource,
        segment_headers: &[SegmentHeader],
    ) -> TransactionValidity {
        // Discard segment header not coming from the local node
        if !matches!(
            source,
            TransactionSource::Local | TransactionSource::InBlock,
        ) {
            warn!(
                target: "runtime::subspace",
                "Rejecting segment header extrinsic because it is not local/in-block.",
            );

            return InvalidTransaction::Call.into();
        }

        check_segment_headers::<T>(segment_headers)?;

        ValidTransaction::with_tag_prefix("SubspaceSegmentHeader")
            // We assign the maximum priority for any segment header.
            .priority(TransactionPriority::MAX)
            // Should be included immediately into the current block (this is an inherent
            // extrinsic) with no exceptions.
            .longevity(0)
            // We don't propagate this. This can never be included on a remote node.
            .propagate(false)
            .build()
    }

    fn pre_dispatch_segment_header(
        segment_headers: &[SegmentHeader],
    ) -> Result<(), TransactionValidityError> {
        check_segment_headers::<T>(segment_headers)
    }

    fn validate_vote(
        signed_vote: &SignedVote<T::BlockNumber, T::Hash, T::AccountId>,
    ) -> TransactionValidity {
        check_vote::<T>(signed_vote, false)?;

        ValidTransaction::with_tag_prefix("SubspaceVote")
            // We assign the maximum priority for any vote.
            .priority(TransactionPriority::MAX)
            // Should be included in the next block or block after that, but not later
            .longevity(2)
            .and_provides(&signed_vote.signature)
            .build()
    }

    fn pre_dispatch_vote(
        signed_vote: &SignedVote<T::BlockNumber, T::Hash, T::AccountId>,
    ) -> Result<(), TransactionValidityError> {
        match check_vote::<T>(signed_vote, true) {
            Ok(()) => Ok(()),
            Err(CheckVoteError::Equivocated(offence)) => {
                // Report equivocation, we don't care about duplicate report here
                if let Err(OffenceError::Other(code)) =
                    T::HandleEquivocation::report_offence(offence)
                {
                    debug!(
                        target: "runtime::subspace",
                        "Failed to submit voter offence report with code {code}"
                    );
                }

                // Return Ok such that changes from this pre-dispatch are persisted
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// Verification data retrieval depends on whether it is called from pre_dispatch (meaning block
/// initialization has already happened) or from `validate_unsigned` by transaction pool (meaning
/// block initialization didn't happen yet).
fn current_vote_verification_data<T: Config>(is_block_initialized: bool) -> VoteVerificationData {
    let global_randomnesses = GlobalRandomnesses::<T>::get();
    let solution_ranges = SolutionRanges::<T>::get();
    VoteVerificationData {
        global_randomness: if is_block_initialized {
            global_randomnesses.current
        } else {
            global_randomnesses
                .next
                .unwrap_or(global_randomnesses.current)
        },
        solution_range: if is_block_initialized {
            solution_ranges.voting_current
        } else {
            solution_ranges
                .voting_next
                .unwrap_or(solution_ranges.voting_current)
        },
        current_slot: Pallet::<T>::current_slot(),
        parent_slot: ParentVoteVerificationData::<T>::get()
            .map(|parent_vote_verification_data| {
                if is_block_initialized {
                    parent_vote_verification_data.current_slot
                } else {
                    parent_vote_verification_data.parent_slot
                }
            })
            .unwrap_or_else(Pallet::<T>::current_slot),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum CheckVoteError {
    BlockListed,
    UnexpectedBeforeHeightTwo,
    HeightInTheFuture,
    HeightInThePast,
    IncorrectParentHash,
    SlotInTheFuture,
    SlotInThePast,
    BadRewardSignature(SignatureError),
    UnknownSegmentCommitment,
    InvalidSolution(String),
    DuplicateVote,
    Equivocated(SubspaceEquivocationOffence<FarmerPublicKey>),
}

impl From<CheckVoteError> for TransactionValidityError {
    fn from(error: CheckVoteError) -> Self {
        TransactionValidityError::Invalid(match error {
            CheckVoteError::BlockListed => InvalidTransaction::BadSigner,
            CheckVoteError::UnexpectedBeforeHeightTwo => InvalidTransaction::Call,
            CheckVoteError::HeightInTheFuture => InvalidTransaction::Future,
            CheckVoteError::HeightInThePast => InvalidTransaction::Stale,
            CheckVoteError::IncorrectParentHash => InvalidTransaction::Call,
            CheckVoteError::SlotInTheFuture => InvalidTransaction::Future,
            CheckVoteError::SlotInThePast => InvalidTransaction::Stale,
            CheckVoteError::BadRewardSignature(_) => InvalidTransaction::BadProof,
            CheckVoteError::UnknownSegmentCommitment => InvalidTransaction::Call,
            CheckVoteError::InvalidSolution(_) => InvalidTransaction::Call,
            CheckVoteError::DuplicateVote => InvalidTransaction::Call,
            CheckVoteError::Equivocated(_) => InvalidTransaction::BadSigner,
        })
    }
}

fn check_vote<T: Config>(
    signed_vote: &SignedVote<T::BlockNumber, T::Hash, T::AccountId>,
    pre_dispatch: bool,
) -> Result<(), CheckVoteError> {
    let Vote::V0 {
        height,
        parent_hash,
        slot,
        solution,
    } = &signed_vote.vote;
    let height = *height;
    let slot = *slot;

    if BlockList::<T>::contains_key(&solution.public_key) {
        return Err(CheckVoteError::BlockListed);
    }

    let current_block_number = frame_system::Pallet::<T>::current_block_number();

    if current_block_number <= One::one() || height <= One::one() {
        debug!(
            target: "runtime::subspace",
            "Votes are not expected at height below 2"
        );

        return Err(CheckVoteError::UnexpectedBeforeHeightTwo);
    }

    // Height must be either the same as in current block or smaller by one.
    //
    // Subtraction will not panic due to check above.
    if !(height == current_block_number || height == current_block_number - One::one()) {
        debug!(
            target: "runtime::subspace",
            "Vote verification error: bad height {height:?}, current block number is \
            {current_block_number:?}"
        );
        return Err(if height > current_block_number {
            CheckVoteError::HeightInTheFuture
        } else {
            CheckVoteError::HeightInThePast
        });
    }

    // Should have parent hash from -1 (parent hash of current block) or -2 (block before that)
    //
    // Subtraction will not panic due to check above.
    if *parent_hash != frame_system::Pallet::<T>::block_hash(height - One::one()) {
        debug!(
            target: "runtime::subspace",
            "Vote verification error: parent hash {parent_hash:?}",
        );
        return Err(CheckVoteError::IncorrectParentHash);
    }

    let current_vote_verification_data = current_vote_verification_data::<T>(pre_dispatch);
    let parent_vote_verification_data = ParentVoteVerificationData::<T>::get()
        .expect("Above check for block number ensures that this value is always present");

    if pre_dispatch {
        // New time slot is already set, whatever time slot is in the vote it must be smaller or the
        // same (for votes produced locally)
        let current_slot = current_vote_verification_data.current_slot;
        if slot > current_slot || (slot == current_slot && height != current_block_number) {
            debug!(
                target: "runtime::subspace",
                "Vote slot {slot:?} must be before current slot {current_slot:?}",
            );
            return Err(CheckVoteError::SlotInTheFuture);
        }
    }

    let parent_slot = if pre_dispatch {
        // For pre-dispatch parent slot is `current_slot` if the parent vote verification data (it
        // was updated in current block because initialization hook was already called) if vote is
        // at the same height as the current block, otherwise it is one level older and
        // `parent_slot` from parent vote verification data needs to be taken instead
        if height == current_block_number {
            parent_vote_verification_data.current_slot
        } else {
            parent_vote_verification_data.parent_slot
        }
    } else {
        // Otherwise parent slot is `current_slot` if the current vote verification data (that
        // wan't updated from parent block because initialization hook wasn't called yet) if vote
        // is at the same height as the current block, otherwise it is one level older and
        // `parent_slot` from current vote verification data needs to be taken instead
        if height == current_block_number {
            current_vote_verification_data.current_slot
        } else {
            current_vote_verification_data.parent_slot
        }
    };

    if slot <= parent_slot {
        debug!(
            target: "runtime::subspace",
            "Vote slot {slot:?} must be after parent slot {parent_slot:?}",
        );
        return Err(CheckVoteError::SlotInThePast);
    }

    if let Err(error) = check_reward_signature(
        signed_vote.vote.hash().as_bytes(),
        &RewardSignature::from(&signed_vote.signature),
        &PublicKey::from(&solution.public_key),
        &schnorrkel::signing_context(REWARD_SIGNING_CONTEXT),
    ) {
        debug!(
            target: "runtime::subspace",
            "Vote verification error: {error:?}"
        );
        return Err(CheckVoteError::BadRewardSignature(error));
    }

    let vote_verification_data = if height == current_block_number {
        current_vote_verification_data
    } else {
        parent_vote_verification_data
    };

    let sector_id = SectorId::new(&(&solution.public_key).into(), solution.sector_index);

    let segment_index = sector_id
        .derive_piece_index(solution.piece_offset, solution.total_pieces)
        .segment_index();

    let segment_commitment =
        if let Some(segment_commitment) = Pallet::<T>::segment_commitment(segment_index) {
            segment_commitment
        } else {
            debug!(
                target: "runtime::subspace",
                "Vote verification error: no segment commitment for segment index {segment_index}"
            );
            return Err(CheckVoteError::UnknownSegmentCommitment);
        };

    if let Err(error) = verify_solution(
        solution.into(),
        slot.into(),
        (&VerifySolutionParams {
            global_randomness: vote_verification_data.global_randomness,
            solution_range: vote_verification_data.solution_range,
            piece_check_params: Some(PieceCheckParams { segment_commitment }),
        })
            .into(),
    ) {
        debug!(
            target: "runtime::subspace",
            "Vote verification error: {error:?}"
        );
        return Err(CheckVoteError::InvalidSolution(error));
    }

    let key = (
        solution.public_key.clone(),
        solution.sector_index,
        ChunkOffset(solution.chunk_offset),
        slot,
    );
    // Check that farmer didn't use solution from this vote yet in:
    // * parent block
    // * current block
    // * parent block vote
    // * current block vote
    let mut is_equivocating = ParentBlockAuthorInfo::<T>::get().as_ref() == Some(&key)
        || CurrentBlockAuthorInfo::<T>::get()
            .map(
                |(public_key, sector_index, chunk_offset, slot, _reward_address)| {
                    (public_key, sector_index, chunk_offset, slot)
                },
            )
            .as_ref()
            == Some(&key);

    if !is_equivocating {
        if let Some((_reward_address, signature)) = ParentBlockVoters::<T>::get().get(&key) {
            if signature != &signed_vote.signature {
                is_equivocating = true;
            } else {
                // The same vote should never be included more than once
                return Err(CheckVoteError::DuplicateVote);
            }
        }
    }

    if !is_equivocating {
        if let Some((_reward_address, signature)) =
            CurrentBlockVoters::<T>::get().unwrap_or_default().get(&key)
        {
            if signature != &signed_vote.signature {
                is_equivocating = true;
            } else {
                // The same vote should never be included more than once
                return Err(CheckVoteError::DuplicateVote);
            }
        }
    }

    if is_equivocating {
        // Revoke reward if assigned in current block.
        CurrentBlockVoters::<T>::mutate(|current_reward_receivers| {
            if let Some(current_reward_receivers) = current_reward_receivers {
                current_reward_receivers.remove(&key);
            }
        });

        let (public_key, _sector_index, _chunk_offset, _slot) = key;

        return Err(CheckVoteError::Equivocated(SubspaceEquivocationOffence {
            slot,
            offender: public_key,
        }));
    }

    if pre_dispatch {
        // During `pre_dispatch` call put farmer into the list of reward receivers.
        CurrentBlockVoters::<T>::mutate(|current_reward_receivers| {
            current_reward_receivers
                .as_mut()
                .expect("Always set during block initialization")
                .insert(
                    key,
                    (
                        solution.reward_address.clone(),
                        signed_vote.signature.clone(),
                    ),
                );
        });
    }

    Ok(())
}

fn check_segment_headers<T: Config>(
    segment_headers: &[SegmentHeader],
) -> Result<(), TransactionValidityError> {
    let mut segment_headers_iter = segment_headers.iter();

    // There should be some segment headers
    let first_segment_header = match segment_headers_iter.next() {
        Some(first_segment_header) => first_segment_header,
        None => {
            return Err(InvalidTransaction::BadMandatory.into());
        }
    };

    // Segment in segment headers should monotonically increase
    if first_segment_header.segment_index() > SegmentIndex::ZERO
        && !SegmentCommitment::<T>::contains_key(
            first_segment_header.segment_index() - SegmentIndex::ONE,
        )
    {
        return Err(InvalidTransaction::BadMandatory.into());
    }

    // Segment headers should never repeat
    if SegmentCommitment::<T>::contains_key(first_segment_header.segment_index()) {
        return Err(InvalidTransaction::BadMandatory.into());
    }

    let mut last_segment_index = first_segment_header.segment_index();

    for segment_header in segment_headers_iter {
        let segment_index = segment_header.segment_index();

        // Segment in segment headers should monotonically increase
        if segment_index != last_segment_index + SegmentIndex::ONE {
            return Err(InvalidTransaction::BadMandatory.into());
        }

        // Segment headers should never repeat
        if SegmentCommitment::<T>::contains_key(segment_index) {
            return Err(InvalidTransaction::BadMandatory.into());
        }

        last_segment_index = segment_index;
    }

    Ok(())
}

impl<T: Config> OnTimestampSet<T::Moment> for Pallet<T> {
    fn on_timestamp_set(moment: T::Moment) {
        let slot_duration = Self::slot_duration();
        assert!(
            !slot_duration.is_zero(),
            "Subspace slot duration cannot be zero."
        );

        let timestamp_slot = moment / slot_duration;
        let timestamp_slot = Slot::from(timestamp_slot.saturated_into::<u64>());

        assert_eq!(
            Self::current_slot(),
            timestamp_slot,
            "Timestamp slot must match `CurrentSlot`",
        );
    }
}

impl<T: Config> subspace_runtime_primitives::FindBlockRewardAddress<T::AccountId> for Pallet<T> {
    fn find_block_reward_address() -> Option<T::AccountId> {
        CurrentBlockAuthorInfo::<T>::get().and_then(
            |(public_key, _sector_index, _chunk_offset, _slot, reward_address)| {
                // Equivocation might have happened in this block, if so - no reward for block
                // author
                if !BlockList::<T>::contains_key(public_key) {
                    // Rewards might be disabled, in which case no block reward either
                    if let Some(height) = EnableRewards::<T>::get() {
                        if frame_system::Pallet::<T>::current_block_number() >= height {
                            return Some(reward_address);
                        }
                    }
                }

                None
            },
        )
    }
}

impl<T: Config> subspace_runtime_primitives::FindVotingRewardAddresses<T::AccountId> for Pallet<T> {
    fn find_voting_reward_addresses() -> Vec<T::AccountId> {
        // Rewards might be disabled, in which case no voting reward
        if let Some(height) = EnableRewards::<T>::get() {
            if frame_system::Pallet::<T>::current_block_number() >= height {
                // It is possible that this is called during initialization when current block
                // voters are already moved into parent block voters, handle it accordingly
                return CurrentBlockVoters::<T>::get()
                    .unwrap_or_else(ParentBlockVoters::<T>::get)
                    .into_values()
                    .map(|(reward_address, _signature)| reward_address)
                    .collect();
            }
        }

        Vec::new()
    }
}

impl<T: Config> frame_support::traits::Randomness<T::Hash, T::BlockNumber> for Pallet<T> {
    fn random(subject: &[u8]) -> (T::Hash, T::BlockNumber) {
        let mut subject = subject.to_vec();
        subject.extend_from_slice(
            PorRandomness::<T>::get()
                .expect("PoR randomness is always set in block initialization; qed")
                .as_ref(),
        );

        (
            T::Hashing::hash(&subject),
            frame_system::Pallet::<T>::current_block_number(),
        )
    }

    fn random_seed() -> (T::Hash, T::BlockNumber) {
        (
            T::Hashing::hash(
                PorRandomness::<T>::get()
                    .expect("PoR randomness is always set in block initialization; qed")
                    .as_ref(),
            ),
            frame_system::Pallet::<T>::current_block_number(),
        )
    }
}

impl<T: Config> OnOffenceHandler<FarmerPublicKey> for Pallet<T> {
    fn on_offence(offenders: &[OffenceDetails<FarmerPublicKey>]) {
        for offender in offenders {
            BlockList::<T>::insert(offender.offender.clone(), ());
        }
    }
}
