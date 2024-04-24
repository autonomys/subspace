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
#![feature(array_chunks, assert_matches, const_option, let_chains, portable_simd)]
#![warn(unused_must_use, unsafe_code, unused_variables)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod equivocation;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod weights;

#[cfg(not(feature = "std"))]
use alloc::string::String;
use codec::{Decode, Encode, MaxEncodedLen};
use core::num::NonZeroU64;
use equivocation::{HandleEquivocation, SubspaceEquivocationOffence};
use frame_support::dispatch::{DispatchResult, DispatchResultWithPostInfo, Pays};
use frame_support::traits::Get;
use frame_system::offchain::{SendTransactionTypes, SubmitTransaction};
use frame_system::pallet_prelude::*;
use log::{debug, error, warn};
pub use pallet::*;
use scale_info::TypeInfo;
use schnorrkel::SignatureError;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::consensus::{is_proof_of_time_valid, verify_solution};
use sp_consensus_subspace::digests::CompatibleDigestItem;
use sp_consensus_subspace::offence::{OffenceDetails, OffenceError, OnOffenceHandler};
use sp_consensus_subspace::{
    EquivocationProof, FarmerPublicKey, FarmerSignature, PotParameters, PotParametersChange,
    SignedVote, Vote, WrappedPotOutput,
};
use sp_runtime::generic::DigestItem;
use sp_runtime::traits::{BlockNumberProvider, CheckedSub, Hash, One, Zero};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
    TransactionValidityError, ValidTransaction,
};
use sp_runtime::DispatchError;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::prelude::*;
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::{
    ArchivedHistorySegment, BlockHash, HistorySize, PieceOffset, PublicKey, RewardSignature,
    SectorId, SectorIndex, SegmentHeader, SegmentIndex, SlotNumber, SolutionRange,
    REWARD_SIGNING_CONTEXT,
};
use subspace_verification::{
    check_reward_signature, derive_next_solution_range, derive_pot_entropy, PieceCheckParams,
    VerifySolutionParams,
};

/// Trigger an era change, if any should take place.
pub trait EraChangeTrigger {
    /// Trigger an era change, if any should take place. This should be called
    /// during every block, after initialization is done.
    fn trigger<T: Config>(block_number: BlockNumberFor<T>);
}

/// A type signifying to Subspace that it should perform era changes with an internal trigger.
pub struct NormalEraChange;

impl EraChangeTrigger for NormalEraChange {
    fn trigger<T: Config>(block_number: BlockNumberFor<T>) {
        if <Pallet<T>>::should_era_change(block_number) {
            <Pallet<T>>::enact_era_change();
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Encode, Decode, MaxEncodedLen, TypeInfo)]
struct VoteVerificationData {
    /// Block solution range, vote must not reach it
    solution_range: SolutionRange,
    vote_solution_range: SolutionRange,
    current_slot: Slot,
    parent_slot: Slot,
}

#[frame_support::pallet]
pub mod pallet {
    use super::{EraChangeTrigger, VoteVerificationData};
    use crate::equivocation::HandleEquivocation;
    use crate::weights::WeightInfo;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_consensus_slots::Slot;
    use sp_consensus_subspace::digests::CompatibleDigestItem;
    use sp_consensus_subspace::inherents::{InherentError, InherentType, INHERENT_IDENTIFIER};
    use sp_consensus_subspace::{EquivocationProof, FarmerPublicKey, FarmerSignature, SignedVote};
    use sp_runtime::DigestItem;
    use sp_std::collections::btree_map::BTreeMap;
    use sp_std::num::NonZeroU32;
    use sp_std::prelude::*;
    use subspace_core_primitives::crypto::Scalar;
    use subspace_core_primitives::{
        Blake3Hash, HistorySize, PieceOffset, Randomness, SectorIndex, SegmentHeader, SegmentIndex,
        SolutionRange,
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
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Number of slots between slot arrival and when corresponding block can be produced.
        ///
        /// Practically this means future proof of time proof needs to be revealed this many slots
        /// ahead before block can be authored even though solution is available before that.
        #[pallet::constant]
        type BlockAuthoringDelay: Get<Slot>;

        /// Interval, in blocks, between blockchain entropy injection into proof of time chain.
        #[pallet::constant]
        type PotEntropyInjectionInterval: Get<BlockNumberFor<Self>>;

        /// Interval, in entropy injection intervals, where to take entropy for injection from.
        #[pallet::constant]
        type PotEntropyInjectionLookbackDepth: Get<u8>;

        /// Delay after block, in slots, when entropy injection takes effect.
        #[pallet::constant]
        type PotEntropyInjectionDelay: Get<Slot>;

        /// The amount of time, in blocks, that each era should last.
        /// NOTE: Currently it is not possible to change the era duration after
        /// the chain has started. Attempting to do so will brick block production.
        #[pallet::constant]
        type EraDuration: Get<BlockNumberFor<Self>>;

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

        /// Depth `K` after which a block enters the recorded history (a global constant, as opposed
        /// to the client-dependent transaction confirmation depth `k`).
        #[pallet::constant]
        type ConfirmationDepthK: Get<BlockNumberFor<Self>>;

        /// Number of latest archived segments that are considered "recent history".
        #[pallet::constant]
        type RecentSegments: Get<HistorySize>;

        /// Fraction of pieces from the "recent history" (`recent_segments`) in each sector.
        #[pallet::constant]
        type RecentHistoryFraction: Get<(HistorySize, HistorySize)>;

        /// Minimum lifetime of a plotted sector, measured in archived segment.
        #[pallet::constant]
        type MinSectorLifetime: Get<HistorySize>;

        /// Number of votes expected per block.
        ///
        /// This impacts solution range for votes in consensus.
        #[pallet::constant]
        type ExpectedVotesPerBlock: Get<u32>;

        /// How many pieces one sector is supposed to contain (max)
        #[pallet::constant]
        type MaxPiecesInSector: Get<u16>;

        type ShouldAdjustSolutionRange: Get<bool>;
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

        /// Maximum number of block number to block slot mappings to keep (oldest pruned first).
        #[pallet::constant]
        type BlockSlotCount: Get<u32>;
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

    #[derive(Debug, Copy, Clone, Encode, Decode, TypeInfo)]
    pub(super) struct PotEntropyValue {
        /// Target slot at which entropy should be injected (when known)
        pub(super) target_slot: Option<Slot>,
        pub(super) entropy: Blake3Hash,
    }

    /// When to enable block/vote rewards
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Encode, Decode, TypeInfo)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub enum EnableRewardsAt<BlockNumber> {
        /// At specified height or next block if `None`
        Height(Option<BlockNumber>),
        /// When solution range is below specified threshold
        SolutionRange(u64),
        /// Manually with an explicit extrinsic
        Manually,
    }

    #[pallet::genesis_config]
    pub struct GenesisConfig<T>
    where
        T: Config,
    {
        /// When rewards should be enabled.
        pub enable_rewards_at: EnableRewardsAt<BlockNumberFor<T>>,
        /// Who can author blocks at genesis.
        pub allow_authoring_by: AllowAuthoringBy,
        /// Number of iterations for proof of time per slot
        pub pot_slot_iterations: NonZeroU32,
        #[serde(skip)]
        pub phantom: PhantomData<T>,
    }

    impl<T> Default for GenesisConfig<T>
    where
        T: Config,
    {
        #[inline]
        fn default() -> Self {
            Self {
                enable_rewards_at: EnableRewardsAt::Height(None),
                allow_authoring_by: AllowAuthoringBy::Anyone,
                pot_slot_iterations: NonZeroU32::MIN,
                phantom: PhantomData,
            }
        }
    }

    #[pallet::genesis_build]
    impl<T> BuildGenesisConfig for GenesisConfig<T>
    where
        T: Config,
    {
        fn build(&self) {
            match self.enable_rewards_at {
                EnableRewardsAt::Height(maybe_block_number) => {
                    EnableRewards::<T>::put(
                        maybe_block_number.unwrap_or_else(sp_runtime::traits::One::one),
                    );
                }
                EnableRewardsAt::SolutionRange(solution_range) => {
                    EnableRewardsBelowSolutionRange::<T>::put(solution_range);
                }
                EnableRewardsAt::Manually => {
                    // Nothing to do in this case
                }
            }
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
            PotSlotIterations::<T>::put(self.pot_slot_iterations);
        }
    }

    /// Events type.
    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Segment header was stored in blockchain history.
        SegmentHeaderStored { segment_header: SegmentHeader },
        /// Farmer vote.
        FarmerVote {
            public_key: FarmerPublicKey,
            reward_address: T::AccountId,
            height: BlockNumberFor<T>,
            parent_hash: T::Hash,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// A given equivocation report is valid but already previously reported.
        DuplicateOffenceReport,
        /// Solution range adjustment already enabled.
        SolutionRangeAdjustmentAlreadyEnabled,
        /// Rewards already active.
        RewardsAlreadyEnabled,
    }

    // TODO: Remove genesis slot
    /// The slot at which the first block was created. This is 0 until the first block of the chain.
    #[pallet::storage]
    #[pallet::getter(fn genesis_slot)]
    pub type GenesisSlot<T> = StorageValue<_, Slot, ValueQuery>;

    // TODO: Replace `CurrentSlot` with `BlockSlots`
    /// Current slot number.
    #[pallet::storage]
    #[pallet::getter(fn current_slot)]
    pub type CurrentSlot<T> = StorageValue<_, Slot, ValueQuery>;

    /// Bounded mapping from block number to slot
    #[pallet::storage]
    #[pallet::getter(fn block_slots)]
    pub type BlockSlots<T: Config> =
        StorageValue<_, BoundedBTreeMap<BlockNumberFor<T>, Slot, T::BlockSlotCount>, ValueQuery>;

    // TODO: Clarify when this value is updated (when it is updated, right now it is not)
    /// Number of iterations for proof of time per slot
    #[pallet::storage]
    pub(super) type PotSlotIterations<T> = StorageValue<_, NonZeroU32>;

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

    /// Whether the segment headers inherent has been processed in this block (temporary value).
    ///
    /// This value is updated to `true` when processing `store_segment_headers` by a node.
    /// It is then cleared at the end of each block execution in the `on_finalize` hook.
    #[pallet::storage]
    pub(super) type DidProcessSegmentHeaders<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Storage of previous vote verification data, updated on each block during finalization.
    #[pallet::storage]
    pub(super) type ParentVoteVerificationData<T> = StorageValue<_, VoteVerificationData>;

    /// Parent block author information.
    #[pallet::storage]
    pub(super) type ParentBlockAuthorInfo<T> =
        StorageValue<_, (FarmerPublicKey, SectorIndex, PieceOffset, Scalar, Slot)>;

    /// Enable rewards since specified block number.
    #[pallet::storage]
    pub(super) type EnableRewards<T: Config> = StorageValue<_, BlockNumberFor<T>>;

    /// Enable rewards when solution range is below this threshold.
    #[pallet::storage]
    pub(super) type EnableRewardsBelowSolutionRange<T: Config> = StorageValue<_, u64>;

    /// Block author information
    #[pallet::storage]
    pub(super) type CurrentBlockAuthorInfo<T: Config> = StorageValue<
        _,
        (
            FarmerPublicKey,
            SectorIndex,
            PieceOffset,
            Scalar,
            Slot,
            T::AccountId,
        ),
    >;

    /// Voters in the parent block (set at the end of the block with current values).
    #[pallet::storage]
    pub(super) type ParentBlockVoters<T: Config> = StorageValue<
        _,
        BTreeMap<
            (FarmerPublicKey, SectorIndex, PieceOffset, Scalar, Slot),
            (T::AccountId, FarmerSignature),
        >,
        ValueQuery,
    >;

    /// Voters in the current block thus far
    #[pallet::storage]
    pub(super) type CurrentBlockVoters<T: Config> = StorageValue<
        _,
        BTreeMap<
            (FarmerPublicKey, SectorIndex, PieceOffset, Scalar, Slot),
            (T::AccountId, FarmerSignature),
        >,
    >;

    /// Entropy that needs to be injected into proof of time chain at specific slot associated with
    /// block number it came from.
    #[pallet::storage]
    pub(super) type PotEntropy<T: Config> =
        StorageValue<_, BTreeMap<BlockNumberFor<T>, PotEntropyValue>, ValueQuery>;

    /// The current block randomness, updated at block initialization. When the proof of time feature
    /// is enabled it derived from PoT otherwise PoR.
    #[pallet::storage]
    pub type BlockRandomness<T> = StorageValue<_, Randomness>;

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
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(block_number: BlockNumberFor<T>) -> Weight {
            Self::do_initialize(block_number);
            Weight::zero()
        }

        fn on_finalize(block_number: BlockNumberFor<T>) {
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
        #[pallet::weight((< T as Config >::WeightInfo::report_equivocation(), DispatchClass::Operational))]
        // Suppression because the custom syntax will also generate an enum and we need enum to have
        // boxed value.
        #[allow(clippy::boxed_local)]
        pub fn report_equivocation(
            origin: OriginFor<T>,
            equivocation_proof: Box<EquivocationProof<HeaderFor<T>>>,
        ) -> DispatchResultWithPostInfo {
            ensure_none(origin)?;

            Self::do_report_equivocation(*equivocation_proof)
        }

        /// Submit new segment header to the blockchain. This is an inherent extrinsic and part of
        /// the Subspace consensus logic.
        #[pallet::call_index(1)]
        #[pallet::weight((< T as Config >::WeightInfo::store_segment_headers(segment_headers.len() as u32), DispatchClass::Mandatory, Pays::No))]
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
        #[pallet::weight(< T as Config >::WeightInfo::enable_solution_range_adjustment())]
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
        #[pallet::call_index(3)]
        #[pallet::weight((< T as Config >::WeightInfo::vote(), DispatchClass::Operational, Pays::No))]
        // Suppression because the custom syntax will also generate an enum and we need enum to have
        // boxed value.
        #[allow(clippy::boxed_local)]
        pub fn vote(
            origin: OriginFor<T>,
            signed_vote: Box<SignedVote<BlockNumberFor<T>, T::Hash, T::AccountId>>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            Self::do_vote(*signed_vote)
        }

        /// Enable rewards for blocks and votes at specified block height.
        #[pallet::call_index(4)]
        #[pallet::weight(< T as Config >::WeightInfo::enable_rewards())]
        pub fn enable_rewards_at(
            origin: OriginFor<T>,
            enable_rewards_at: EnableRewardsAt<BlockNumberFor<T>>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            Self::do_enable_rewards_at(enable_rewards_at)
        }

        /// Enable storage access for all users.
        #[pallet::call_index(5)]
        #[pallet::weight(< T as Config >::WeightInfo::enable_authoring_by_anyone())]
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
    /// Total number of pieces in the blockchain
    pub fn history_size() -> HistorySize {
        // Chain starts with one segment plotted, even if it is not recorded in the runtime yet
        let number_of_segments = u64::from(SegmentCommitment::<T>::count()).max(1);
        HistorySize::from(NonZeroU64::new(number_of_segments).expect("Not zero; qed"))
    }

    /// Determine whether an era change should take place at this block.
    /// Assumes that initialization has already taken place.
    fn should_era_change(block_number: BlockNumberFor<T>) -> bool {
        block_number % T::EraDuration::get() == Zero::zero()
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

            if let Some(solution_range_for_rewards) = EnableRewardsBelowSolutionRange::<T>::get() {
                if next_solution_range <= solution_range_for_rewards {
                    EnableRewardsBelowSolutionRange::<T>::take();

                    let next_block_number =
                        frame_system::Pallet::<T>::current_block_number() + One::one();
                    EnableRewards::<T>::put(next_block_number);
                }
            }
        });

        EraStartSlot::<T>::put(current_slot);
    }

    fn do_initialize(block_number: BlockNumberFor<T>) {
        let pre_digest = frame_system::Pallet::<T>::digest()
            .logs
            .iter()
            .find_map(|s| s.as_subspace_pre_digest::<T::AccountId>())
            .expect("Block must always have pre-digest");

        // On the first non-zero block (i.e. block #1) we need to adjust internal storage
        // accordingly.
        if *GenesisSlot::<T>::get() == 0 {
            GenesisSlot::<T>::put(pre_digest.slot());
            debug_assert_ne!(*GenesisSlot::<T>::get(), 0);
        }

        // The slot number of the current block being initialized.
        CurrentSlot::<T>::put(pre_digest.slot());

        BlockSlots::<T>::mutate(|block_slots| {
            if let Some(to_remove) = block_number.checked_sub(&T::BlockSlotCount::get().into()) {
                block_slots.remove(&to_remove);
            }
            block_slots
                .try_insert(block_number, pre_digest.slot())
                .expect("one entry just removed before inserting; qed");
        });

        {
            // Remove old value
            CurrentBlockAuthorInfo::<T>::take();
            let farmer_public_key = pre_digest.solution().public_key.clone();

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
                pre_digest.solution().sector_index,
                pre_digest.solution().piece_offset,
                pre_digest.solution().chunk,
                pre_digest.slot(),
            );
            if ParentBlockVoters::<T>::get().contains_key(&key) {
                let (public_key, _sector_index, _piece_offset, _chunk, slot) = key;

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
                let (public_key, sector_index, piece_offset, chunk, slot) = key;

                CurrentBlockAuthorInfo::<T>::put((
                    public_key,
                    sector_index,
                    piece_offset,
                    chunk,
                    slot,
                    pre_digest.solution().reward_address.clone(),
                ));
            }
        }
        CurrentBlockVoters::<T>::put(BTreeMap::<
            (FarmerPublicKey, SectorIndex, PieceOffset, Scalar, Slot),
            (T::AccountId, FarmerSignature),
        >::default());

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

        let block_randomness = pre_digest
            .pot_info()
            .proof_of_time()
            .derive_global_randomness();

        // Update the block randomness.
        BlockRandomness::<T>::put(block_randomness);

        // Deposit solution range data such that light client can validate blocks later.
        frame_system::Pallet::<T>::deposit_log(DigestItem::solution_range(
            SolutionRanges::<T>::get().current,
        ));

        // Enact era change, if necessary.
        T::EraChangeTrigger::trigger::<T>(block_number);

        {
            let pot_slot_iterations =
                PotSlotIterations::<T>::get().expect("Always initialized during genesis; qed");
            let pot_entropy_injection_interval = T::PotEntropyInjectionInterval::get();
            let pot_entropy_injection_delay = T::PotEntropyInjectionDelay::get();

            // TODO: Take adjustment of iterations into account once we have it
            frame_system::Pallet::<T>::deposit_log(DigestItem::pot_slot_iterations(
                pot_slot_iterations,
            ));

            let mut entropy = PotEntropy::<T>::get();
            let lookback_in_blocks = pot_entropy_injection_interval
                * BlockNumberFor::<T>::from(T::PotEntropyInjectionLookbackDepth::get());
            let last_entropy_injection_block =
                block_number / pot_entropy_injection_interval * pot_entropy_injection_interval;
            let maybe_entropy_source_block_number =
                last_entropy_injection_block.checked_sub(&lookback_in_blocks);

            if (block_number % pot_entropy_injection_interval).is_zero() {
                let current_block_entropy = derive_pot_entropy(
                    pre_digest.solution().chunk,
                    pre_digest.pot_info().proof_of_time(),
                );
                // Collect entropy every `T::PotEntropyInjectionInterval` blocks
                entropy.insert(
                    block_number,
                    PotEntropyValue {
                        target_slot: None,
                        entropy: current_block_entropy,
                    },
                );

                // Update target slot for entropy injection once we know it
                if let Some(entropy_source_block_number) = maybe_entropy_source_block_number {
                    if let Some(entropy_value) = entropy.get_mut(&entropy_source_block_number) {
                        let target_slot = pre_digest
                            .slot()
                            .saturating_add(pot_entropy_injection_delay);
                        debug!(
                            target: "runtime::subspace",
                            "Pot entropy injection will happen at slot {target_slot:?}",
                        );
                        entropy_value.target_slot.replace(target_slot);
                    }
                }

                PotEntropy::<T>::put(entropy.clone());
            }

            // Deposit consensus log item with parameters change in case corresponding entropy is
            // available
            if let Some(entropy_source_block_number) = maybe_entropy_source_block_number {
                let maybe_entropy_value = entropy.get(&entropy_source_block_number).copied();
                if let Some(PotEntropyValue {
                    target_slot,
                    entropy,
                }) = maybe_entropy_value
                {
                    let target_slot = target_slot
                        .expect("Target slot is guaranteed to be present due to logic above; qed");

                    frame_system::Pallet::<T>::deposit_log(DigestItem::pot_parameters_change(
                        PotParametersChange {
                            slot: target_slot,
                            // TODO: Take adjustment of iterations into account once we have it
                            slot_iterations: pot_slot_iterations,
                            entropy,
                        },
                    ));
                }
            }

            // Clean up old values we'll no longer need
            if let Some(entry) = entropy.first_entry() {
                if let Some(target_slot) = entry.get().target_slot
                    && target_slot < pre_digest.slot()
                {
                    entry.remove();
                    PotEntropy::<T>::put(entropy);
                }
            }
        }
    }

    fn do_finalize(_block_number: BlockNumberFor<T>) {
        // Deposit the next solution range in the block finalization to account for solution range override extrinsic and
        // era change happens in the same block.
        if let Some(next_solution_range) = SolutionRanges::<T>::get().next {
            // Deposit next solution range data such that light client can validate blocks later.
            frame_system::Pallet::<T>::deposit_log(DigestItem::next_solution_range(
                next_solution_range,
            ));
        }

        if let Some((public_key, sector_index, piece_offset, scalar, slot, _reward_address)) =
            CurrentBlockAuthorInfo::<T>::get()
        {
            ParentBlockAuthorInfo::<T>::put((public_key, sector_index, piece_offset, scalar, slot));
        } else {
            ParentBlockAuthorInfo::<T>::take();
        }

        ParentVoteVerificationData::<T>::put(current_vote_verification_data::<T>(true));

        ParentBlockVoters::<T>::put(CurrentBlockVoters::<T>::get().unwrap_or_default());

        DidProcessSegmentHeaders::<T>::take();
    }

    fn do_report_equivocation(
        equivocation_proof: EquivocationProof<HeaderFor<T>>,
    ) -> DispatchResultWithPostInfo {
        let offender = equivocation_proof.offender.clone();
        let slot = equivocation_proof.slot;

        let offence = SubspaceEquivocationOffence { slot, offender };

        T::HandleEquivocation::report_offence(offence)
            .map_err(|_| Error::<T>::DuplicateOffenceReport)?;

        // waive the fee since the report is valid and beneficial
        Ok(Pays::No.into())
    }

    fn do_store_segment_headers(segment_headers: Vec<SegmentHeader>) -> DispatchResult {
        assert!(
            !DidProcessSegmentHeaders::<T>::exists(),
            "Segment headers must be updated only once in the block"
        );

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

        DidProcessSegmentHeaders::<T>::put(true);
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

    fn do_vote(
        signed_vote: SignedVote<BlockNumberFor<T>, T::Hash, T::AccountId>,
    ) -> DispatchResult {
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

    fn do_enable_rewards_at(
        enable_rewards_at: EnableRewardsAt<BlockNumberFor<T>>,
    ) -> DispatchResult {
        if EnableRewards::<T>::get().is_some() {
            return Err(Error::<T>::RewardsAlreadyEnabled.into());
        }

        match enable_rewards_at {
            EnableRewardsAt::Height(maybe_block_number) => {
                // Enable rewards at a particular block height (default to the next block after
                // this)
                let next_block_number =
                    frame_system::Pallet::<T>::current_block_number() + One::one();
                EnableRewards::<T>::put(
                    maybe_block_number
                        .unwrap_or(next_block_number)
                        .max(next_block_number),
                );
            }
            EnableRewardsAt::SolutionRange(solution_range) => {
                EnableRewardsBelowSolutionRange::<T>::put(solution_range);
            }
            EnableRewardsAt::Manually => {
                // Nothing to do in this case
            }
        }

        Ok(())
    }

    /// Submits an extrinsic to report an equivocation. This method will create an unsigned
    /// extrinsic with a call to `report_equivocation` and will push the transaction to the pool.
    /// Only useful in an offchain context.
    pub fn submit_equivocation_report(
        equivocation_proof: EquivocationProof<HeaderFor<T>>,
    ) -> Option<()> {
        T::HandleEquivocation::submit_equivocation_report(equivocation_proof).ok()
    }

    /// Just stores offender from equivocation report in block list, only used for tests.
    pub fn submit_test_equivocation_report(
        equivocation_proof: EquivocationProof<HeaderFor<T>>,
    ) -> Option<()> {
        BlockList::<T>::insert(equivocation_proof.offender, ());
        Some(())
    }

    /// Proof of time parameters
    pub fn pot_parameters() -> PotParameters {
        let block_number = frame_system::Pallet::<T>::block_number();
        let pot_slot_iterations =
            PotSlotIterations::<T>::get().expect("Always initialized during genesis; qed");
        let pot_entropy_injection_interval = T::PotEntropyInjectionInterval::get();

        let entropy = PotEntropy::<T>::get();
        let lookback_in_blocks = pot_entropy_injection_interval
            * BlockNumberFor::<T>::from(T::PotEntropyInjectionLookbackDepth::get());
        let last_entropy_injection_block =
            block_number / pot_entropy_injection_interval * pot_entropy_injection_interval;
        let maybe_entropy_source_block_number =
            last_entropy_injection_block.checked_sub(&lookback_in_blocks);

        let mut next_change = None;

        if let Some(entropy_source_block_number) = maybe_entropy_source_block_number {
            let maybe_entropy_value = entropy.get(&entropy_source_block_number).copied();
            if let Some(PotEntropyValue {
                target_slot,
                entropy,
            }) = maybe_entropy_value
            {
                let target_slot = target_slot.expect(
                    "Always present due to identical check present in block initialization; qed",
                );

                next_change.replace(PotParametersChange {
                    slot: target_slot,
                    // TODO: Take adjustment of iterations into account once we have it
                    slot_iterations: pot_slot_iterations,
                    entropy,
                });
            }
        }

        PotParameters::V0 {
            slot_iterations: pot_slot_iterations,
            next_change,
        }
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
}

impl<T> Pallet<T>
where
    T: Config + SendTransactionTypes<Call<T>>,
{
    /// Submit farmer vote vote that is essentially a header with bigger solution range than
    /// acceptable for block authoring.
    pub fn submit_vote(signed_vote: SignedVote<BlockNumberFor<T>, T::Hash, T::AccountId>) {
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
        signed_vote: &SignedVote<BlockNumberFor<T>, T::Hash, T::AccountId>,
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
        signed_vote: &SignedVote<BlockNumberFor<T>, T::Hash, T::AccountId>,
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
    let solution_ranges = SolutionRanges::<T>::get();
    VoteVerificationData {
        solution_range: if is_block_initialized {
            solution_ranges.current
        } else {
            solution_ranges.next.unwrap_or(solution_ranges.current)
        },
        vote_solution_range: if is_block_initialized {
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
    InvalidHistorySize,
    InvalidSolution(String),
    QualityTooHigh,
    InvalidProofOfTime,
    InvalidFutureProofOfTime,
    DuplicateVote,
    Equivocated(SubspaceEquivocationOffence<FarmerPublicKey>),
}

impl From<CheckVoteError> for TransactionValidityError {
    #[inline]
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
            CheckVoteError::InvalidHistorySize => InvalidTransaction::Call,
            CheckVoteError::InvalidSolution(_) => InvalidTransaction::Call,
            CheckVoteError::QualityTooHigh => InvalidTransaction::Call,
            CheckVoteError::InvalidProofOfTime => InvalidTransaction::Future,
            CheckVoteError::InvalidFutureProofOfTime => InvalidTransaction::Call,
            CheckVoteError::DuplicateVote => InvalidTransaction::Call,
            CheckVoteError::Equivocated(_) => InvalidTransaction::BadSigner,
        })
    }
}

fn check_vote<T: Config>(
    signed_vote: &SignedVote<BlockNumberFor<T>, T::Hash, T::AccountId>,
    pre_dispatch: bool,
) -> Result<(), CheckVoteError> {
    let Vote::V0 {
        height,
        parent_hash,
        slot,
        solution,
        proof_of_time,
        future_proof_of_time,
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
        .expect("Above check for block number ensures that this value is always present; qed");

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
        // For pre-dispatch parent slot is `current_slot` in the parent vote verification data (it
        // was updated in current block because initialization hook was already called) if vote is
        // at the same height as the current block, otherwise it is one level older and
        // `parent_slot` from parent vote verification data needs to be taken instead
        if height == current_block_number {
            parent_vote_verification_data.current_slot
        } else {
            parent_vote_verification_data.parent_slot
        }
    } else {
        // Otherwise parent slot is `current_slot` in the current vote verification data (that
        // wasn't updated from parent block because initialization hook wasn't called yet) if vote
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

    let sector_id = SectorId::new(
        PublicKey::from(&solution.public_key).hash(),
        solution.sector_index,
    );

    let recent_segments = T::RecentSegments::get();
    let recent_history_fraction = (
        T::RecentHistoryFraction::get().0,
        T::RecentHistoryFraction::get().1,
    );
    let segment_index = sector_id
        .derive_piece_index(
            solution.piece_offset,
            solution.history_size,
            T::MaxPiecesInSector::get(),
            recent_segments,
            recent_history_fraction,
        )
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

    let sector_expiration_check_segment_commitment = Pallet::<T>::segment_commitment(
        solution
            .history_size
            .sector_expiration_check(T::MinSectorLifetime::get())
            .ok_or(CheckVoteError::InvalidHistorySize)?
            .segment_index(),
    );

    match verify_solution(
        solution.into(),
        slot.into(),
        (&VerifySolutionParams {
            proof_of_time: *proof_of_time,
            solution_range: vote_verification_data.vote_solution_range,
            piece_check_params: Some(PieceCheckParams {
                max_pieces_in_sector: T::MaxPiecesInSector::get(),
                segment_commitment,
                recent_segments,
                recent_history_fraction,
                min_sector_lifetime: T::MinSectorLifetime::get(),
                current_history_size: Pallet::<T>::history_size(),
                sector_expiration_check_segment_commitment,
            }),
        })
            .into(),
    ) {
        Ok(solution_distance) => {
            if solution_distance <= vote_verification_data.solution_range / 2 {
                debug!(
                    target: "runtime::subspace",
                    "Vote quality is too high"
                );
                return Err(CheckVoteError::QualityTooHigh);
            }
        }
        Err(error) => {
            debug!(
                target: "runtime::subspace",
                "Vote verification error: {error:?}"
            );
            return Err(CheckVoteError::InvalidSolution(error));
        }
    }

    // Cheap proof of time verification is possible here because proof of time must have already
    // been seen by this node due to votes requiring the same authoring delay as blocks
    if !is_proof_of_time_valid(
        BlockHash::try_from(parent_hash.as_ref())
            .expect("Must be able to convert to block hash type"),
        SlotNumber::from(slot),
        WrappedPotOutput::from(*proof_of_time),
        // Quick verification when entering transaction pool, but not when constructing the block
        !pre_dispatch,
    ) {
        debug!(target: "runtime::subspace", "Invalid proof of time");

        return Err(CheckVoteError::InvalidProofOfTime);
    }

    // During pre-dispatch we have already verified proofs of time up to future proof of time of
    // current block, which vote can't exceed, this must be possible to verify cheaply
    if pre_dispatch
        && !is_proof_of_time_valid(
            BlockHash::try_from(parent_hash.as_ref())
                .expect("Must be able to convert to block hash type"),
            SlotNumber::from(slot + T::BlockAuthoringDelay::get()),
            WrappedPotOutput::from(*future_proof_of_time),
            false,
        )
    {
        debug!(target: "runtime::subspace", "Invalid future proof of time");

        return Err(CheckVoteError::InvalidFutureProofOfTime);
    }

    let key = (
        solution.public_key.clone(),
        solution.sector_index,
        solution.piece_offset,
        solution.chunk,
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
                |(public_key, sector_index, piece_offset, chunk, slot, _reward_address)| {
                    (public_key, sector_index, piece_offset, chunk, slot)
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

        let (public_key, _sector_index, _piece_offset, _chunk, _slot) = key;

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

impl<T: Config> subspace_runtime_primitives::RewardsEnabled for Pallet<T> {
    fn rewards_enabled() -> bool {
        if let Some(height) = EnableRewards::<T>::get() {
            frame_system::Pallet::<T>::current_block_number() >= height
        } else {
            false
        }
    }
}

impl<T: Config> subspace_runtime_primitives::FindBlockRewardAddress<T::AccountId> for Pallet<T> {
    fn find_block_reward_address() -> Option<T::AccountId> {
        CurrentBlockAuthorInfo::<T>::get().and_then(
            |(public_key, _sector_index, _piece_offset, _chunk, _slot, reward_address)| {
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

impl<T: Config> frame_support::traits::Randomness<T::Hash, BlockNumberFor<T>> for Pallet<T> {
    fn random(subject: &[u8]) -> (T::Hash, BlockNumberFor<T>) {
        let mut subject = subject.to_vec();
        subject.extend_from_slice(
            BlockRandomness::<T>::get()
                .expect("Block randomness is always set in block initialization; qed")
                .as_ref(),
        );

        (
            T::Hashing::hash(&subject),
            frame_system::Pallet::<T>::current_block_number(),
        )
    }

    fn random_seed() -> (T::Hash, BlockNumberFor<T>) {
        (
            T::Hashing::hash(
                BlockRandomness::<T>::get()
                    .expect("Block randomness is always set in block initialization; qed")
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
