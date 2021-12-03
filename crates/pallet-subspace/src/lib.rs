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

//! Subspace consensus pallet.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused_must_use, unsafe_code, unused_variables, unused_must_use)]

mod default_weights;
pub mod equivocation;

#[cfg(all(feature = "std", test))]
mod mock;
#[cfg(all(feature = "std", test))]
mod tests;

use codec::{Decode, Encode};
use equivocation::{HandleEquivocation, SubspaceEquivocationOffence};
use frame_support::{
    dispatch::{DispatchResult, DispatchResultWithPostInfo},
    traits::{ConstU32, Get, OnTimestampSet},
    weights::{Pays, Weight},
    BoundedVec,
};
#[cfg(not(feature = "std"))]
use num_traits::float::FloatCore;
pub use pallet::*;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{
    digests::{
        NextEpochDescriptor, NextSaltDescriptor, NextSolutionRangeDescriptor, PreDigest,
        SaltDescriptor, SolutionRangeDescriptor,
    },
    offence::{OffenceDetails, OnOffenceHandler},
    ConsensusLog, Epoch, EquivocationProof, FarmerPublicKey, SubspaceEpochConfiguration,
    SUBSPACE_ENGINE_ID,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
    TransactionValidityError, ValidTransaction,
};
use sp_runtime::{
    generic::DigestItem,
    traits::{One, SaturatedConversion, Saturating, Zero},
};
use sp_std::prelude::*;
use subspace_core_primitives::{RootBlock, RANDOMNESS_LENGTH};

pub trait WeightInfo {
    fn plan_config_change() -> Weight;
    fn report_equivocation() -> Weight;
    fn store_root_blocks(root_blocks_count: usize) -> Weight;
}

/// Trigger an epoch change, if any should take place.
pub trait EpochChangeTrigger {
    /// Trigger an epoch change, if any should take place. This should be called
    /// during every block, after initialization is done.
    fn trigger<T: Config>(now: T::BlockNumber);
}
/// A type signifying to Subspace that it should perform epoch changes with an internal trigger.
pub struct NormalEpochChange;

impl EpochChangeTrigger for NormalEpochChange {
    fn trigger<T: Config>(now: T::BlockNumber) {
        if <Pallet<T>>::should_epoch_change(now) {
            <Pallet<T>>::enact_epoch_change();
        }
    }
}

/// Trigger an era change, if any should take place.
pub trait EraChangeTrigger {
    /// Trigger an era change, if any should take place. This should be called
    /// during every block, after initialization is done.
    fn trigger<T: Config>(now: T::BlockNumber);
}

/// A type signifying to Subspace that it should perform era changes with an internal trigger.
pub struct NormalEraChange;

impl EraChangeTrigger for NormalEraChange {
    fn trigger<T: Config>(now: T::BlockNumber) {
        if <Pallet<T>>::should_era_change(now) {
            <Pallet<T>>::enact_era_change(now);
        }
    }
}

/// Trigger an era change, if any should take place.
pub trait EonChangeTrigger {
    /// Trigger an era change, if any should take place. This should be called
    /// during every block, after initialization is done.
    fn trigger<T: Config>(now: T::BlockNumber);
}

/// A type signifying to Subspace that it should perform era changes with an internal trigger.
pub struct NormalEonChange;

impl EonChangeTrigger for NormalEonChange {
    fn trigger<T: Config>(now: T::BlockNumber) {
        if <Pallet<T>>::should_eon_change(now) {
            <Pallet<T>>::enact_eon_change();
        }
    }
}

#[frame_support::pallet]
mod pallet {
    use super::{EonChangeTrigger, EpochChangeTrigger, EraChangeTrigger, WeightInfo};
    use crate::equivocation::HandleEquivocation;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_consensus_slots::Slot;
    use sp_consensus_subspace::digests::NextConfigDescriptor;
    use sp_consensus_subspace::inherents::{InherentError, InherentType, INHERENT_IDENTIFIER};
    use sp_consensus_subspace::{EquivocationProof, FarmerPublicKey, SubspaceEpochConfiguration};
    use sp_std::prelude::*;
    use subspace_core_primitives::{RootBlock, Sha256Hash};

    pub(super) const UNDER_CONSTRUCTION_SEGMENT_LENGTH: u32 = 256;

    pub(super) type MaybeRandomness = Option<subspace_core_primitives::Randomness>;

    /// The Subspace Pallet
    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::generate_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::config]
    #[pallet::disable_frame_system_supertrait_check]
    pub trait Config: pallet_timestamp::Config {
        /// The overarching event type.
        type Event: From<Event> + IsType<<Self as frame_system::Config>::Event>;

        /// The amount of time, in slots, that each epoch should last.
        /// NOTE: Currently it is not possible to change the epoch duration after
        /// the chain has started. Attempting to do so will brick block production.
        #[pallet::constant]
        type EpochDuration: Get<u64>;

        /// The amount of time, in blocks, that each era should last.
        /// NOTE: Currently it is not possible to change the era duration after
        /// the chain has started. Attempting to do so will brick block production.
        #[pallet::constant]
        type EraDuration: Get<u32>;

        /// The amount of time, in slots, that each eon should last.
        /// NOTE: Currently it is not possible to change the eon duration after
        /// the chain has started. Attempting to do so will brick block production.
        #[pallet::constant]
        type EonDuration: Get<u64>;

        /// Initial solution range used for challenges during the very first era.
        #[pallet::constant]
        type InitialSolutionRange: Get<u64>;

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
        type ConfirmationDepthK: Get<u32>;

        /// The size of data in one piece (in bytes).
        #[pallet::constant]
        type RecordSize: Get<u32>;

        // TODO: This will probably become configurable later
        /// Recorded history is encoded and plotted in segments of this size (in bytes).
        #[pallet::constant]
        type RecordedHistorySegmentSize: Get<u32>;

        /// Subspace requires some logic to be triggered on every block to query for whether an epoch
        /// has ended and to perform the transition to the next epoch.
        ///
        /// Typically, the `ExternalTrigger` type should be used. An internal trigger should only be used
        /// when no other module is responsible for changing epochs.
        type EpochChangeTrigger: EpochChangeTrigger;

        /// Subspace requires some logic to be triggered on every block to query for whether an era
        /// has ended and to perform the transition to the next era.
        type EraChangeTrigger: EraChangeTrigger;

        /// Subspace requires some logic to be triggered on every block to query for whether an eon
        /// has ended and to perform the transition to the next eon.
        type EonChangeTrigger: EonChangeTrigger;

        /// The equivocation handling subsystem, defines methods to report an
        /// offence (after the equivocation has been validated) and for submitting a
        /// transaction to report an equivocation (from an offchain context).
        /// NOTE: when enabling equivocation handling (i.e. this type isn't set to
        /// `()`) you must use this pallet's `ValidateUnsigned` in the runtime
        /// definition.
        type HandleEquivocation: HandleEquivocation<Self>;

        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    /// Events type.
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event {
        /// Root block was stored in blockchain history.
        /// \[root_block\].
        RootBlockStored(RootBlock),
    }

    #[pallet::error]
    pub enum Error<T> {
        /// An equivocation proof provided as part of an equivocation report is invalid.
        InvalidEquivocationProof,
        /// A key ownership proof provided as part of an equivocation report is invalid.
        InvalidKeyOwnershipProof,
        /// A given equivocation report is valid but already previously reported.
        DuplicateOffenceReport,
    }

    /// Current epoch index.
    #[pallet::storage]
    #[pallet::getter(fn epoch_index)]
    pub type EpochIndex<T> = StorageValue<_, u64, ValueQuery>;

    /// Current eon index.
    #[pallet::storage]
    #[pallet::getter(fn eon_index)]
    pub type EonIndex<T> = StorageValue<_, u64, ValueQuery>;

    /// The slot at which the first epoch actually started. This is 0
    /// until the first block of the chain.
    #[pallet::storage]
    #[pallet::getter(fn genesis_slot)]
    pub type GenesisSlot<T> = StorageValue<_, Slot, ValueQuery>;

    /// Current slot number.
    #[pallet::storage]
    #[pallet::getter(fn current_slot)]
    pub type CurrentSlot<T> = StorageValue<_, Slot, ValueQuery>;

    /// The epoch randomness for the *current* epoch.
    ///
    /// # Security
    ///
    /// This MUST NOT be used for gambling, as it can be influenced by a
    /// malicious validator in the short term. It MAY be used in many
    /// cryptographic protocols, however, so long as one remembers that this
    /// (like everything else on-chain) it is public. For example, it can be
    /// used where a number is needed that cannot have been chosen by an
    /// adversary, for purposes such as public-coin zero-knowledge proofs.
    // NOTE: the following fields don't use the constants to define the
    // array size because the metadata API currently doesn't resolve the
    // variable to its underlying value.
    #[pallet::storage]
    #[pallet::getter(fn randomness)]
    pub type Randomness<T> = StorageValue<_, subspace_core_primitives::Randomness, ValueQuery>;

    /// The solution range for *current* era.
    #[pallet::storage]
    #[pallet::getter(fn solution_range)]
    pub type SolutionRange<T> = StorageValue<_, u64>;

    /// Salt for *current* eon.
    #[pallet::storage]
    #[pallet::getter(fn salt)]
    pub type Salt<T> = StorageValue<_, u64, ValueQuery>;

    /// The solution range for *current* era.
    #[pallet::storage]
    pub type EraStartSlot<T> = StorageValue<_, Slot>;

    /// Pending epoch configuration change that will be applied when the next epoch is enacted.
    #[pallet::storage]
    pub(super) type PendingEpochConfigChange<T> = StorageValue<_, NextConfigDescriptor>;

    /// Next epoch randomness.
    #[pallet::storage]
    pub(super) type NextRandomness<T> =
        StorageValue<_, subspace_core_primitives::Randomness, ValueQuery>;

    /// Randomness under construction.
    ///
    /// We make a tradeoff between storage accesses and list length.
    /// We store the under-construction randomness in segments of up to
    /// `UNDER_CONSTRUCTION_SEGMENT_LENGTH`.
    ///
    /// Once a segment reaches this length, we begin the next one.
    /// We reset all segments and return to `0` at the beginning of every
    /// epoch.
    #[pallet::storage]
    pub(super) type SegmentIndex<T> = StorageValue<_, u32, ValueQuery>;

    /// TWOX-NOTE: `SegmentIndex` is an increasing integer, so this is okay.
    #[pallet::storage]
    pub(super) type UnderConstruction<T: Config> = StorageMap<
        _,
        Twox64Concat,
        u32,
        BoundedVec<
            subspace_core_primitives::Randomness,
            ConstU32<UNDER_CONSTRUCTION_SEGMENT_LENGTH>,
        >,
        ValueQuery,
    >;

    /// Temporary value (cleared at block finalization) which is `Some`
    /// if per-block initialization has already been called for current block.
    #[pallet::storage]
    #[pallet::getter(fn initialized)]
    pub(super) type Initialized<T> = StorageValue<_, MaybeRandomness>;

    /// This field should always be populated during block processing.
    ///
    /// It is set in `on_initialize`, before it will contain the value from the last block.
    #[pallet::storage]
    #[pallet::getter(fn author_por_randomness)]
    pub(super) type AuthorPorRandomness<T> = StorageValue<_, MaybeRandomness, ValueQuery>;

    /// The block numbers when the last and current epoch have started, respectively `N-1` and
    /// `N`.
    /// NOTE: We track this is in order to annotate the block number when a given pool of
    /// entropy was fixed (i.e. it was known to chain observers). Since epochs are defined in
    /// slots, which may be skipped, the block numbers may not line up with the slot numbers.
    #[pallet::storage]
    pub(super) type EpochStart<T: Config> =
        StorageValue<_, (T::BlockNumber, T::BlockNumber), ValueQuery>;

    /// How late the current block is compared to its parent.
    ///
    /// This entry is populated as part of block execution and is cleaned up
    /// on block finalization. Querying this storage entry outside of block
    /// execution context should always yield zero.
    #[pallet::storage]
    #[pallet::getter(fn lateness)]
    pub(super) type Lateness<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

    /// The configuration for the current epoch. Should never be `None` as it is initialized in genesis.
    #[pallet::storage]
    pub(super) type EpochConfig<T> = StorageValue<_, SubspaceEpochConfiguration>;

    /// The configuration for the next epoch, `None` if the config will not change
    /// (you can fallback to `EpochConfig` instead in that case).
    #[pallet::storage]
    pub(super) type NextEpochConfig<T> = StorageValue<_, SubspaceEpochConfiguration>;

    /// A set of blocked farmers keyed by their public key.
    #[pallet::storage]
    pub(super) type BlockList<T> = StorageMap<_, Twox64Concat, FarmerPublicKey, ()>;

    /// Mapping from segment index to corresponding merkle tree root of segment records.
    #[pallet::storage]
    #[pallet::getter(fn records_root)]
    pub(super) type RecordsRoot<T> = StorageMap<_, Twox64Concat, u64, Sha256Hash>;

    #[pallet::genesis_config]
    #[cfg_attr(feature = "std", derive(Default))]
    pub struct GenesisConfig {
        pub epoch_config: Option<SubspaceEpochConfiguration>,
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig {
        fn build(&self) {
            SegmentIndex::<T>::put(0);
            EpochConfig::<T>::put(
                self.epoch_config
                    .clone()
                    .expect("epoch_config must not be None"),
            );
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        /// Initialization
        fn on_initialize(now: BlockNumberFor<T>) -> Weight {
            Self::do_initialize(now);
            0
        }

        /// Block finalization
        fn on_finalize(_n: BlockNumberFor<T>) {
            // at the end of the block, we can safely include the new PoR output
            // from this block into the under-construction randomness. If we've determined
            // that this block was the first in a new epoch, the changeover logic has
            // already occurred at this point, so the under-construction randomness
            // will only contain outputs from the right epoch.
            if let Some(Some(randomness)) = Initialized::<T>::take() {
                Self::deposit_randomness(&randomness);
            }

            // remove temporary "environment" entry from storage
            Lateness::<T>::kill();
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

        /// Plan an epoch config change. The epoch config change is recorded and will be enacted on
        /// the next call to `enact_epoch_change`. The config will be activated one epoch after.
        /// Multiple calls to this method will replace any existing planned config change that had
        /// not been enacted yet.
        #[pallet::weight(<T as Config>::WeightInfo::plan_config_change())]
        pub fn plan_config_change(
            origin: OriginFor<T>,
            config: NextConfigDescriptor,
        ) -> DispatchResult {
            ensure_root(origin)?;
            PendingEpochConfigChange::<T>::put(config);
            Ok(())
        }

        /// Submit new root block to the blockchain. This is an inherent extrinsic and part of the
        /// Subspace consensus logic.
        #[pallet::weight((<T as Config>::WeightInfo::store_root_blocks(root_blocks.len()), DispatchClass::Mandatory, Pays::No))]
        pub fn store_root_blocks(
            origin: OriginFor<T>,
            root_blocks: Vec<RootBlock>,
        ) -> DispatchResult {
            ensure_none(origin)?;
            Self::do_store_root_blocks(root_blocks)
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

            let root_blocks = inherent_data.root_blocks;
            if root_blocks.is_empty() {
                None
            } else {
                Some(Call::store_root_blocks { root_blocks })
            }
        }

        fn check_inherent(call: &Self::Call, data: &InherentData) -> Result<(), Self::Error> {
            if let Call::store_root_blocks { root_blocks } = call {
                let inherent_data = data
                    .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                    .expect("Subspace inherent data not correctly encoded")
                    .expect("Subspace inherent data must be provided");

                if root_blocks != &inherent_data.root_blocks {
                    return Err(InherentError::IncorrectRootBlocksList);
                }
            }

            Ok(())
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::store_root_blocks { .. })
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
        fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::report_equivocation { .. } => {
                    Self::validate_equivocation_report(source, call)
                }
                Call::store_root_blocks { .. } => Self::validate_root_block(source, call),
                _ => InvalidTransaction::Call.into(),
            }
        }

        fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
            match call {
                Call::report_equivocation { .. } => Self::pre_dispatch_equivocation_report(call),
                Call::store_root_blocks { .. } => Self::pre_dispatch_root_block(call),
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

    /// Determine whether an epoch change should take place at this block.
    /// Assumes that initialization has already taken place.
    pub fn should_epoch_change(now: T::BlockNumber) -> bool {
        // The epoch has technically ended during the passage of time
        // between this block and the last, but we have to "end" the epoch now,
        // since there is no earlier possible block we could have done it.
        //
        // The exception is for block 1: the genesis has slot 0, so we treat
        // epoch 0 as having started at the slot of block 1. We want to use
        // the same randomness and validator set as signalled in the genesis,
        // so we don't rotate the epoch.
        now != One::one() && {
            let diff = CurrentSlot::<T>::get().saturating_sub(Self::current_epoch_start());
            *diff >= T::EpochDuration::get()
        }
    }

    /// Determine whether an era change should take place at this block.
    /// Assumes that initialization has already taken place.
    pub fn should_era_change(now: T::BlockNumber) -> bool {
        // The era has technically ended during the passage of time
        // between this block and the last, but we have to "end" the era now,
        // since there is no earlier possible block we could have done it.
        now != One::one() && now % T::EraDuration::get().into() == 1_u32.into()
    }

    /// Determine whether an eon change should take place at this block.
    /// Assumes that initialization has already taken place.
    pub fn should_eon_change(now: T::BlockNumber) -> bool {
        // The eon has technically ended during the passage of time
        // between this block and the last, but we have to "end" the eon now,
        // since there is no earlier possible block we could have done it.
        now != One::one() && {
            let diff = CurrentSlot::<T>::get().saturating_sub(Self::current_eon_start());
            *diff >= T::EonDuration::get()
        }
    }

    /// Return the _best guess_ block number, at which the next epoch change is predicted to happen.
    ///
    /// Returns None if the prediction is in the past; This implies an error internally in Subspace
    /// and should not happen under normal circumstances.
    ///
    /// In other words, this is only accurate if no slots are missed. Given missed slots, the slot
    /// number will grow while the block number will not. Hence, the result can be interpreted as an
    /// upper bound.
    //
    // ## IMPORTANT NOTE
    //
    // This implementation is linked to how [`should_epoch_change`] is working. This might need to
    // be updated accordingly, if the underlying mechanics of slot and epochs change.
    //
    // WEIGHT NOTE: This function is tied to the weight of `EstimateNextSessionRotation`. If you
    // update this function, you must also update the corresponding weight.
    pub fn next_expected_epoch_change(now: T::BlockNumber) -> Option<T::BlockNumber> {
        let next_slot = Self::current_epoch_start().saturating_add(T::EpochDuration::get());
        next_slot
            .checked_sub(*CurrentSlot::<T>::get())
            .map(|slots_remaining| {
                // This is a best effort guess. Drifts in the slot/block ratio will cause errors here.
                let blocks_remaining: T::BlockNumber = slots_remaining.saturated_into();
                now.saturating_add(blocks_remaining)
            })
    }

    /// DANGEROUS: Enact an epoch change. Should be done on every block where `should_epoch_change` has returned `true`,
    /// and the caller is the only caller of this function.
    ///
    /// Typically, this is not handled directly by the user, but by higher-level validator-set manager logic like
    /// `pallet-session`.
    pub fn enact_epoch_change() {
        // PRECONDITION: caller has done initialization and is guaranteed
        // by the session module to be called before this.
        debug_assert!(Self::initialized().is_some());

        // Update epoch index
        let epoch_index = EpochIndex::<T>::get()
            .checked_add(1)
            .expect("epoch indices will never reach 2^64 before the death of the universe; qed");

        EpochIndex::<T>::put(epoch_index);

        // Update epoch randomness.
        let next_epoch_index = epoch_index
            .checked_add(1)
            .expect("epoch indices will never reach 2^64 before the death of the universe; qed");

        // Returns randomness for the current epoch and computes the *next*
        // epoch randomness.
        let randomness = Self::randomness_change_epoch(next_epoch_index);
        Randomness::<T>::put(randomness);

        // Update the start blocks of the previous and new current epoch.
        <EpochStart<T>>::mutate(|(previous_epoch_start_block, current_epoch_start_block)| {
            *previous_epoch_start_block = sp_std::mem::take(current_epoch_start_block);
            *current_epoch_start_block = <frame_system::Pallet<T>>::block_number();
        });

        // After we update the current epoch, we signal the *next* epoch change
        // so that nodes can track changes.
        let next_randomness = NextRandomness::<T>::get();

        let next_epoch = NextEpochDescriptor {
            randomness: next_randomness,
        };
        Self::deposit_consensus(ConsensusLog::NextEpochData(next_epoch));

        if let Some(next_config) = NextEpochConfig::<T>::get() {
            EpochConfig::<T>::put(next_config);
        }

        if let Some(pending_epoch_config_change) = PendingEpochConfigChange::<T>::take() {
            let next_epoch_config: SubspaceEpochConfiguration =
                pending_epoch_config_change.clone().into();
            NextEpochConfig::<T>::put(next_epoch_config);

            Self::deposit_consensus(ConsensusLog::NextConfigData(pending_epoch_config_change));
        }
    }

    /// DANGEROUS: Enact era change. Should be done on every block where `should_era_change` has
    /// returned `true`, and the caller is the only caller of this function.
    pub fn enact_era_change(block_number: T::BlockNumber) {
        // PRECONDITION: caller has done initialization and is guaranteed by the session module to
        // be called before this.
        debug_assert!(Self::initialized().is_some());

        let slot_probability = T::SlotProbability::get();

        let previous_solution_range =
            SolutionRange::<T>::get().unwrap_or_else(T::InitialSolutionRange::get);

        let current_slot = CurrentSlot::<T>::get();
        // If Era start slot is not found it means we have just finished the first era
        let era_start_slot = EraStartSlot::<T>::get().unwrap_or_else(GenesisSlot::<T>::get);
        let era_slot_count = u64::from(current_slot) - u64::from(era_start_slot);

        // Now we need to re-calculate solution range. The idea here is to keep block production at
        // the same pace while space pledged on the network changes. For this we adjust previous
        // solution range according to actual and expected number of blocks per era.
        let actual_slots_per_block = era_slot_count as f64 / T::EraDuration::get() as f64;
        let expected_slots_per_block = slot_probability.1 as f64 / slot_probability.0 as f64;
        let adjustment_factor =
            (actual_slots_per_block / expected_slots_per_block).clamp(0.25, 4.0);

        // TODO: Temporary testnet hack, we don't update solution range for the first 15_000 blocks
        //  in order to seed the blockchain with data quickly
        #[cfg(all(feature = "no-early-solution-range-updates", not(test)))]
        let solution_range = if block_number < 15_000_u32.into() {
            previous_solution_range
        } else {
            (previous_solution_range as f64 * adjustment_factor).round() as u64
        };
        #[cfg(not(all(feature = "no-early-solution-range-updates", not(test))))]
        let solution_range = (previous_solution_range as f64 * adjustment_factor).round() as u64;

        SolutionRange::<T>::put(solution_range);
        EraStartSlot::<T>::put(current_slot);

        Self::deposit_consensus(ConsensusLog::NextSolutionRangeData(
            NextSolutionRangeDescriptor { solution_range },
        ));
    }

    /// DANGEROUS: Enact an eon change. Should be done on every block where `should_eon_change` has returned `true`,
    /// and the caller is the only caller of this function.
    ///
    /// Typically, this is not handled directly by the user, but by higher-level validator-set manager logic like
    /// `pallet-session`.
    pub fn enact_eon_change() {
        // PRECONDITION: caller has done initialization and is guaranteed
        // by the session module to be called before this.
        debug_assert!(Self::initialized().is_some());

        // Update eon index
        let eon_index = EonIndex::<T>::get()
            .checked_add(1)
            .expect("eon indices will never reach 2^64 before the death of the universe; qed");

        EonIndex::<T>::put(eon_index);

        let salt = eon_index;

        Salt::<T>::put(salt);

        Self::deposit_consensus(ConsensusLog::NextSaltData(NextSaltDescriptor { salt }));
    }

    /// Finds the start slot of the current epoch. only guaranteed to
    /// give correct results after `do_initialize` of the first block
    /// in the chain (as its result is based off of `GenesisSlot`).
    pub fn current_epoch_start() -> Slot {
        Self::epoch_start(EpochIndex::<T>::get())
    }

    /// Finds the start slot of the current eon. only guaranteed to
    /// give correct results after `do_initialize` of the first block
    /// in the chain (as its result is based off of `GenesisSlot`).
    pub fn current_eon_start() -> Slot {
        Self::eon_start(EonIndex::<T>::get())
    }

    /// Produces information about the current epoch.
    pub fn current_epoch() -> Epoch {
        Epoch {
            epoch_index: EpochIndex::<T>::get(),
            start_slot: Self::current_epoch_start(),
            duration: T::EpochDuration::get(),
            randomness: Self::randomness(),
            config: EpochConfig::<T>::get()
                .expect("EpochConfig is initialized in genesis; we never `take` or `kill` it; qed"),
        }
    }

    /// Produces information about the next epoch (which was already previously
    /// announced).
    pub fn next_epoch() -> Epoch {
        let next_epoch_index = EpochIndex::<T>::get().checked_add(1).expect(
            "epoch index is u64; it is always only incremented by one; \
			 if u64 is not enough we should crash for safety; qed.",
        );

        Epoch {
            epoch_index: next_epoch_index,
            start_slot: Self::epoch_start(next_epoch_index),
            duration: T::EpochDuration::get(),
            randomness: NextRandomness::<T>::get(),
            config: NextEpochConfig::<T>::get().unwrap_or_else(|| {
                EpochConfig::<T>::get().expect(
                    "EpochConfig is initialized in genesis; we never `take` or `kill` it; qed",
                )
            }),
        }
    }

    fn epoch_start(epoch_index: u64) -> Slot {
        // (epoch_index * epoch_duration) + genesis_slot

        const PROOF: &str = "slot number is u64; it should relate in some way to wall clock time; \
							 if u64 is not enough we should crash for safety; qed.";

        let epoch_start = epoch_index
            .checked_mul(T::EpochDuration::get())
            .expect(PROOF);

        epoch_start
            .checked_add(*GenesisSlot::<T>::get())
            .expect(PROOF)
            .into()
    }

    fn eon_start(eon_index: u64) -> Slot {
        // (eon_index * eon_duration) + genesis_slot

        const PROOF: &str =
            "slot number is u64; it should relate in some way to wall clock time; if u64 is not \
            enough we should crash for safety; qed.";

        let eon_start = eon_index.checked_mul(T::EonDuration::get()).expect(PROOF);

        eon_start
            .checked_add(*GenesisSlot::<T>::get())
            .expect(PROOF)
            .into()
    }

    fn deposit_consensus<U: Encode>(new: U) {
        let log = DigestItem::Consensus(SUBSPACE_ENGINE_ID, new.encode());
        <frame_system::Pallet<T>>::deposit_log(log)
    }

    fn deposit_randomness(randomness: &subspace_core_primitives::Randomness) {
        let segment_idx = SegmentIndex::<T>::get();
        let mut segment = UnderConstruction::<T>::get(&segment_idx);
        if segment.try_push(*randomness).is_ok() {
            // push onto current segment: not full.
            UnderConstruction::<T>::insert(&segment_idx, &segment);
        } else {
            // move onto the next segment and update the index.
            let segment_idx = segment_idx + 1;
            let bounded_randomness =
                BoundedVec::<_, ConstU32<UNDER_CONSTRUCTION_SEGMENT_LENGTH>>::try_from(vec![
                    *randomness,
                ])
                .expect("UNDER_CONSTRUCTION_SEGMENT_LENGTH >= 1");
            UnderConstruction::<T>::insert(&segment_idx, bounded_randomness);
            SegmentIndex::<T>::put(&segment_idx);
        }
    }

    fn do_initialize(now: T::BlockNumber) {
        let maybe_pre_digest: Option<PreDigest> = <frame_system::Pallet<T>>::digest()
            .logs
            .iter()
            .filter_map(|s| s.as_pre_runtime())
            .find_map(|(id, mut data)| {
                if id == SUBSPACE_ENGINE_ID {
                    PreDigest::decode(&mut data).ok()
                } else {
                    None
                }
            });

        let maybe_randomness: MaybeRandomness = maybe_pre_digest.map(|digest| {
            // on the first non-zero block (i.e. block #1)
            // this is where the first epoch (epoch #0) actually starts.
            // we need to adjust internal storage accordingly.
            if *GenesisSlot::<T>::get() == 0 {
                GenesisSlot::<T>::put(digest.slot);
                debug_assert_ne!(*GenesisSlot::<T>::get(), 0);

                // deposit a log because this is the first block in epoch #0
                // we use the same values as genesis because we haven't collected any
                // randomness yet.
                let next = NextEpochDescriptor {
                    randomness: Self::randomness(),
                };

                Self::deposit_consensus(ConsensusLog::NextEpochData(next))
            }

            // the slot number of the current block being initialized
            let current_slot = digest.slot;

            // how many slots were skipped between current and last block
            let lateness = current_slot.saturating_sub(CurrentSlot::<T>::get() + 1);
            let lateness = T::BlockNumber::from(*lateness as u32);

            Lateness::<T>::put(lateness);
            CurrentSlot::<T>::put(current_slot);

            sp_io::hashing::blake2_256(&digest.solution.signature)
        });

        // For PoR output we place it in the `Initialized` storage
        // item and it'll be put onto the under-construction randomness later,
        // once we've decided which epoch this block is in.
        Initialized::<T>::put(maybe_randomness);

        // Place PoR output into the `AuthorPorRandomness` storage item.
        AuthorPorRandomness::<T>::put(maybe_randomness);

        // Deposit solution range data such that light client can validate blocks later.
        Self::deposit_consensus(ConsensusLog::SolutionRangeData(SolutionRangeDescriptor {
            solution_range: SolutionRange::<T>::get().unwrap_or_else(T::InitialSolutionRange::get),
        }));
        // Deposit salt data such that light client can validate blocks later.
        Self::deposit_consensus(ConsensusLog::SaltData(SaltDescriptor {
            salt: Salt::<T>::get(),
        }));

        // enact epoch change, if necessary.
        T::EpochChangeTrigger::trigger::<T>(now);
        // enact era change, if necessary.
        T::EraChangeTrigger::trigger::<T>(now);
        // enact eon change, if necessary.
        T::EonChangeTrigger::trigger::<T>(now);
    }

    /// Call this function exactly once when an epoch changes, to update the
    /// randomness. Returns the new randomness.
    fn randomness_change_epoch(next_epoch_index: u64) -> subspace_core_primitives::Randomness {
        let this_randomness = NextRandomness::<T>::get();
        let segment_idx: u32 = SegmentIndex::<T>::mutate(|s| sp_std::mem::replace(s, 0));

        // overestimate to the segment being full.
        let rho_size = (segment_idx.saturating_add(1) * UNDER_CONSTRUCTION_SEGMENT_LENGTH) as usize;

        let next_randomness = compute_randomness(
            this_randomness,
            next_epoch_index,
            (0..segment_idx).flat_map(|i| UnderConstruction::<T>::take(&i)),
            Some(rho_size),
        );
        NextRandomness::<T>::put(&next_randomness);
        this_randomness
    }

    fn do_report_equivocation(
        equivocation_proof: EquivocationProof<T::Header>,
    ) -> DispatchResultWithPostInfo {
        let offender = equivocation_proof.offender.clone();
        let slot = equivocation_proof.slot;

        // validate the equivocation proof
        if !sp_consensus_subspace::check_equivocation_proof(equivocation_proof) {
            return Err(Error::<T>::InvalidEquivocationProof.into());
        }

        let offence = SubspaceEquivocationOffence { slot, offender };

        T::HandleEquivocation::report_offence(offence)
            .map_err(|_| Error::<T>::DuplicateOffenceReport)?;

        // waive the fee since the report is valid and beneficial
        Ok(Pays::No.into())
    }

    fn do_store_root_blocks(root_blocks: Vec<RootBlock>) -> DispatchResult {
        for root_block in root_blocks {
            RecordsRoot::<T>::insert(root_block.segment_index(), root_block.records_root());
            Self::deposit_event(Event::RootBlockStored(root_block));
        }
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
}

/// Methods for the `ValidateUnsigned` implementation:
/// It restricts calls to `store_root_block` to local calls (i.e. extrinsics generated on this
/// node) or that already in a block. This guarantees that only block authors can include root
/// blocks.
impl<T: Config> Pallet<T> {
    pub fn validate_root_block(source: TransactionSource, call: &Call<T>) -> TransactionValidity {
        if let Call::store_root_blocks { root_blocks } = call {
            // Discard root block not coming from the local node
            if !matches!(
                source,
                TransactionSource::Local | TransactionSource::InBlock,
            ) {
                log::warn!(
                    target: "runtime::subspace",
                    "Rejecting root block extrinsic because it is not local/in-block.",
                );

                return InvalidTransaction::Call.into();
            }

            check_root_blocks::<T>(root_blocks)?;

            ValidTransaction::with_tag_prefix("SubspaceRootBlock")
                // We assign the maximum priority for any equivocation report.
                .priority(TransactionPriority::MAX)
                // Should be included immediately into the upcoming block with no exceptions.
                .longevity(0)
                // We don't propagate this. This can never be included on a remote node.
                .propagate(false)
                .build()
        } else {
            InvalidTransaction::Call.into()
        }
    }

    pub fn pre_dispatch_root_block(call: &Call<T>) -> Result<(), TransactionValidityError> {
        if let Call::store_root_blocks { root_blocks } = call {
            check_root_blocks::<T>(root_blocks)?;

            Ok(())
        } else {
            Err(InvalidTransaction::Call.into())
        }
    }
}

fn check_root_blocks<T: Config>(root_blocks: &[RootBlock]) -> Result<(), TransactionValidityError> {
    let mut root_blocks_iter = root_blocks.iter();

    // There should be some root blocks
    let first_root_block = match root_blocks_iter.next() {
        Some(first_root_block) => first_root_block,
        None => {
            return Err(InvalidTransaction::BadMandatory.into());
        }
    };

    // Segment in root blocks should monotonically increase
    if first_root_block.segment_index() > 0
        && !RecordsRoot::<T>::contains_key(first_root_block.segment_index() - 1)
    {
        return Err(InvalidTransaction::BadMandatory.into());
    }

    // Root blocks should never repeat
    if RecordsRoot::<T>::contains_key(first_root_block.segment_index()) {
        return Err(InvalidTransaction::BadMandatory.into());
    }

    let mut last_segment_index = first_root_block.segment_index();

    for root_block in root_blocks_iter {
        let segment_index = root_block.segment_index();

        // Segment in root blocks should monotonically increase
        if segment_index != last_segment_index + 1 {
            return Err(InvalidTransaction::BadMandatory.into());
        }

        // Root blocks should never repeat
        if RecordsRoot::<T>::contains_key(segment_index) {
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
            CurrentSlot::<T>::get(),
            timestamp_slot,
            "Timestamp slot must match `CurrentSlot`",
        );
    }
}

impl<T: Config> frame_support::traits::Lateness<T::BlockNumber> for Pallet<T> {
    fn lateness(&self) -> T::BlockNumber {
        Self::lateness()
    }
}

impl<T: Config> sp_runtime::BoundToRuntimeAppPublic for Pallet<T> {
    type Public = FarmerPublicKey;
}

impl<T: Config> OnOffenceHandler<FarmerPublicKey> for Pallet<T> {
    fn on_offence(offenders: &[OffenceDetails<FarmerPublicKey>]) {
        for offender in offenders {
            BlockList::<T>::insert(offender.offender.clone(), ());
        }
    }
}

// Compute randomness for a new epoch. rho is the concatenation of all
// PoR outputs in the prior epoch.
//
// An optional size hint as to how many PoR outputs there were may be provided.
fn compute_randomness(
    last_epoch_randomness: subspace_core_primitives::Randomness,
    epoch_index: u64,
    rho: impl Iterator<Item = subspace_core_primitives::Randomness>,
    rho_size_hint: Option<usize>,
) -> subspace_core_primitives::Randomness {
    let mut s = Vec::with_capacity(40 + rho_size_hint.unwrap_or(0) * RANDOMNESS_LENGTH);
    s.extend_from_slice(&last_epoch_randomness);
    s.extend_from_slice(&epoch_index.to_le_bytes());

    for output in rho {
        s.extend_from_slice(&output[..]);
    }

    sp_io::hashing::blake2_256(&s)
}
