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

use core::mem;
use equivocation::{HandleEquivocation, SubspaceEquivocationOffence};
use frame_support::{
    dispatch::{DispatchResult, DispatchResultWithPostInfo},
    traits::{Get, OnTimestampSet},
    weights::{Pays, Weight},
};
#[cfg(not(feature = "std"))]
use num_traits::float::FloatCore;
pub use pallet::*;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    CompatibleDigestItem, CompatibleDigestItemRef, GlobalRandomnessDescriptor, SaltDescriptor,
    SolutionRangeDescriptor,
};
use sp_consensus_subspace::offence::{OffenceDetails, OnOffenceHandler};
use sp_consensus_subspace::{EquivocationProof, FarmerPublicKey};
use sp_io::hashing;
use sp_runtime::generic::{DigestItem, DigestItemRef};
use sp_runtime::traits::{BlockNumberProvider, Hash, SaturatedConversion, Saturating, Zero};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
    TransactionValidityError, ValidTransaction,
};
use sp_runtime::ConsensusEngineId;
use sp_std::prelude::*;
use subspace_core_primitives::{
    crypto, Randomness, RootBlock, Signature, PIECE_SIZE, RANDOMNESS_LENGTH, SALT_SIZE,
};

const GLOBAL_CHALLENGE_HASHING_PREFIX: &[u8] = b"global_challenge";
const GLOBAL_CHALLENGE_HASHING_PREFIX_LEN: usize = GLOBAL_CHALLENGE_HASHING_PREFIX.len();
const SALT_HASHING_PREFIX: &[u8] = b"salt";
const SALT_HASHING_PREFIX_LEN: usize = SALT_HASHING_PREFIX.len();

pub trait WeightInfo {
    fn report_equivocation() -> Weight;
    fn store_root_blocks(root_blocks_count: usize) -> Weight;
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
            <Pallet<T>>::enact_era_change(block_number);
        }
    }
}

/// Trigger an era change, if any should take place.
pub trait EonChangeTrigger {
    /// Trigger an era change, if any should take place. This should be called
    /// during every block, after initialization is done.
    fn trigger<T: Config>(block_number: T::BlockNumber);
}

/// A type signifying to Subspace that it should perform era changes with an internal trigger.
pub struct NormalEonChange;

impl EonChangeTrigger for NormalEonChange {
    fn trigger<T: Config>(block_number: T::BlockNumber) {
        if <Pallet<T>>::should_eon_change(block_number) {
            <Pallet<T>>::enact_eon_change(block_number);
        }
    }
}

#[frame_support::pallet]
mod pallet {
    use super::{EonChangeTrigger, EraChangeTrigger, GlobalRandomnessIntervalTrigger, WeightInfo};
    use crate::equivocation::HandleEquivocation;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_consensus_slots::Slot;
    use sp_consensus_subspace::inherents::{InherentError, InherentType, INHERENT_IDENTIFIER};
    use sp_consensus_subspace::{EquivocationProof, FarmerPublicKey};
    use sp_std::prelude::*;
    use subspace_core_primitives::{RootBlock, Sha256Hash};

    pub(super) struct InitialSolutionRanges<T: Config> {
        _config: T,
    }

    impl<T: Config> Get<sp_consensus_subspace::SolutionRanges> for InitialSolutionRanges<T> {
        fn get() -> sp_consensus_subspace::SolutionRanges {
            sp_consensus_subspace::SolutionRanges {
                current: T::InitialSolutionRange::get(),
                next: None,
            }
        }
    }

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

        /// The amount of time, in blocks, between updates of global randomness.
        #[pallet::constant]
        type GlobalRandomnessUpdateInterval: Get<Self::BlockNumber>;

        /// The amount of time, in blocks, that each era should last.
        /// NOTE: Currently it is not possible to change the era duration after
        /// the chain has started. Attempting to do so will brick block production.
        #[pallet::constant]
        type EraDuration: Get<Self::BlockNumber>;

        /// The amount of time, in slots, that each eon should last.
        /// NOTE: Currently it is not possible to change the eon duration after
        /// the chain has started. Attempting to do so will brick block production.
        #[pallet::constant]
        type EonDuration: Get<u64>;

        /// The amount of time within eon, in slots, after which next eon salt should be revealed.
        ///
        /// The purpose of this is to allow to start tag recommitment a bit upfront, but not too
        /// soon. For instance, if eon duration is 7 days, this parameter may be set to 6 days worth
        /// of timeslots.
        #[pallet::constant]
        type EonNextSaltReveal: Get<u64>;

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
        type ConfirmationDepthK: Get<Self::BlockNumber>;

        /// The size of data in one piece (in bytes).
        #[pallet::constant]
        type RecordSize: Get<u32>;

        // TODO: This will probably become configurable later
        /// Recorded history is encoded and plotted in segments of this size (in bytes).
        #[pallet::constant]
        type RecordedHistorySegmentSize: Get<u32>;

        /// Subspace requires periodic global randomness update.
        type GlobalRandomnessIntervalTrigger: GlobalRandomnessIntervalTrigger;

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
        RootBlockStored { root_block: RootBlock },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// An equivocation proof provided as part of an equivocation report is invalid.
        InvalidEquivocationProof,
        /// A given equivocation report is valid but already previously reported.
        DuplicateOffenceReport,
    }

    /// Current eon index.
    #[pallet::storage]
    #[pallet::getter(fn eon_index)]
    pub type EonIndex<T> = StorageValue<_, u64, ValueQuery>;

    /// The slot at which the block was created. This is 0 until the first block of the chain.
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

    /// Salts used for challenges.
    #[pallet::storage]
    #[pallet::getter(fn salts)]
    pub type Salts<T> = StorageValue<_, sp_consensus_subspace::Salts, ValueQuery>;

    /// The solution range for *current* era.
    #[pallet::storage]
    pub type EraStartSlot<T> = StorageValue<_, Slot>;

    /// A set of blocked farmers keyed by their public key.
    #[pallet::storage]
    pub(super) type BlockList<T> = StorageMap<_, Twox64Concat, FarmerPublicKey, ()>;

    /// Mapping from segment index to corresponding merkle tree root of segment records.
    #[pallet::storage]
    #[pallet::getter(fn records_root)]
    pub(super) type RecordsRoot<T> = CountedStorageMap<_, Twox64Concat, u64, Sha256Hash>;

    /// Temporary value (cleared at block finalization) which contains current block PoR randomness.
    #[pallet::storage]
    pub(super) type PorRandomness<T> = StorageValue<_, subspace_core_primitives::Randomness>;

    #[pallet::hooks]
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_initialize(block_number: T::BlockNumber) -> Weight {
            Self::do_initialize(block_number);
            0
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

    /// Determine whether a randomness update should take place at this block.
    /// Assumes that initialization has already taken place.
    pub fn should_update_global_randomness(block_number: T::BlockNumber) -> bool {
        block_number % T::GlobalRandomnessUpdateInterval::get() == Zero::zero()
    }

    /// Determine whether an era change should take place at this block.
    /// Assumes that initialization has already taken place.
    pub fn should_era_change(block_number: T::BlockNumber) -> bool {
        block_number % T::EraDuration::get() == Zero::zero()
    }

    /// Determine whether an eon change should take place at this block.
    /// Assumes that initialization has already taken place.
    pub fn should_eon_change(_block_number: T::BlockNumber) -> bool {
        let diff = Self::current_slot().saturating_sub(Self::current_eon_start());
        *diff >= T::EonDuration::get()
    }

    /// DANGEROUS: Enact era change. Should be done on every block where `should_era_change` has
    /// returned `true`, and the caller is the only caller of this function.
    pub fn enact_update_global_randomness(
        _block_number: T::BlockNumber,
        por_randomness: Randomness,
    ) {
        GlobalRandomnesses::<T>::mutate(|global_randomnesses| {
            global_randomnesses.next = Some(por_randomness);
        });
    }

    /// DANGEROUS: Enact era change. Should be done on every block where `should_era_change` has
    /// returned `true`, and the caller is the only caller of this function.
    pub fn enact_era_change(block_number: T::BlockNumber) {
        let slot_probability = T::SlotProbability::get();

        let current_slot = Self::current_slot();

        SolutionRanges::<T>::mutate(|solution_ranges| {
            // If Era start slot is not found it means we have just finished the first era
            let era_start_slot = EraStartSlot::<T>::get().unwrap_or_else(GenesisSlot::<T>::get);
            let era_slot_count = u64::from(current_slot) - u64::from(era_start_slot);

            // Now we need to re-calculate solution range. The idea here is to keep block production at
            // the same pace while space pledged on the network changes. For this we adjust previous
            // solution range according to actual and expected number of blocks per era.
            let era_duration: u64 = T::EraDuration::get()
                .try_into()
                .unwrap_or_else(|_| panic!("Era duration is always within u64; qed"));
            let actual_slots_per_block = era_slot_count as f64 / era_duration as f64;
            let expected_slots_per_block = slot_probability.1 as f64 / slot_probability.0 as f64;
            let adjustment_factor =
                (actual_slots_per_block / expected_slots_per_block).clamp(0.25, 4.0);

            solution_ranges.next.replace(
                // TODO: Temporary testnet hack, we don't update solution range for the first 15_000 blocks
                //  in order to seed the blockchain with data quickly
                if cfg!(all(feature = "no-early-solution-range-updates", not(test))) {
                    if block_number < 15_000_u32.into() {
                        solution_ranges.current
                    } else {
                        (solution_ranges.current as f64 * adjustment_factor).round() as u64
                    }
                } else {
                    (solution_ranges.current as f64 * adjustment_factor).round() as u64
                },
            );
        });

        EraStartSlot::<T>::put(current_slot);
    }

    /// DANGEROUS: Enact an eon change. Should be done on every block where `should_eon_change` has
    /// returned `true`, and the caller is the only caller of this function.
    pub fn enact_eon_change(_block_number: T::BlockNumber) {
        let current_slot = *Self::current_slot();
        let eon_index = current_slot
            .checked_sub(*GenesisSlot::<T>::get())
            .expect("Current slot is never lower than genesis slot; qed")
            .checked_div(T::EonDuration::get())
            .expect("Eon duration is never zero; qed");

        EonIndex::<T>::put(eon_index);
        Salts::<T>::mutate(|salts| {
            salts.switch_next_block = true;
        });
    }

    /// Finds the start slot of the current eon. Only guaranteed to give correct results after
    /// `do_initialize` of the first block in the chain (as its result is based off of
    /// `GenesisSlot`).
    pub fn current_eon_start() -> Slot {
        Self::eon_start(EonIndex::<T>::get())
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

        // If global randomness was updated in previous block, set it as current.
        if let Some(next_randomness) = GlobalRandomnesses::<T>::get().next {
            GlobalRandomnesses::<T>::put(sp_consensus_subspace::GlobalRandomnesses {
                current: next_randomness,
                next: None,
            });
        }

        // If solution range was updated in previous block, set it as current.
        if let Some(next_solution_range) = SolutionRanges::<T>::get().next {
            SolutionRanges::<T>::put(sp_consensus_subspace::SolutionRanges {
                current: next_solution_range,
                next: None,
            });
        }

        // Update current salt if needed
        {
            let salts = Salts::<T>::get();
            if salts.switch_next_block {
                if let Some(next_salt) = salts.next {
                    Salts::<T>::put(sp_consensus_subspace::Salts {
                        current: next_salt,
                        next: None,
                        switch_next_block: false,
                    });
                }
            }
        }

        // Extract PoR randomness from pre-digest.
        let por_randomness: Randomness = hashing::blake2_256(&{
            let mut input =
                [0u8; GLOBAL_CHALLENGE_HASHING_PREFIX_LEN + mem::size_of::<Signature>()];
            input[..GLOBAL_CHALLENGE_HASHING_PREFIX_LEN]
                .copy_from_slice(GLOBAL_CHALLENGE_HASHING_PREFIX);
            input[GLOBAL_CHALLENGE_HASHING_PREFIX_LEN..]
                .copy_from_slice(&pre_digest.solution.signature);

            input
        });
        // Store PoR randomness for block duration as it might be useful.
        PorRandomness::<T>::put(por_randomness);

        // Deposit global randomness data such that light client can validate blocks later.
        frame_system::Pallet::<T>::deposit_log(DigestItem::global_randomness_descriptor(
            GlobalRandomnessDescriptor {
                global_randomness: GlobalRandomnesses::<T>::get().current,
            },
        ));
        // Deposit solution range data such that light client can validate blocks later.
        frame_system::Pallet::<T>::deposit_log(DigestItem::solution_range_descriptor(
            SolutionRangeDescriptor {
                solution_range: SolutionRanges::<T>::get().current,
            },
        ));
        // Deposit salt data such that light client can validate blocks later.
        frame_system::Pallet::<T>::deposit_log(DigestItem::salt_descriptor(SaltDescriptor {
            salt: Salts::<T>::get().current,
        }));

        let next_salt_reveal = Self::current_eon_start()
            .checked_add(T::EonNextSaltReveal::get())
            .expect("Will not overflow until the end of universe; qed");
        let current_slot = Self::current_slot();
        #[cfg(feature = "std")]
        println!(
            "Self::current_eon_start() {} current_slot {} next_salt_reveal {}",
            Self::current_eon_start(),
            current_slot,
            next_salt_reveal
        );
        if current_slot >= next_salt_reveal {
            Salts::<T>::mutate(|salts| {
                if salts.next.is_none() {
                    let eon_index = Self::eon_index();
                    log::info!(
                        target: "runtime::subspace",
                        "🔃 Updating next salt on eon {} slot {}",
                        eon_index,
                        *current_slot
                    );
                    salts.next.replace(Self::derive_next_salt_from_randomness(
                        eon_index,
                        &por_randomness,
                    ));
                }
            });
        }

        // Enact global randomness update, if necessary.
        T::GlobalRandomnessIntervalTrigger::trigger::<T>(block_number, por_randomness);
        // Enact era change, if necessary.
        T::EraChangeTrigger::trigger::<T>(block_number);
        // Enact eon change, if necessary.
        T::EonChangeTrigger::trigger::<T>(block_number);
    }

    fn do_finalize(_block_number: T::BlockNumber) {
        PorRandomness::<T>::take();
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
            Self::deposit_event(Event::RootBlockStored { root_block });
        }
        Ok(())
    }

    fn derive_next_salt_from_randomness(
        eon_index: u64,
        randomness: &subspace_core_primitives::Randomness,
    ) -> subspace_core_primitives::Salt {
        crypto::sha256_hash({
            let mut input =
                [0u8; SALT_HASHING_PREFIX_LEN + RANDOMNESS_LENGTH + mem::size_of::<u64>()];
            input[..SALT_HASHING_PREFIX_LEN].copy_from_slice(SALT_HASHING_PREFIX);
            input[SALT_HASHING_PREFIX_LEN..SALT_HASHING_PREFIX_LEN + RANDOMNESS_LENGTH]
                .copy_from_slice(randomness);
            input[SALT_HASHING_PREFIX_LEN + RANDOMNESS_LENGTH..]
                .copy_from_slice(&eon_index.to_le_bytes());
            input
        })[..SALT_SIZE]
            .try_into()
            .expect("Slice has exactly the size needed; qed")
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
        let archived_segments = RecordsRoot::<T>::count();
        // `*2` because we need to include both data and parity pieces
        let archived_segment_size = T::RecordedHistorySegmentSize::get() / T::RecordSize::get()
            * u32::try_from(PIECE_SIZE)
                .expect("Piece size is definitely small enough to fit into u32; qed")
            * 2;

        u64::from(archived_segments) * u64::from(archived_segment_size)
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
            Self::current_slot(),
            timestamp_slot,
            "Timestamp slot must match `CurrentSlot`",
        );
    }
}

impl<T: Config> frame_support::traits::FindAuthor<T::AccountId> for Pallet<T> {
    fn find_author<'a, I>(digests: I) -> Option<T::AccountId>
    where
        I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
    {
        digests
            .into_iter()
            .find_map(|(id, data)| {
                // TODO: Simplify once https://github.com/paritytech/substrate/pull/10536 is merged
                DigestItemRef::PreRuntime(&id, &data.to_vec()).as_subspace_pre_digest()
            })
            .map(|pre_digest| pre_digest.solution.public_key)
    }
}

impl<T: Config> frame_support::traits::Randomness<T::Hash, T::BlockNumber> for Pallet<T> {
    fn random(subject: &[u8]) -> (T::Hash, T::BlockNumber) {
        let mut subject = subject.to_vec();
        subject.reserve(RANDOMNESS_LENGTH);
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
