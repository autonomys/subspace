#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::pallet_prelude::*;
use frame_support::traits::{BuildGenesisConfig, Get};

#[cfg(test)]
mod tests;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_system::pallet_prelude::*;
    use frame_system::{RawOrigin, WeightInfo};
    use scale_info::prelude::vec::Vec;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// History was seeded. [who, remark_size]
        HistorySeeded { who: T::AccountId, remark_size: u32 },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// The sender is not authorized to seed history
        NotAuthorized,
    }

    #[pallet::storage]
    #[pallet::getter(fn history_seeder)]
    pub type HistorySeeder<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Seed history with a remark
        /// TODO: add proper weight
        #[pallet::call_index(0)]
        #[pallet::weight((<T as frame_system::Config>::SystemWeightInfo::remark(remark.len() as u32) + T::DbWeight::get().reads(1), Pays::No))]
        pub fn seed_history(origin: OriginFor<T>, remark: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin.clone())?;

            // Ensure the sender is the authorized history seeder
            ensure!(
                Some(who.clone()) == Self::history_seeder(),
                Error::<T>::NotAuthorized
            );

            // Add the remark to the block
            frame_system::Pallet::<T>::remark(
                RawOrigin::Signed(who.clone()).into(),
                remark.clone(),
            )
            .map_err(|e| e.error)?;

            // Emit an event
            Self::deposit_event(Event::HistorySeeded {
                who,
                remark_size: remark.len() as u32,
            });

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::DbWeight::get().writes(1))]
        pub fn set_history_seeder(
            origin: OriginFor<T>,
            new_seeder: T::AccountId,
        ) -> DispatchResult {
            ensure_root(origin)?;
            HistorySeeder::<T>::put(new_seeder);
            Ok(())
        }
    }

    #[derive(frame_support::DefaultNoBound)]
    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub history_seeder: Option<T::AccountId>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            if let Some(ref seeder) = self.history_seeder {
                HistorySeeder::<T>::put(seeder);
            }
        }
    }
}
