#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod tests;
pub mod weights;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use crate::weights::WeightInfo;
    use frame_support::pallet_prelude::*;
    use frame_support::traits::BuildGenesisConfig;
    use frame_system::pallet_prelude::*;
    use scale_info::prelude::vec::Vec;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::error]
    pub enum Error<T> {
        /// The sender is not authorized to seed history
        NotAuthorized,
    }

    #[pallet::storage]
    #[pallet::getter(fn history_seeder)]
    pub(super) type HistorySeeder<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Seed history with a remark
        #[pallet::call_index(0)]
        #[pallet::weight((T::WeightInfo::seed_history(remark.len() as u32), Pays::No))]
        pub fn seed_history(origin: OriginFor<T>, remark: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin.clone())?;

            ensure!(
                Some(who.clone()) == Self::history_seeder(),
                Error::<T>::NotAuthorized
            );

            let _ = remark;

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::set_history_seeder())]
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
            if let Some(seeder) = &self.history_seeder {
                HistorySeeder::<T>::put(seeder);
            }
        }
    }
}
