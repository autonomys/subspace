//! Migration module for pallet-domains

use crate::{AllowedDefaultSharePriceEpoch, AllowedMissingSharePriceEpoch, Config, Pallet};
use core::marker::PhantomData;
use frame_support::migrations::VersionedMigration;
use frame_support::traits::UncheckedOnRuntimeUpgrade;
use frame_support::weights::Weight;
use sp_core::Get;

pub type VersionCheckedMigrateDomainsV5ToV6<T> = VersionedMigration<
    5,
    6,
    VersionUncheckedMigrateV5ToV6<T>,
    Pallet<T>,
    <T as frame_system::Config>::DbWeight,
>;

pub struct VersionUncheckedMigrateV5ToV6<T>(PhantomData<T>);
impl<T: Config> UncheckedOnRuntimeUpgrade for VersionUncheckedMigrateV5ToV6<T> {
    fn on_runtime_upgrade() -> Weight {
        AllowedDefaultSharePriceEpoch::<T>::put(AllowedMissingSharePriceEpoch::get());
        T::DbWeight::get().writes(1)
    }
}
