//! Migration module for pallet-domains

use crate::{Config, Pallet};
use core::marker::PhantomData;
use frame_support::migrations::VersionedMigration;
use frame_support::traits::UncheckedOnRuntimeUpgrade;
use frame_support::weights::Weight;

pub type VersionCheckedMigrateDomainsV1ToV5<T> = VersionedMigration<
    1,
    5,
    VersionUncheckedMigrateV1ToV5<T>,
    Pallet<T>,
    <T as frame_system::Config>::DbWeight,
>;

pub struct VersionUncheckedMigrateV1ToV5<T>(PhantomData<T>);
impl<T: Config> UncheckedOnRuntimeUpgrade for VersionUncheckedMigrateV1ToV5<T> {
    fn on_runtime_upgrade() -> Weight {
        Weight::zero()
    }
}
