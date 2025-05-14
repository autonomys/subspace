//! Migration module for pallet-messenger

use crate::{Config, Pallet};
use core::marker::PhantomData;
use frame_support::migrations::VersionedMigration;
use frame_support::traits::UncheckedOnRuntimeUpgrade;
use frame_support::weights::Weight;

pub type VersionCheckedMigrateDomainsV0ToV1<T> = VersionedMigration<
    0,
    1,
    VersionUncheckedMigrateV0ToV1<T>,
    Pallet<T>,
    <T as frame_system::Config>::DbWeight,
>;

pub struct VersionUncheckedMigrateV0ToV1<T>(PhantomData<T>);
impl<T: Config> UncheckedOnRuntimeUpgrade for VersionUncheckedMigrateV0ToV1<T> {
    fn on_runtime_upgrade() -> Weight {
        Weight::zero()
    }
}
