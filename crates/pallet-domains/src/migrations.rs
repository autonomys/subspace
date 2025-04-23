//! Migration module for pallet-domains
//!
//! TODO: remove this module after it has been deployed to Taurus.

#[cfg(not(feature = "std"))]
extern crate alloc;
use crate::{Config, Pallet};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
use frame_support::migrations::VersionedMigration;
use frame_support::traits::UncheckedOnRuntimeUpgrade;
use frame_support::weights::Weight;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

pub type VersionCheckedMigrateDomainsV3ToV4<T> = VersionedMigration<
    3,
    4,
    VersionUncheckedMigrateV3ToV4<T>,
    Pallet<T>,
    <T as frame_system::Config>::DbWeight,
>;

pub struct VersionUncheckedMigrateV3ToV4<T>(sp_std::marker::PhantomData<T>);
impl<T: Config> UncheckedOnRuntimeUpgrade for VersionUncheckedMigrateV3ToV4<T> {
    fn on_runtime_upgrade() -> Weight {
        domain_balance_check_migration_migration::migrate_domain_balance_check::<T>()
            .saturating_add(
                domain_balance_check_migration_migration::migrate_domain_share_price_check::<T>(),
            )
    }
}

mod domain_balance_check_migration_migration {
    use super::{BTreeSet, Config};
    use crate::staking::DomainEpoch;
    use crate::{AllowedDefaultSharePriceEpoch, DomainStakingSummary, SkipBalanceChecks};
    use frame_support::pallet_prelude::Weight;
    use sp_core::Get;
    use sp_domains::DomainId;

    pub(super) fn migrate_domain_balance_check<T: Config>() -> Weight {
        // 0 read and 1 write
        let list = BTreeSet::from([DomainId::new(0)]);
        SkipBalanceChecks::<T>::put(list);
        T::DbWeight::get().reads_writes(0, 1)
    }

    pub(super) fn migrate_domain_share_price_check<T: Config>() -> Weight {
        // 1 read and 1 write
        let domain_id = DomainId::new(0);
        if let Some(staking_summary) = DomainStakingSummary::<T>::get(domain_id) {
            AllowedDefaultSharePriceEpoch::<T>::put(DomainEpoch::from((
                domain_id,
                staking_summary.current_epoch_index,
            )));
        }
        T::DbWeight::get().reads_writes(1, 1)
    }
}
