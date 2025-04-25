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

pub type VersionCheckedMigrateDomainsV4ToV5<T> = VersionedMigration<
    4,
    5,
    VersionUncheckedMigrateV3ToV4<T>,
    Pallet<T>,
    <T as frame_system::Config>::DbWeight,
>;

pub struct VersionUncheckedMigrateV4ToV5<T>(sp_std::marker::PhantomData<T>);
impl<T: Config> UncheckedOnRuntimeUpgrade for VersionUncheckedMigrateV4ToV5<T> {
    fn on_runtime_upgrade() -> Weight {
        domain_genesis_receipt::set_domain_genesis_receipt::<T>()
    }
}

mod domain_genesis_receipt {
    use super::Config;
    use crate::{DomainGenesisBlockExecutionReceipt, ExecutionReceiptOf};
    use hexlit::hex;
    use sp_core::{Get, H256};
    use sp_domains::DomainId;
    use sp_runtime::Weight;

    pub(super) fn set_domain_genesis_receipt<T: Config>() -> Weight {
        let genesis_state_root = T::DomainHash::from(H256::from(hex!(
            "0x530eae1878202aa0ab5997eadf2b7245ee78f44a35ab25ff84151fab489aa334"
        )));

        let genesis_block_hash = T::DomainHash::from(H256::from(hex!(
            "0x5a367ed131b9d8807f0166651095a9ed51aefa9aaec3152d3eb5cee322220ce6"
        )));

        let domain_0_genesis_er = ExecutionReceiptOf::<T>::genesis(
            genesis_state_root,
            sp_domains::EMPTY_EXTRINSIC_ROOT.into(),
            genesis_block_hash,
        );

        DomainGenesisBlockExecutionReceipt::<T>::insert(DomainId::new(0), domain_0_genesis_er);

        T::DbWeight::get().reads_writes(0, 1)
    }
}
