//! Migrations for pallet-transporter.

use crate::{Config, Pallet};
use core::marker::PhantomData;
use frame_support::migrations::VersionedMigration;
use frame_support::traits::UncheckedOnRuntimeUpgrade;
use frame_support::weights::Weight;

/// Seeds `AllDomainsSupply` from the existing component storages on the introducing
/// runtime upgrade (storage version 0 -> 1).
pub type VersionCheckedMigrateTransporterV0ToV1<T> = VersionedMigration<
    0,
    1,
    VersionUncheckedMigrateV0ToV1<T>,
    Pallet<T>,
    <T as frame_system::Config>::DbWeight,
>;

pub struct VersionUncheckedMigrateV0ToV1<T>(PhantomData<T>);
impl<T: Config> UncheckedOnRuntimeUpgrade for VersionUncheckedMigrateV0ToV1<T> {
    fn on_runtime_upgrade() -> Weight {
        seed_all_domains_supply::seed::<T>()
    }
}

mod seed_all_domains_supply {
    use crate::{
        AllDomainsSupply, BalanceOf, CancelledTransfers, Config, DomainBalances,
        UnconfirmedTransfers,
    };
    use frame_support::traits::{Defensive, Get};
    use frame_support::weights::Weight;
    use sp_runtime::traits::{CheckedAdd, Zero};

    pub(super) fn seed<T: Config>() -> Weight {
        // AllDomainsSupply is only read on the consensus runtime; on domains the aggregate is
        // unused, so skip the seed and let the versioned migration only bump the storage version.
        if !T::SelfChainId::get().is_consensus_chain() {
            return Weight::zero();
        }

        let mut reads: u64 = 0;
        let mut total = BalanceOf::<T>::zero();
        for value in DomainBalances::<T>::iter_values() {
            reads += 1;
            total = total.checked_add(&value).defensive_unwrap_or(total);
        }
        for value in UnconfirmedTransfers::<T>::iter_values() {
            reads += 1;
            total = total.checked_add(&value).defensive_unwrap_or(total);
        }
        for value in CancelledTransfers::<T>::iter_values() {
            reads += 1;
            total = total.checked_add(&value).defensive_unwrap_or(total);
        }

        AllDomainsSupply::<T>::put(total);

        // Fixed base plus one read per component-storage entry and the single aggregate write.
        let base_weight = T::DbWeight::get().reads_writes(1, 1);
        base_weight.saturating_add(T::DbWeight::get().reads(reads))
    }
}

#[cfg(test)]
mod tests {
    use super::VersionCheckedMigrateTransporterV0ToV1;
    use super::seed_all_domains_supply::seed;
    use crate::mock::consensus::{ConsensusMockRuntime, new_test_ext as new_consensus_test_ext};
    use crate::mock::{MockRuntime, assert_all_domains_supply_reconciles, new_test_ext};
    use crate::{
        AllDomainsSupply, CancelledTransfers, DomainBalances, Pallet, UnconfirmedTransfers,
    };
    use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};
    use sp_domains::DomainId;
    use sp_messenger::messages::ChainId;

    #[test]
    fn seed_migration_sets_aggregate_from_existing_storage() {
        new_consensus_test_ext().execute_with(|| {
            let domain = DomainId::new(0);
            DomainBalances::<ConsensusMockRuntime>::insert(domain, 500u64);
            UnconfirmedTransfers::<ConsensusMockRuntime>::insert(
                ChainId::Consensus,
                ChainId::Domain(domain),
                70u64,
            );
            CancelledTransfers::<ConsensusMockRuntime>::insert(
                ChainId::Domain(domain),
                ChainId::Consensus,
                5u64,
            );
            // aggregate deliberately left stale at 0 before the migration runs
            assert_eq!(AllDomainsSupply::<ConsensusMockRuntime>::get(), 0);

            seed::<ConsensusMockRuntime>();

            assert_eq!(Pallet::<ConsensusMockRuntime>::all_domains_supply(), 575);
            assert_all_domains_supply_reconciles::<ConsensusMockRuntime>();
        });
    }

    #[test]
    fn seed_migration_sums_multiple_entries_across_maps() {
        new_consensus_test_ext().execute_with(|| {
            DomainBalances::<ConsensusMockRuntime>::insert(DomainId::new(0), 100u64);
            DomainBalances::<ConsensusMockRuntime>::insert(DomainId::new(1), 200u64);
            DomainBalances::<ConsensusMockRuntime>::insert(DomainId::new(2), 300u64);
            UnconfirmedTransfers::<ConsensusMockRuntime>::insert(
                ChainId::Consensus,
                ChainId::Domain(DomainId::new(0)),
                10u64,
            );
            UnconfirmedTransfers::<ConsensusMockRuntime>::insert(
                ChainId::Consensus,
                ChainId::Domain(DomainId::new(1)),
                20u64,
            );
            CancelledTransfers::<ConsensusMockRuntime>::insert(
                ChainId::Domain(DomainId::new(0)),
                ChainId::Consensus,
                1u64,
            );
            CancelledTransfers::<ConsensusMockRuntime>::insert(
                ChainId::Domain(DomainId::new(1)),
                ChainId::Consensus,
                2u64,
            );

            seed::<ConsensusMockRuntime>();

            assert_eq!(Pallet::<ConsensusMockRuntime>::all_domains_supply(), 633);
            assert_all_domains_supply_reconciles::<ConsensusMockRuntime>();
        });
    }

    #[test]
    fn seed_migration_with_empty_maps_is_zero() {
        new_consensus_test_ext().execute_with(|| {
            seed::<ConsensusMockRuntime>();
            assert_eq!(Pallet::<ConsensusMockRuntime>::all_domains_supply(), 0);
            assert_all_domains_supply_reconciles::<ConsensusMockRuntime>();
        });
    }

    #[test]
    fn seed_migration_is_noop_on_domains() {
        new_test_ext().execute_with(|| {
            // On a domain the aggregate is unused, so the seed must skip even with populated maps.
            DomainBalances::<MockRuntime>::insert(DomainId::new(0), 500u64);
            UnconfirmedTransfers::<MockRuntime>::insert(
                ChainId::Consensus,
                ChainId::Domain(DomainId::new(0)),
                70u64,
            );

            seed::<MockRuntime>();

            assert_eq!(Pallet::<MockRuntime>::all_domains_supply(), 0);
        });
    }

    #[test]
    fn versioned_migration_seeds_once_and_is_idempotent() {
        new_consensus_test_ext().execute_with(|| {
            // start at on-chain version 0 (genesis otherwise sets it to 1)
            StorageVersion::new(0).put::<Pallet<ConsensusMockRuntime>>();
            DomainBalances::<ConsensusMockRuntime>::insert(DomainId::new(0), 500u64);
            UnconfirmedTransfers::<ConsensusMockRuntime>::insert(
                ChainId::Consensus,
                ChainId::Domain(DomainId::new(0)),
                70u64,
            );
            CancelledTransfers::<ConsensusMockRuntime>::insert(
                ChainId::Domain(DomainId::new(0)),
                ChainId::Consensus,
                5u64,
            );

            <VersionCheckedMigrateTransporterV0ToV1<ConsensusMockRuntime> as OnRuntimeUpgrade>::on_runtime_upgrade();
            assert_eq!(Pallet::<ConsensusMockRuntime>::all_domains_supply(), 575);
            assert_eq!(
                Pallet::<ConsensusMockRuntime>::on_chain_storage_version(),
                StorageVersion::new(1)
            );

            // second run is version-gated to a no-op: mutate a map, re-run, aggregate stays put
            DomainBalances::<ConsensusMockRuntime>::insert(DomainId::new(1), 1_000u64);
            <VersionCheckedMigrateTransporterV0ToV1<ConsensusMockRuntime> as OnRuntimeUpgrade>::on_runtime_upgrade();
            assert_eq!(
                Pallet::<ConsensusMockRuntime>::all_domains_supply(),
                575,
                "migration must be idempotent (version-gated)"
            );
        });
    }
}
