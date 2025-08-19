//! Migration for EvmChainIds

use crate::{Config, Pallet};
use core::marker::PhantomData;
use frame_support::migrations::VersionedMigration;
use frame_support::traits::UncheckedOnRuntimeUpgrade;
use frame_support::weights::Weight;

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
        migrate_evm_chain_id::migrate_evm_chain_ids::<T>()
    }
}

mod migrate_evm_chain_id {
    use crate::pallet::DomainRegistry;
    use crate::{Config, EvmChainIds, Pallet};
    use domain_runtime_primitives::EVMChainId;
    use frame_support::pallet_prelude::ValueQuery;
    use frame_support::storage_alias;
    use sp_core::Get;
    use sp_domains::DomainRuntimeInfo;
    use sp_runtime::Weight;

    #[storage_alias]
    pub(super) type NextEVMChainId<T: Config> = StorageValue<Pallet<T>, EVMChainId, ValueQuery>;

    pub(super) fn migrate_evm_chain_ids<T: Config>() -> Weight {
        let (mut read, mut write) = (0, 0);
        // Kill the unused NextEVMChainId
        NextEVMChainId::<T>::kill();
        write += 1;

        DomainRegistry::<T>::iter().for_each(|(domain_id, domain_obj)| {
            read += 1;
            // chain_ids are already unique due to incrementer.
            // so it guarantees no duplicate chain_ids for different domains.
            if let DomainRuntimeInfo::Evm { chain_id, .. } = domain_obj.domain_runtime_info {
                EvmChainIds::<T>::insert(chain_id, domain_id);
                write += 1;
            }
        });

        T::DbWeight::get().reads_writes(read, write)
    }
}

#[cfg(test)]
mod tests {
    use crate::EvmChainIds;
    use crate::domain_registry::{DomainConfigParams, DomainObject, into_domain_config};
    use crate::migrations::v5_to_v6::migrate_evm_chain_id::{
        NextEVMChainId, migrate_evm_chain_ids,
    };
    use crate::pallet::DomainRegistry;
    use crate::tests::{AccountId, Test, new_test_ext};
    use domain_runtime_primitives::{Balance, DEFAULT_EVM_CHAIN_ID};
    use frame_support::weights::RuntimeDbWeight;
    use sp_domains::{DomainId, EvmDomainRuntimeConfig, OperatorAllowList};

    #[test]
    fn test_migrate_evm_chain_ids() {
        let mut ext = new_test_ext();

        // setup Domain registry
        let creator = 1u128;
        let created_at = 0u32;
        let domain_config_params = DomainConfigParams::<AccountId, Balance> {
            domain_name: "evm-domain".to_owned(),
            runtime_id: 0,
            maybe_bundle_limit: None,
            bundle_slot_probability: (1, 1),
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: vec![],
            domain_runtime_info: (DEFAULT_EVM_CHAIN_ID, EvmDomainRuntimeConfig::default()).into(),
        };

        let domain_obj = DomainObject {
            owner_account_id: creator,
            created_at,
            genesis_receipt_hash: Default::default(),
            domain_config: into_domain_config::<Test>(domain_config_params.clone()).unwrap(),
            domain_runtime_info: domain_config_params.domain_runtime_info,
            domain_instantiation_deposit: Default::default(),
        };
        ext.execute_with(|| {
            DomainRegistry::<Test>::insert(DomainId::new(0), domain_obj);
            NextEVMChainId::<Test>::set(871);
        });
        ext.commit_all().unwrap();

        // migrate
        ext.execute_with(|| {
            let weight = migrate_evm_chain_ids::<Test>();
            let db_weights: RuntimeDbWeight = <Test as frame_system::Config>::DbWeight::get();
            // we have 2 writes i.e... `NextEVMChainId` storage kill and `EvmChainIds` set
            // we have 1 read for `DomainRegistry`
            assert_eq!(weight, db_weights.reads_writes(1, 2));
        });

        ext.commit_all().unwrap();

        // verify
        ext.execute_with(|| {
            assert!(!NextEVMChainId::<Test>::exists());
            assert_eq!(
                EvmChainIds::<Test>::get(DEFAULT_EVM_CHAIN_ID),
                Some(DomainId::new(0))
            );
        })
    }
}
