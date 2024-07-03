//! Migration module for pallet-domains

use crate::Config;
use frame_support::traits::UncheckedOnRuntimeUpgrade;
use frame_support::weights::Weight;

pub struct VersionUncheckedMigrateV0ToV1<T>(sp_std::marker::PhantomData<T>);
impl<T: Config> UncheckedOnRuntimeUpgrade for VersionUncheckedMigrateV0ToV1<T> {
    fn on_runtime_upgrade() -> Weight {
        runtime_registry_instance_count_migration::migrate_runtime_registry_storages::<T>()
    }
}

pub(super) mod runtime_registry_instance_count_migration {
    use crate::pallet::{DomainRegistry, RuntimeRegistry as RuntimeRegistryV1};
    use crate::{Config, DomainSudoCalls};
    #[cfg(not(feature = "std"))]
    use alloc::string::String;
    use codec::{Decode, Encode};
    use frame_support::pallet_prelude::{OptionQuery, TypeInfo, Weight};
    use frame_support::{storage_alias, Identity};
    use frame_system::pallet_prelude::BlockNumberFor;
    use sp_core::Get;
    use sp_domains::storage::RawGenesis;
    use sp_domains::{DomainSudoCall, RuntimeId, RuntimeObject as RuntimeObjectV1, RuntimeType};
    use sp_version::RuntimeVersion;

    #[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
    pub struct RuntimeObject<Number, Hash> {
        pub runtime_name: String,
        pub runtime_type: RuntimeType,
        pub runtime_upgrades: u32,
        pub hash: Hash,
        // The raw genesis storage that contains the runtime code.
        // NOTE: don't use this field directly but `into_complete_raw_genesis` instead
        pub raw_genesis: RawGenesis,
        pub version: RuntimeVersion,
        pub created_at: Number,
        pub updated_at: Number,
    }

    #[storage_alias]
    pub type RuntimeRegistry<T: Config> = StorageMap<
        crate::Pallet<T>,
        Identity,
        RuntimeId,
        RuntimeObject<BlockNumberFor<T>, <T as frame_system::Config>::Hash>,
        OptionQuery,
    >;

    // Return the number of domain instance that instantiated with the given runtime
    fn domain_instance_count<T: Config>(runtime_id: RuntimeId) -> (u32, u64) {
        let mut read_write_count = 0;
        (
            DomainRegistry::<T>::iter()
                .filter(|(domain_id, domain_obj)| {
                    read_write_count += 1;
                    DomainSudoCalls::<T>::insert(domain_id, DomainSudoCall { maybe_call: None });
                    domain_obj.domain_config.runtime_id == runtime_id
                })
                .count() as u32,
            read_write_count,
        )
    }

    /// Indexes the currently used operator's signing keys into v2 domains storage.
    pub(super) fn migrate_runtime_registry_storages<T: Config>() -> Weight {
        let (mut read_count, mut write_count) = (0, 0);
        RuntimeRegistry::<T>::drain().for_each(|(runtime_id, runtime_obj)| {
            let (instance_count, domain_read_write_count) = domain_instance_count::<T>(runtime_id);
            RuntimeRegistryV1::<T>::set(
                runtime_id,
                Some(RuntimeObjectV1 {
                    runtime_name: runtime_obj.runtime_name,
                    runtime_type: runtime_obj.runtime_type,
                    runtime_upgrades: runtime_obj.runtime_upgrades,
                    instance_count,
                    hash: runtime_obj.hash,
                    raw_genesis: runtime_obj.raw_genesis,
                    version: runtime_obj.version,
                    created_at: runtime_obj.created_at,
                    updated_at: runtime_obj.updated_at,
                }),
            );

            // domain_read_count + 1 since we read the old runtime registry as well
            read_count += domain_read_write_count + 1;
            // 1 write to new registry and 1 for old registry + domain_write_count to load Sudo Domain runtime call.
            write_count += 2 + domain_read_write_count;
        });

        T::DbWeight::get().reads_writes(read_count, write_count)
    }
}

#[cfg(test)]
mod tests {
    use crate::domain_registry::{do_instantiate_domain, DomainConfig};
    use crate::migrations::runtime_registry_instance_count_migration::{
        RuntimeObject, RuntimeRegistry,
    };
    use crate::pallet::RuntimeRegistry as RuntimeRegistryV1;
    use crate::tests::{new_test_ext, Balances, Test};
    use crate::{Config, DomainSudoCalls};
    use domain_runtime_primitives::{AccountId20, AccountId20Converter};
    use frame_support::pallet_prelude::Weight;
    use frame_support::traits::Currency;
    use hex_literal::hex;
    use sp_domains::storage::RawGenesis;
    use sp_domains::{DomainId, OperatorAllowList, RuntimeObject as RuntimeObjectV1};
    use sp_runtime::traits::Convert;
    use sp_version::RuntimeVersion;
    use subspace_runtime_primitives::SSC;

    #[test]
    fn test_migrate_runtime_registry() {
        let mut ext = new_test_ext();
        let domain_config = DomainConfig {
            domain_name: "evm-domain".to_owned(),
            runtime_id: 0,
            max_block_size: 10,
            max_block_weight: Weight::from_parts(1, 0),
            bundle_slot_probability: (1, 1),
            target_bundles_per_block: 1,
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: vec![(
                AccountId20Converter::convert(AccountId20::from(hex!(
                    "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
                ))),
                1_000_000 * SSC,
            )],
        };
        let creator = 1u128;

        ext.execute_with(|| {
            // create old registry
            RuntimeRegistry::<Test>::insert(
                domain_config.runtime_id,
                RuntimeObject {
                    runtime_name: "evm".to_owned(),
                    runtime_type: Default::default(),
                    runtime_upgrades: 0,
                    hash: Default::default(),
                    raw_genesis: RawGenesis::dummy(vec![1, 2, 3, 4]),
                    version: RuntimeVersion {
                        spec_name: "test".into(),
                        spec_version: 1,
                        impl_version: 1,
                        transaction_version: 1,
                        ..Default::default()
                    },
                    created_at: Default::default(),
                    updated_at: Default::default(),
                },
            );

            // create new registry so that domain instantiation can get through
            RuntimeRegistryV1::<Test>::insert(
                domain_config.runtime_id,
                RuntimeObjectV1 {
                    runtime_name: "evm".to_owned(),
                    runtime_type: Default::default(),
                    runtime_upgrades: 0,
                    instance_count: 0,
                    hash: Default::default(),
                    raw_genesis: RawGenesis::dummy(vec![1, 2, 3, 4]),
                    version: RuntimeVersion {
                        spec_name: "test".into(),
                        spec_version: 1,
                        impl_version: 1,
                        transaction_version: 1,
                        ..Default::default()
                    },
                    created_at: Default::default(),
                    updated_at: Default::default(),
                },
            );

            // Set enough fund to creator
            Balances::make_free_balance_be(
                &creator,
                <Test as Config>::DomainInstantiationDeposit::get()
                    // for domain total issuance
                    + 1_000_000 * SSC
                    + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
            );

            do_instantiate_domain::<Test>(domain_config.clone(), creator, 0u64).unwrap();
        });

        ext.commit_all().unwrap();

        ext.execute_with(|| {
            let weights =
                crate::migrations::runtime_registry_instance_count_migration::migrate_runtime_registry_storages::<Test>();
            assert_eq!(
                weights,
                <Test as frame_system::Config>::DbWeight::get().reads_writes(2, 3),
            );

            assert_eq!(
                RuntimeRegistryV1::<Test>::get(0).unwrap().instance_count,
                1
            );

            assert!(DomainSudoCalls::<Test>::contains_key(DomainId::new(0)));
        });
    }
}
