//! Migration module for pallet-domains EVM and AutoId domain config storage, versions 2 to 3.
//!
//! TODO: consider removing this module after it has been deployed to Taurus.
//! If we add EVM or AutoId domains to Mainnet, also deploy it there.
//! (If there are no EVM or AutoId domains, this migration does nothing, so it's safe to run.)

use crate::{Config, Pallet};
use frame_support::migrations::VersionedMigration;
use frame_support::traits::UncheckedOnRuntimeUpgrade;
use frame_support::weights::Weight;

pub type VersionCheckedMigrateDomainsV2ToV3<T> = VersionedMigration<
    2,
    3,
    VersionUncheckedMigrateV2ToV3<T>,
    Pallet<T>,
    <T as frame_system::Config>::DbWeight,
>;

pub struct VersionUncheckedMigrateV2ToV3<T>(sp_std::marker::PhantomData<T>);
impl<T: Config> UncheckedOnRuntimeUpgrade for VersionUncheckedMigrateV2ToV3<T> {
    fn on_runtime_upgrade() -> Weight {
        domain_registry_structure_migration::migrate_domain_registry_structure::<T>()
    }
}

mod domain_registry_structure_migration {
    // Types that have changed are imported or declared with a V2/V3 suffix.
    // Types that haven't changed are imported or declared without a suffix.
    pub(super) use crate::domain_registry::{DomainConfig, DomainObject as DomainObjectV3};
    pub(super) use crate::pallet::DomainRegistry as DomainRegistryV3;
    pub(super) use crate::runtime_registry::DomainRuntimeInfo as DomainRuntimeInfoV3;
    use crate::{BalanceOf, BlockNumberFor, Config, Pallet, ReceiptHashFor};
    use codec::{Decode, Encode};
    use domain_runtime_primitives::EVMChainId;
    use frame_support::pallet_prelude::{OptionQuery, TypeInfo, Weight};
    use frame_support::{storage_alias, Identity};
    use sp_core::Get;
    pub(super) use sp_domains::{
        AutoIdDomainRuntimeConfig as AutoIdDomainRuntimeConfigV3,
        DomainId,
        // changed in V3, but we use Into to convert to it
        // DomainRuntimeConfig as DomainRuntimeConfigV3,
        EvmDomainRuntimeConfig as EvmDomainRuntimeConfigV3,
    };

    /// Domain runtime specific information to create domain raw genesis.
    #[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq, Copy)]
    #[allow(clippy::upper_case_acronyms)]
    pub enum DomainRuntimeInfoV2 {
        EVM { chain_id: EVMChainId },
        AutoId,
    }

    #[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
    pub struct DomainObjectV2<Number, ReceiptHash, AccountId: Ord, Balance> {
        /// The address of the domain creator, used to validate updating the domain config.
        pub owner_account_id: AccountId,
        /// The consensus chain block number when the domain first instantiated.
        pub created_at: Number,
        /// The hash of the genesis execution receipt for this domain.
        pub genesis_receipt_hash: ReceiptHash,
        /// The domain config.
        pub domain_config: DomainConfig<AccountId, Balance>,
        /// Domain runtime specific information.
        pub domain_runtime_info: DomainRuntimeInfoV2,
        /// The amount of balance hold on the domain owner account
        pub domain_instantiation_deposit: Balance,
    }

    #[storage_alias]
    pub(super) type DomainRegistry<T: Config> = StorageMap<
        Pallet<T>,
        Identity,
        DomainId,
        DomainObjectV2<
            BlockNumberFor<T>,
            ReceiptHashFor<T>,
            <T as frame_system::Config>::AccountId,
            BalanceOf<T>,
        >,
        OptionQuery,
    >;

    pub(super) fn migrate_domain_registry_structure<T: Config>() -> Weight {
        let mut domain_count = 0;

        DomainRegistryV3::<T>::translate_values::<
            DomainObjectV2<BlockNumberFor<T>, ReceiptHashFor<T>, T::AccountId, BalanceOf<T>>,
            _,
        >(|domain_object_v2| {
            domain_count += 1;

            let domain_runtime_info_v3 = match domain_object_v2.domain_runtime_info {
                DomainRuntimeInfoV2::EVM { chain_id } => {
                    DomainRuntimeInfoV3::Evm {
                        chain_id,
                        // Added in V3
                        domain_runtime_config: EvmDomainRuntimeConfigV3::default(),
                    }
                }
                DomainRuntimeInfoV2::AutoId => {
                    DomainRuntimeInfoV3::AutoId {
                        // Added in V3
                        domain_runtime_config: AutoIdDomainRuntimeConfigV3::default(),
                    }
                }
            };

            Some(DomainObjectV3 {
                owner_account_id: domain_object_v2.owner_account_id,
                created_at: domain_object_v2.created_at,
                genesis_receipt_hash: domain_object_v2.genesis_receipt_hash,
                domain_config: domain_object_v2.domain_config,
                // Modified in V3
                domain_runtime_info: domain_runtime_info_v3,
                domain_instantiation_deposit: domain_object_v2.domain_instantiation_deposit,
            })
        });

        // 1 read and 1 write per domain
        T::DbWeight::get().reads_writes(domain_count, domain_count)
    }
}

#[cfg(test)]
mod tests {
    use super::domain_registry_structure_migration::{
        migrate_domain_registry_structure, AutoIdDomainRuntimeConfigV3, DomainConfig, DomainId,
        DomainObjectV2, DomainObjectV3, DomainRegistry, DomainRegistryV3, DomainRuntimeInfoV2,
        DomainRuntimeInfoV3, EvmDomainRuntimeConfigV3,
    };
    use crate::tests::{new_test_ext, Test};
    use sp_domains::{EvmType as EvmTypeV3, OperatorAllowList};

    #[test]
    fn test_domain_registry_structure_migration_evm() {
        let mut ext = new_test_ext();
        let domain_id: DomainId = 0.into();
        let chain_id = 8u32.into();
        let domain_config = DomainConfig {
            domain_name: "test-evm-migrate".to_string(),
            runtime_id: 3u32,
            max_bundle_size: 4,
            max_bundle_weight: 5.into(),
            bundle_slot_probability: (6, 7),
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: vec![],
        };
        let domain = DomainObjectV2 {
            owner_account_id: 1u32.into(),
            created_at: 2u32.into(),
            genesis_receipt_hash: Default::default(),
            domain_config: domain_config.clone(),
            domain_runtime_info: DomainRuntimeInfoV2::EVM { chain_id },
            domain_instantiation_deposit: 9u32.into(),
        };

        ext.execute_with(|| DomainRegistry::<Test>::set(domain_id, Some(domain.clone())));

        ext.commit_all().unwrap();

        ext.execute_with(|| {
            let weights = migrate_domain_registry_structure::<Test>();
            assert_eq!(
                weights,
                <Test as frame_system::Config>::DbWeight::get().reads_writes(1, 1),
            );
            assert_eq!(
                DomainRegistryV3::<Test>::get(domain_id),
                Some(DomainObjectV3 {
                    owner_account_id: domain.owner_account_id,
                    created_at: domain.created_at,
                    genesis_receipt_hash: domain.genesis_receipt_hash,
                    domain_config,
                    domain_runtime_info: DomainRuntimeInfoV3::Evm {
                        chain_id,
                        domain_runtime_config: EvmDomainRuntimeConfigV3 {
                            // All current EVM domains are public EVMs
                            evm_type: EvmTypeV3::Public
                        },
                    },
                    domain_instantiation_deposit: domain.domain_instantiation_deposit,
                })
            );
        });
    }

    #[test]
    fn test_domain_registry_structure_migration_auto_id() {
        let mut ext = new_test_ext();
        let domain_id: DomainId = 10.into();
        let domain_config = DomainConfig {
            domain_name: "test-auto-id-migrate".to_string(),
            runtime_id: 13u32,
            max_bundle_size: 14,
            max_bundle_weight: 15.into(),
            bundle_slot_probability: (16, 17),
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: vec![],
        };
        let domain = DomainObjectV2 {
            owner_account_id: 11u32.into(),
            created_at: 12u32.into(),
            genesis_receipt_hash: Default::default(),
            domain_config: domain_config.clone(),
            domain_runtime_info: DomainRuntimeInfoV2::AutoId,
            domain_instantiation_deposit: 19u32.into(),
        };

        ext.execute_with(|| DomainRegistry::<Test>::set(domain_id, Some(domain.clone())));

        ext.commit_all().unwrap();

        ext.execute_with(|| {
            let weights = migrate_domain_registry_structure::<Test>();
            assert_eq!(
                weights,
                <Test as frame_system::Config>::DbWeight::get().reads_writes(1, 1),
            );
            assert_eq!(
                DomainRegistryV3::<Test>::get(domain_id),
                Some(DomainObjectV3 {
                    owner_account_id: domain.owner_account_id,
                    created_at: domain.created_at,
                    genesis_receipt_hash: domain.genesis_receipt_hash,
                    domain_config,
                    domain_runtime_info: DomainRuntimeInfoV3::AutoId {
                        // There are no AutoId-specific config fields at this time
                        domain_runtime_config: AutoIdDomainRuntimeConfigV3 {}
                    },
                    domain_instantiation_deposit: domain.domain_instantiation_deposit,
                })
            );
        });
    }
}
