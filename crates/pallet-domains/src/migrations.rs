//! Migration module for pallet-domains

// TODO: remove the entire module once the runtime is upgraded
pub mod migrate_domain_object {
    use crate::domain_registry::DomainConfig;
    use crate::runtime_registry::DomainRuntimeInfo;
    use crate::{Config, ReceiptHashFor};
    use codec::{Decode, Encode};
    use frame_support::pallet_prelude::{OptionQuery, StorageVersion, TypeInfo, Weight};
    use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade};
    use frame_support::{storage_alias, Identity};
    use frame_system::pallet_prelude::BlockNumberFor;
    use sp_core::Get;
    use sp_domains::DomainId;
    use sp_std::vec::Vec;

    /// Previous domain object that needs to be migrated.
    #[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
    pub struct DomainObject<Number, ReceiptHash, AccountId: Ord> {
        /// The address of the domain creator, used to validate updating the domain config.
        pub owner_account_id: AccountId,
        /// The consensus chain block number when the domain first instantiated.
        pub created_at: Number,
        /// The hash of the genesis execution receipt for this domain.
        pub genesis_receipt_hash: ReceiptHash,
        /// The domain config.
        pub domain_config: DomainConfig<AccountId>,
    }

    impl<Number, ReceiptHash, AccountId: Ord> From<DomainObject<Number, ReceiptHash, AccountId>>
        for crate::domain_registry::DomainObject<Number, ReceiptHash, AccountId>
    {
        fn from(old_domain_obj: DomainObject<Number, ReceiptHash, AccountId>) -> Self {
            crate::domain_registry::DomainObject {
                owner_account_id: old_domain_obj.owner_account_id,
                created_at: old_domain_obj.created_at,
                genesis_receipt_hash: old_domain_obj.genesis_receipt_hash,
                domain_config: old_domain_obj.domain_config,
                // 1002 is the evm chain id for gemini networks
                domain_runtime_info: DomainRuntimeInfo::EVM { chain_id: 1002 },
            }
        }
    }

    #[storage_alias]
    pub type DomainRegistry<T: Config> = StorageMap<
        crate::Pallet<T>,
        Identity,
        DomainId,
        DomainObject<BlockNumberFor<T>, ReceiptHashFor<T>, <T as frame_system::Config>::AccountId>,
        OptionQuery,
    >;

    /// Whenever there is a migration to specific storage and that storage item is used as part of the runtimeAPI,
    /// decoding such storage item fails
    /// Here is an example:
    /// If runtime upgrade happened on Block #100, migration is not done yet
    /// But since the :code already holds the new runtime, runtime api will use the new Runtime when
    /// queried at Block #100. This essentially causes a Decode to fail and cause State Corrupt error.
    ///
    /// Once the migration is done at block #101, this runtime api works as expected.
    /// To adjust to the case for Block #100 specifically, we try to decode with latest type
    /// and then fall back to old type.
    pub fn get_domain_object<T: Config>(
        domain_id: DomainId,
    ) -> Option<
        crate::domain_registry::DomainObject<
            BlockNumberFor<T>,
            ReceiptHashFor<T>,
            <T as frame_system::Config>::AccountId,
        >,
    > {
        crate::DomainRegistry::<T>::get(domain_id).or_else(|| {
            let old_domain_obj = DomainRegistry::<T>::get(domain_id)?;
            Some(old_domain_obj.into())
        })
    }

    pub struct MigrateDomainObject<T>(sp_std::marker::PhantomData<T>);
    impl<T: Config> OnRuntimeUpgrade for MigrateDomainObject<T> {
        fn on_runtime_upgrade() -> Weight {
            if crate::Pallet::<T>::on_chain_storage_version() > 0 {
                log::info!(target: "pallet-domains", "MigrateDomainObject should be removed");
                return T::DbWeight::get().reads(1);
            }

            let updated_domain_objects = DomainRegistry::<T>::drain()
                .map(|(domain_id, old_domain_obj)| {
                    let new_domain_object = old_domain_obj.into();
                    (domain_id, new_domain_object)
                })
                .collect::<Vec<(DomainId, crate::domain_registry::DomainObject<_, _, _>)>>();

            let count = updated_domain_objects.len() as u64;
            log::info!(target: "pallet-domains", "Migrating {count:?} Domain objects");

            for (domain_id, domain_obj) in updated_domain_objects {
                crate::DomainRegistry::<T>::insert(domain_id, domain_obj)
            }

            StorageVersion::new(1).put::<crate::Pallet<T>>();

            // +1 for storage version read and write
            T::DbWeight::get().reads_writes(count + 1, count + 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::domain_registry::DomainConfig;
    use crate::runtime_registry::DomainRuntimeInfo;
    use crate::tests::{new_test_ext, Test};
    use frame_support::traits::OnRuntimeUpgrade;
    use sp_core::H256;
    use sp_domains::{DomainId, OperatorAllowList};

    #[test]
    fn migration_domain_objects() {
        let mut ext = new_test_ext();

        ext.execute_with(|| {
            let old_obj = crate::migrations::migrate_domain_object::DomainObject {
                owner_account_id: 1,
                created_at: 10,
                genesis_receipt_hash: H256::random(),
                domain_config: DomainConfig {
                    domain_name: "evm".to_string(),
                    runtime_id: 0,
                    max_block_size: 0,
                    max_block_weight: Default::default(),
                    bundle_slot_probability: (0, 0),
                    target_bundles_per_block: 0,
                    operator_allow_list: OperatorAllowList::Anyone,
                },
            };

            let domain_id = DomainId::new(1);
            crate::migrations::migrate_domain_object::DomainRegistry::<Test>::insert(
                domain_id, old_obj,
            );
        });

        ext.commit_all().unwrap();

        ext.execute_with(|| {
            assert_eq!(
                crate::migrations::migrate_domain_object::MigrateDomainObject::<Test>::on_runtime_upgrade(),
                <Test as frame_system::Config>::DbWeight::get().reads_writes(2, 2),
            );

            let domain_runtime_info = crate::DomainRegistry::<Test>::get(DomainId::new(1))
                .unwrap()
                .domain_runtime_info;
            assert_eq!(
                domain_runtime_info,
                DomainRuntimeInfo::EVM { chain_id: 1002 }
            )
        })
    }
}
