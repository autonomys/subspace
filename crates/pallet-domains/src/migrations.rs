//! Migration module for pallet-domains

use crate::Config;
use frame_support::traits::OnRuntimeUpgrade;
use frame_support::weights::Weight;

pub struct VersionUncheckedMigrateV1ToV2<T>(sp_std::marker::PhantomData<T>);
impl<T: Config> OnRuntimeUpgrade for VersionUncheckedMigrateV1ToV2<T> {
    fn on_runtime_upgrade() -> Weight {
        signing_key_index_migration::index_operator_signing_keys_v1_to_v2::<T>()
    }
}

pub struct VersionUncheckedMigrateV2ToV3<T>(sp_std::marker::PhantomData<T>);
impl<T: Config> OnRuntimeUpgrade for VersionUncheckedMigrateV2ToV3<T> {
    fn on_runtime_upgrade() -> Weight {
        signing_key_index_migration::index_operator_signing_keys_v2_to_v3::<T>()
    }
}

pub(super) mod signing_key_index_migration {
    use crate::pallet::{OperatorSigningKey as OperatorSigningKeyV3, Operators};
    use crate::Config;
    use frame_support::pallet_prelude::{OptionQuery, Weight};
    use frame_support::{storage_alias, Identity};
    use sp_core::Get;
    use sp_domains::{OperatorId, OperatorPublicKey};
    use sp_std::collections::btree_set::BTreeSet;

    #[storage_alias]
    pub(super) type OperatorSigningKey<T: Config> = StorageMap<
        crate::Pallet<T>,
        Identity,
        OperatorPublicKey,
        BTreeSet<OperatorId>,
        OptionQuery,
    >;

    /// Indexes the currently used operator's signing keys into v2 domains storage.
    pub(super) fn index_operator_signing_keys_v1_to_v2<T: Config>() -> Weight {
        let mut count = 0;
        Operators::<T>::iter().for_each(|(operator_id, operator)| {
            count += 1;
            OperatorSigningKey::<T>::append(operator.signing_key, operator_id)
        });

        T::DbWeight::get().reads_writes(count, count)
    }

    /// Indexes the currently used operator's signing keys into v3 storage item.
    pub(super) fn index_operator_signing_keys_v2_to_v3<T: Config>() -> Weight {
        let mut count = 0;
        let keys = OperatorSigningKey::<T>::drain();
        keys.for_each(|(signing_key, operators)| {
            count += 1;
            let maybe_operator_id = operators.first().cloned();
            if let Some(operator_id) = maybe_operator_id {
                OperatorSigningKeyV3::<T>::insert(signing_key, operator_id)
            }
        });

        T::DbWeight::get().reads_writes(count, count)
    }
}

#[cfg(test)]
mod tests {
    use crate::migrations::signing_key_index_migration::OperatorSigningKey as OperatorSigningKeyV2;
    use crate::pallet::{OperatorSigningKey as OperatorSigningKeyV3, Operators};
    use crate::staking::{Operator, OperatorStatus};
    use crate::tests::{new_test_ext, Test};
    use sp_core::{Pair, U256};
    use sp_domains::OperatorPair;
    use std::collections::BTreeSet;
    use subspace_runtime_primitives::{Balance, SSC};

    #[test]
    fn test_index_operator_signing_keys() {
        let mut ext = new_test_ext();
        let create_operator = |signing_key| -> Operator<Balance, Balance> {
            Operator {
                signing_key,
                current_domain_id: Default::default(),
                next_domain_id: Default::default(),
                minimum_nominator_stake: 100 * SSC,
                nomination_tax: Default::default(),
                current_total_stake: 100 * SSC,
                current_epoch_rewards: Default::default(),
                total_shares: Default::default(),
                status: OperatorStatus::Registered,
            }
        };

        let pair_1 = OperatorPair::from_seed(&U256::from(0u32).into());
        let pair_2 = OperatorPair::from_seed(&U256::from(1u32).into());

        ext.execute_with(|| {
            // operator uses pair_1
            Operators::<Test>::insert(1, create_operator(pair_1.public()));

            // operator uses pair_2
            Operators::<Test>::insert(2, create_operator(pair_2.public()));

            // operator uses pair_2
            Operators::<Test>::insert(3, create_operator(pair_2.public()));

            assert!(!OperatorSigningKeyV2::<Test>::contains_key(pair_1.public()));
            assert!(!OperatorSigningKeyV2::<Test>::contains_key(pair_2.public()));
        });

        ext.commit_all().unwrap();

        ext.execute_with(|| {
            let weights =
                crate::migrations::signing_key_index_migration::index_operator_signing_keys_v1_to_v2::<Test>(
                );
            assert_eq!(
                weights,
                <Test as frame_system::Config>::DbWeight::get().reads_writes(3, 3),
            );

            assert_eq!(
                OperatorSigningKeyV2::<Test>::get(pair_1.public()),
                Some(BTreeSet::from([1]))
            );
            assert_eq!(
                OperatorSigningKeyV2::<Test>::get(pair_2.public()),
                Some(BTreeSet::from([2, 3]))
            );
        });

        ext.commit_all().unwrap();

        ext.execute_with(|| {
            let weights =
                crate::migrations::signing_key_index_migration::index_operator_signing_keys_v2_to_v3::<Test>(
                );
            assert_eq!(
                weights,
                // only 2 migrations since we have only 2 signing keys
                <Test as frame_system::Config>::DbWeight::get().reads_writes(2, 2),
            );

            assert_eq!(
                OperatorSigningKeyV3::<Test>::get(pair_1.public()),
                Some(1)
            );
            assert_eq!(
                OperatorSigningKeyV3::<Test>::get(pair_2.public()),
                Some(2)
            );
        })
    }
}
