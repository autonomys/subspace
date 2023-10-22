//! Domain registry for domains

use crate::block_tree::import_genesis_receipt;
use crate::pallet::DomainStakingSummary;
use crate::staking::StakingSummary;
use crate::{
    Config, DomainHashingFor, DomainRegistry, ExecutionReceiptOf, HoldIdentifier, NextDomainId,
    RuntimeRegistry,
};
use alloc::string::String;
use codec::{Decode, Encode};
use frame_support::traits::fungible::{Inspect, MutateHold};
use frame_support::traits::tokens::{Fortitude, Preservation};
use frame_support::weights::Weight;
use frame_support::{ensure, PalletError};
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::{
    derive_domain_block_hash, DomainId, DomainsDigestItem, OperatorAllowList, ReceiptHash,
    RuntimeId,
};
use sp_runtime::traits::{CheckedAdd, Zero};
use sp_runtime::DigestItem;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::btree_set::BTreeSet;

/// Domain registry specific errors
#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum Error {
    InvalidBundlesPerBlock,
    ExceedMaxDomainBlockWeight,
    ExceedMaxDomainBlockSize,
    MaxDomainId,
    InvalidSlotProbability,
    RuntimeNotFound,
    InsufficientFund,
    DomainNameTooLong,
    BalanceFreeze,
    FailedToGenerateGenesisStateRoot,
    DomainNotFound,
    NotDomainOwner,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct DomainConfig<AccountId: Ord> {
    /// A user defined name for this domain, should be a human-readable UTF-8 encoded string.
    pub domain_name: String,
    /// A pointer to the `RuntimeRegistry` entry for this domain.
    pub runtime_id: RuntimeId,
    /// The max block size for this domain, may not exceed the system-wide `MaxDomainBlockSize` limit.
    pub max_block_size: u32,
    /// The max block weight for this domain, may not exceed the system-wide `MaxDomainBlockWeight` limit.
    pub max_block_weight: Weight,
    /// The probability of successful bundle in a slot (active slots coefficient). This defines the
    /// expected bundle production rate, must be `> 0` and `≤ 1`.
    pub bundle_slot_probability: (u64, u64),
    /// The expected number of bundles for a domain block, must be `≥ 1` and `≤ MaxBundlesPerBlock`.
    pub target_bundles_per_block: u32,
    /// Allowed operators to operate for this domain.
    pub operator_allow_list: OperatorAllowList<AccountId>,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct DomainObject<Number, AccountId: Ord> {
    /// The address of the domain creator, used to validate updating the domain config.
    pub owner_account_id: AccountId,
    /// The consensus chain block number when the domain first instantiated.
    pub created_at: Number,
    /// The hash of the genesis execution receipt for this domain.
    pub genesis_receipt_hash: ReceiptHash,
    /// The domain config.
    pub domain_config: DomainConfig<AccountId>,
}

pub(crate) fn can_instantiate_domain<T: Config>(
    owner_account_id: &T::AccountId,
    domain_config: &DomainConfig<T::AccountId>,
) -> Result<(), Error> {
    ensure!(
        domain_config.domain_name.len() as u32 <= T::MaxDomainNameLength::get(),
        Error::DomainNameTooLong,
    );
    ensure!(
        RuntimeRegistry::<T>::contains_key(domain_config.runtime_id),
        Error::RuntimeNotFound
    );
    ensure!(
        domain_config.max_block_size <= T::MaxDomainBlockSize::get(),
        Error::ExceedMaxDomainBlockSize
    );
    ensure!(
        domain_config.max_block_weight.ref_time() <= T::MaxDomainBlockWeight::get().ref_time(),
        Error::ExceedMaxDomainBlockWeight
    );
    ensure!(
        domain_config.target_bundles_per_block != 0
            && domain_config.target_bundles_per_block <= T::MaxBundlesPerBlock::get(),
        Error::InvalidBundlesPerBlock
    );

    // `bundle_slot_probability` must be `> 0` and `≤ 1`
    let (numerator, denominator) = domain_config.bundle_slot_probability;
    ensure!(
        numerator != 0 && denominator != 0 && numerator <= denominator,
        Error::InvalidSlotProbability
    );

    ensure!(
        T::Currency::reducible_balance(owner_account_id, Preservation::Protect, Fortitude::Polite)
            >= T::DomainInstantiationDeposit::get(),
        Error::InsufficientFund
    );

    Ok(())
}

pub(crate) fn do_instantiate_domain<T: Config>(
    domain_config: DomainConfig<T::AccountId>,
    owner_account_id: T::AccountId,
    created_at: BlockNumberFor<T>,
) -> Result<DomainId, Error> {
    can_instantiate_domain::<T>(&owner_account_id, &domain_config)?;

    let domain_id = NextDomainId::<T>::get();

    let genesis_receipt = {
        let runtime_obj = RuntimeRegistry::<T>::get(domain_config.runtime_id)
            .expect("Runtime object must exist as checked in `can_instantiate_domain`; qed");

        let state_version = runtime_obj.version.state_version();
        let raw_genesis = runtime_obj.into_complete_raw_genesis(domain_id);
        let state_root = raw_genesis.state_root::<DomainHashingFor<T>>(state_version);
        let genesis_block_hash = derive_domain_block_hash::<T::DomainHeader>(
            Zero::zero(),
            sp_domains::EMPTY_EXTRINSIC_ROOT.into(),
            state_root,
            Default::default(),
            Default::default(),
        );

        ExecutionReceiptOf::<T>::genesis(
            state_root,
            sp_domains::EMPTY_EXTRINSIC_ROOT,
            genesis_block_hash,
        )
    };
    let genesis_receipt_hash = genesis_receipt.hash();

    let domain_obj = DomainObject {
        owner_account_id: owner_account_id.clone(),
        created_at,
        genesis_receipt_hash,
        domain_config,
    };
    DomainRegistry::<T>::insert(domain_id, domain_obj);

    let next_domain_id = domain_id.checked_add(&1.into()).ok_or(Error::MaxDomainId)?;
    NextDomainId::<T>::set(next_domain_id);

    // Lock up fund of the domain instance creator
    T::Currency::hold(
        &T::HoldIdentifier::domain_instantiation_id(domain_id),
        &owner_account_id,
        T::DomainInstantiationDeposit::get(),
    )
    .map_err(|_| Error::BalanceFreeze)?;

    DomainStakingSummary::<T>::insert(
        domain_id,
        StakingSummary {
            current_epoch_index: 0,
            current_total_stake: Zero::zero(),
            current_operators: BTreeMap::new(),
            next_operators: BTreeSet::new(),
            current_epoch_rewards: BTreeMap::new(),
        },
    );

    import_genesis_receipt::<T>(domain_id, genesis_receipt);

    frame_system::Pallet::<T>::deposit_log(DigestItem::domain_instantiation(domain_id));

    Ok(domain_id)
}

pub(crate) fn do_update_domain_allow_list<T: Config>(
    domain_owner: T::AccountId,
    domain_id: DomainId,
    updated_operator_allow_list: OperatorAllowList<T::AccountId>,
) -> Result<(), Error> {
    DomainRegistry::<T>::try_mutate(domain_id, |maybe_domain_object| {
        let domain_obj = maybe_domain_object.as_mut().ok_or(Error::DomainNotFound)?;
        ensure!(
            domain_obj.owner_account_id == domain_owner,
            Error::NotDomainOwner
        );

        domain_obj.domain_config.operator_allow_list = updated_operator_allow_list;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pallet::{DomainRegistry, NextDomainId, RuntimeRegistry};
    use crate::runtime_registry::RuntimeObject;
    use crate::tests::{new_test_ext, Test};
    use frame_support::assert_ok;
    use frame_support::traits::Currency;
    use sp_domains::storage::RawGenesis;
    use sp_std::collections::btree_set::BTreeSet;
    use sp_std::vec;
    use sp_version::RuntimeVersion;

    type Balances = pallet_balances::Pallet<Test>;

    #[test]
    fn test_domain_instantiation() {
        let creator = 1u64;
        let created_at = 0u64;
        // Construct an invalid domain config initially
        let mut domain_config = DomainConfig {
            domain_name: String::from_utf8(vec![0; 1024]).unwrap(),
            runtime_id: 0,
            max_block_size: u32::MAX,
            max_block_weight: Weight::MAX,
            bundle_slot_probability: (0, 0),
            target_bundles_per_block: 0,
            operator_allow_list: OperatorAllowList::Anyone,
        };

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            assert_eq!(NextDomainId::<Test>::get(), 0.into());

            // Failed to instantiate domain due to `domain_name` too long
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Err(Error::DomainNameTooLong)
            );
            // Recorrect `domain_name`
            domain_config.domain_name = "evm-domain".to_owned();

            // Failed to instantiate domain due to using unregistered runtime id
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Err(Error::RuntimeNotFound)
            );
            // Register runtime id
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

            // Failed to instantiate domain due to exceed max domain block size limit
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Err(Error::ExceedMaxDomainBlockSize)
            );
            // Recorrect `max_block_size`
            domain_config.max_block_size = 1;

            // Failed to instantiate domain due to exceed max domain block weight limit
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Err(Error::ExceedMaxDomainBlockWeight)
            );
            // Recorrect `max_block_weight`
            domain_config.max_block_weight = Weight::from_parts(1, 0);

            // Failed to instantiate domain due to invalid `target_bundles_per_block`
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Err(Error::InvalidBundlesPerBlock)
            );
            domain_config.target_bundles_per_block = u32::MAX;
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Err(Error::InvalidBundlesPerBlock)
            );
            // Recorrect `target_bundles_per_block`
            domain_config.target_bundles_per_block = 1;

            // Failed to instantiate domain due to invalid `bundle_slot_probability`
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Err(Error::InvalidSlotProbability)
            );
            domain_config.bundle_slot_probability = (1, 0);
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Err(Error::InvalidSlotProbability)
            );
            domain_config.bundle_slot_probability = (0, 1);
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Err(Error::InvalidSlotProbability)
            );
            domain_config.bundle_slot_probability = (2, 1);
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Err(Error::InvalidSlotProbability)
            );
            // Recorrect `bundle_slot_probability`
            domain_config.bundle_slot_probability = (1, 1);

            // Failed to instantiate domain due to creator don't have enough fund
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Err(Error::InsufficientFund)
            );
            // Set enough fund to creator
            Balances::make_free_balance_be(
                &creator,
                <Test as Config>::DomainInstantiationDeposit::get()
                    + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
            );

            // `instantiate_domain` must success now
            let domain_id =
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at).unwrap();
            let domain_obj = DomainRegistry::<Test>::get(domain_id).unwrap();

            assert_eq!(domain_obj.owner_account_id, creator);
            assert_eq!(domain_obj.created_at, created_at);
            assert_eq!(domain_obj.domain_config, domain_config);
            assert_eq!(NextDomainId::<Test>::get(), 1.into());
            // Fund locked up thus can't withdraw, and usable balance is zero since ED is 1
            assert_eq!(Balances::usable_balance(creator), Zero::zero());

            // cannot use the locked funds to create a new domain instance
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config, creator, created_at),
                Err(Error::InsufficientFund)
            );

            // update operator allow list
            let updated_operator_allow_list =
                OperatorAllowList::Operators(BTreeSet::from_iter(vec![1, 2, 3]));
            assert_ok!(do_update_domain_allow_list::<Test>(
                creator,
                domain_id,
                updated_operator_allow_list.clone()
            ));
            let domain_obj = DomainRegistry::<Test>::get(domain_id).unwrap();
            assert_eq!(
                domain_obj.domain_config.operator_allow_list,
                updated_operator_allow_list
            );
        });
    }
}
