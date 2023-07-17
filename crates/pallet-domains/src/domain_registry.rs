//! Domain registry for domains

use crate::pallet::DomainStakingSummary;
use crate::staking::StakingSummary;
use crate::{Config, DomainRegistry, FreezeIdentifier, NextDomainId, RuntimeRegistry};
use codec::{Decode, Encode};
use frame_support::traits::fungible::{Inspect, MutateFreeze};
use frame_support::traits::tokens::{Fortitude, Preservation};
use frame_support::weights::Weight;
use frame_support::{ensure, PalletError};
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::{DomainId, DomainsDigestItem, GenesisDomain, RuntimeId};
use sp_runtime::traits::{CheckedAdd, Zero};
use sp_runtime::DigestItem;
use sp_std::vec;
use sp_std::vec::Vec;

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
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct DomainConfig {
    /// A user defined name for this domain, should be a human-readable UTF-8 encoded string.
    pub domain_name: Vec<u8>,
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
}

impl DomainConfig {
    pub(crate) fn from_genesis<T: Config>(
        genesis_domain: &GenesisDomain<T::AccountId>,
        runtime_id: RuntimeId,
    ) -> Self {
        DomainConfig {
            domain_name: genesis_domain.domain_name.clone(),
            runtime_id,
            max_block_size: genesis_domain.max_block_size,
            max_block_weight: genesis_domain.max_block_weight,
            bundle_slot_probability: genesis_domain.bundle_slot_probability,
            target_bundles_per_block: genesis_domain.target_bundles_per_block,
        }
    }
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct DomainObject<Number, Hash, AccountId> {
    /// The address of the domain creator, used to validate updating the domain config.
    pub owner_account_id: AccountId,
    /// The consensus chain block number when the domain first instantiated.
    pub created_at: Number,
    /// The hash of the genesis execution receipt for this domain.
    pub genesis_receipt_hash: Hash,
    /// The domain config.
    pub domain_config: DomainConfig,
}

pub(crate) fn can_instantiate_domain<T: Config>(
    owner_account_id: &T::AccountId,
    domain_config: &DomainConfig,
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
    domain_config: DomainConfig,
    owner_account_id: T::AccountId,
    created_at: T::BlockNumber,
) -> Result<DomainId, Error> {
    can_instantiate_domain::<T>(&owner_account_id, &domain_config)?;

    let domain_obj = DomainObject {
        owner_account_id: owner_account_id.clone(),
        created_at,
        // TODO: drive the `genesis_receipt_hash` from genesis config through host function
        genesis_receipt_hash: T::Hash::default(),
        domain_config,
    };
    let domain_id = NextDomainId::<T>::get();
    DomainRegistry::<T>::insert(domain_id, domain_obj);

    let next_domain_id = domain_id.checked_add(&1.into()).ok_or(Error::MaxDomainId)?;
    NextDomainId::<T>::set(next_domain_id);

    // Lock up fund of the domain instance creator
    T::Currency::set_freeze(
        &T::FreezeIdentifier::domain_instantiation_id(domain_id),
        &owner_account_id,
        T::DomainInstantiationDeposit::get(),
    )
    .map_err(|_| Error::BalanceFreeze)?;

    DomainStakingSummary::<T>::insert(
        domain_id,
        StakingSummary {
            current_epoch_index: 0,
            current_total_stake: Zero::zero(),
            current_operators: vec![],
            next_operators: vec![],
        },
    );

    frame_system::Pallet::<T>::deposit_log(DigestItem::domain_instantiation(domain_id));

    // TODO: initialize the genesis block in the domain block tree once we can drive the
    // genesis ER from genesis config through host function

    Ok(domain_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pallet::{DomainRegistry, NextDomainId, RuntimeRegistry};
    use crate::runtime_registry::RuntimeObject;
    use crate::tests::{new_test_ext, Test};
    use frame_support::traits::Currency;
    use sp_runtime::traits::One;
    use sp_version::RuntimeVersion;

    type Balances = pallet_balances::Pallet<Test>;

    #[test]
    fn test_domain_instantiation() {
        let creator = 1u64;
        let created_at = 0u64;
        // Construct an invalid domain config initially
        let mut domain_config = DomainConfig {
            domain_name: vec![0; 1024],
            runtime_id: 0,
            max_block_size: u32::MAX,
            max_block_weight: Weight::MAX,
            bundle_slot_probability: (0, 0),
            target_bundles_per_block: 0,
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
            domain_config.domain_name = b"evm-domain".to_vec();

            // Failed to instantiate domain due to using unregistered runtime id
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Err(Error::RuntimeNotFound)
            );
            // Register runtime id
            RuntimeRegistry::<Test>::insert(
                domain_config.runtime_id,
                RuntimeObject {
                    runtime_name: b"evm".to_vec(),
                    runtime_type: Default::default(),
                    runtime_upgrades: 0,
                    hash: Default::default(),
                    code: vec![1, 2, 3, 4],
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
            // Fund locked up thus can't withdraw
            assert!(Balances::usable_balance(creator) == One::one(),);

            // cannot use the locked funds to create a new domain instance
            assert!(
                do_instantiate_domain::<Test>(domain_config, creator, created_at)
                    == Err(Error::InsufficientFund)
            )
        });
    }
}
