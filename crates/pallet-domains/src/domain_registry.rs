//! Domain registry for domains

use crate::{Config, DomainRegistry, NextDomainId, RuntimeRegistry};
use codec::{Decode, Encode};
use frame_support::traits::{Currency, LockIdentifier, LockableCurrency, WithdrawReasons};
use frame_support::weights::Weight;
use frame_support::{ensure, PalletError};
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::{DomainId, GenesisDomain, RuntimeId};
use sp_runtime::traits::CheckedAdd;
use sp_std::vec::Vec;

const DOMAIN_INSTANCE_ID: LockIdentifier = *b"domains ";

pub type EpochIndex = u32;

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
    /// The domain genesis config.
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
        T::Currency::free_balance(owner_account_id) >= T::DomainInstantiationDeposit::get(),
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
    T::Currency::set_lock(
        DOMAIN_INSTANCE_ID,
        &owner_account_id,
        T::DomainInstantiationDeposit::get(),
        WithdrawReasons::all(),
    );

    // TODO: initialize the stake summary for this domain

    // TODO: initialize the genesis block in the domain block tree once we can drive the
    // genesis ER from genesis config through host function

    Ok(domain_id)
}
