//! Domain registry for domains

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::block_tree::import_genesis_receipt;
use crate::pallet::{DomainStakingSummary, NextEVMChainId};
use crate::runtime_registry::DomainRuntimeInfo;
use crate::staking::StakingSummary;
use crate::{
    into_complete_raw_genesis, BalanceOf, Config, DomainHashingFor, DomainRegistry,
    ExecutionReceiptOf, HoldIdentifier, NextDomainId, RuntimeRegistry,
};
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use codec::{Decode, Encode};
use domain_runtime_primitives::MultiAccountId;
use frame_support::traits::fungible::{Inspect, Mutate, MutateHold};
use frame_support::traits::tokens::{Fortitude, Precision, Preservation};
use frame_support::weights::Weight;
use frame_support::{ensure, PalletError};
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::{
    derive_domain_block_hash, DomainBundleLimit, DomainId, DomainsDigestItem,
    DomainsTransfersTracker, OnDomainInstantiated, OperatorAllowList, RuntimeId, RuntimeType,
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
    MaxEVMChainId,
    InvalidSlotProbability,
    RuntimeNotFound,
    InsufficientFund,
    DomainNameTooLong,
    BalanceFreeze,
    FailedToGenerateGenesisStateRoot,
    DomainNotFound,
    NotDomainOwner,
    InitialBalanceOverflow,
    TransfersTracker,
    MinInitialAccountBalance,
    MaxInitialDomainAccounts,
    DuplicateInitialAccounts,
    FailedToGenerateRawGenesis(crate::runtime_registry::Error),
    BundleLimitCalculationOverflow,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct DomainConfig<AccountId: Ord, Balance> {
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
    // Initial balances for Domain.
    pub initial_balances: Vec<(MultiAccountId, Balance)>,
}

impl<AccountId, Balance> DomainConfig<AccountId, Balance>
where
    AccountId: Ord,
    Balance: Zero + CheckedAdd + PartialOrd,
{
    pub(crate) fn total_issuance(&self) -> Option<Balance> {
        self.initial_balances
            .iter()
            .try_fold(Balance::zero(), |total, (_, balance)| {
                total.checked_add(balance)
            })
    }

    pub(crate) fn check_initial_balances<T: Config>(&self) -> Result<(), Error>
    where
        Balance: From<BalanceOf<T>>,
    {
        let accounts: BTreeSet<MultiAccountId> = self
            .initial_balances
            .iter()
            .map(|(acc, _)| acc)
            .cloned()
            .collect();

        ensure!(
            accounts.len() == self.initial_balances.len(),
            Error::DuplicateInitialAccounts
        );

        ensure!(
            self.initial_balances.len() as u32 <= T::MaxInitialDomainAccounts::get(),
            Error::MaxInitialDomainAccounts
        );

        for (_, balance) in &self.initial_balances {
            ensure!(
                *balance >= T::MinInitialDomainAccountBalance::get().into(),
                Error::MinInitialAccountBalance
            );
        }

        Ok(())
    }

    pub(crate) fn calculate_bundle_limit<T: Config>(&self) -> Result<DomainBundleLimit, Error> {
        calculate_max_bundle_weight_and_size(
            self.max_block_size,
            self.max_block_weight,
            T::ConsensusSlotProbability::get(),
            self.bundle_slot_probability,
        )
        .ok_or(Error::BundleLimitCalculationOverflow)
    }
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct DomainObject<Number, ReceiptHash, AccountId: Ord, Balance> {
    /// The address of the domain creator, used to validate updating the domain config.
    pub owner_account_id: AccountId,
    /// The consensus chain block number when the domain first instantiated.
    pub created_at: Number,
    /// The hash of the genesis execution receipt for this domain.
    pub genesis_receipt_hash: ReceiptHash,
    /// The domain config.
    pub domain_config: DomainConfig<AccountId, Balance>,
    /// Domain runtime specific information.
    pub domain_runtime_info: DomainRuntimeInfo,
}

pub(crate) fn can_instantiate_domain<T: Config>(
    owner_account_id: &T::AccountId,
    domain_config: &DomainConfig<T::AccountId, BalanceOf<T>>,
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

    // Ensure the bundle limit can be calculated successfully
    let _ = domain_config.calculate_bundle_limit::<T>()?;

    ensure!(
        T::Currency::reducible_balance(owner_account_id, Preservation::Protect, Fortitude::Polite)
            >= T::DomainInstantiationDeposit::get(),
        Error::InsufficientFund
    );

    domain_config.check_initial_balances::<T>()?;

    Ok(())
}

pub(crate) fn do_instantiate_domain<T: Config>(
    domain_config: DomainConfig<T::AccountId, BalanceOf<T>>,
    owner_account_id: T::AccountId,
    created_at: BlockNumberFor<T>,
) -> Result<DomainId, Error> {
    can_instantiate_domain::<T>(&owner_account_id, &domain_config)?;

    let domain_id = NextDomainId::<T>::get();
    let runtime_obj = RuntimeRegistry::<T>::get(domain_config.runtime_id)
        .expect("Runtime object must exist as checked in `can_instantiate_domain`; qed");

    let domain_runtime_info = match runtime_obj.runtime_type {
        RuntimeType::Evm => {
            let evm_chain_id = NextEVMChainId::<T>::get();
            let next_evm_chain_id = evm_chain_id.checked_add(1).ok_or(Error::MaxEVMChainId)?;
            NextEVMChainId::<T>::set(next_evm_chain_id);
            DomainRuntimeInfo::EVM {
                chain_id: evm_chain_id,
            }
        }
        RuntimeType::AutoId => DomainRuntimeInfo::AutoId,
    };

    // burn total issuance on domain from owners account and track the domain balance
    let total_issuance = domain_config
        .total_issuance()
        .ok_or(Error::InitialBalanceOverflow)?;

    T::Currency::burn_from(
        &owner_account_id,
        total_issuance,
        Precision::Exact,
        Fortitude::Polite,
    )
    .map_err(|_| Error::InsufficientFund)?;

    T::DomainsTransfersTracker::initialize_domain_balance(domain_id, total_issuance)
        .map_err(|_| Error::TransfersTracker)?;

    let genesis_receipt = {
        let state_version = runtime_obj.version.state_version();
        let raw_genesis = into_complete_raw_genesis::<T>(
            runtime_obj,
            domain_id,
            domain_runtime_info,
            total_issuance,
            domain_config.initial_balances.clone(),
        )
        .map_err(Error::FailedToGenerateRawGenesis)?;
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
            sp_domains::EMPTY_EXTRINSIC_ROOT.into(),
            genesis_block_hash,
        )
    };
    let genesis_receipt_hash = genesis_receipt.hash::<DomainHashingFor<T>>();

    let domain_obj = DomainObject {
        owner_account_id: owner_account_id.clone(),
        created_at,
        genesis_receipt_hash,
        domain_config,
        domain_runtime_info,
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
    T::OnDomainInstantiated::on_domain_instantiated(domain_id);

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

// See https://forum.subspace.network/t/on-bundle-weight-limits-sum/2277 for more details
// about the formula
pub(crate) fn calculate_max_bundle_weight_and_size(
    max_domain_block_size: u32,
    max_domain_block_weight: Weight,
    consensus_slot_probability: (u64, u64),
    bundle_slot_probability: (u64, u64),
) -> Option<DomainBundleLimit> {
    // (n1 / d1) / (n2 / d2) is equal to (n1 * d2) / (d1 * n2)
    // This represents: bundle_slot_probability/SLOT_PROBABILITY
    let expected_bundles_per_block = bundle_slot_probability
        .0
        .checked_mul(consensus_slot_probability.1)?
        .checked_div(
            bundle_slot_probability
                .1
                .checked_mul(consensus_slot_probability.0)?,
        )?;

    let max_bundle_weight = max_domain_block_weight.checked_div(expected_bundles_per_block)?;
    let max_bundle_size = (max_domain_block_size as u64).checked_div(expected_bundles_per_block)?;

    Some(DomainBundleLimit {
        max_bundle_size: max_bundle_size as u32,
        max_bundle_weight,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{new_test_ext, Test};
    use domain_runtime_primitives::{AccountId20, AccountId20Converter};
    use frame_support::traits::Currency;
    use frame_support::{assert_err, assert_ok};
    use hex_literal::hex;
    use sp_domains::storage::RawGenesis;
    use sp_domains::RuntimeObject;
    use sp_runtime::traits::Convert;
    use sp_std::vec;
    use sp_version::RuntimeVersion;
    use subspace_runtime_primitives::SSC;

    type Balances = pallet_balances::Pallet<Test>;

    #[test]
    fn test_domain_instantiation() {
        let creator = 1u128;
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
            initial_balances: Default::default(),
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
            "evm-domain".clone_into(&mut domain_config.domain_name);

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

    #[test]
    fn test_domain_instantiation_evm_accounts() {
        let creator = 1u128;
        let created_at = 0u64;
        // Construct an invalid domain config initially
        let mut domain_config = DomainConfig {
            domain_name: "evm-domain".to_owned(),
            runtime_id: 0,
            max_block_size: 10,
            max_block_weight: Weight::from_parts(1, 0),
            bundle_slot_probability: (1, 1),
            target_bundles_per_block: 1,
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: vec![(MultiAccountId::Raw(vec![0, 1, 2, 3, 4, 5]), 1_000_000 * SSC)],
        };

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            assert_eq!(NextDomainId::<Test>::get(), 0.into());
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

            // Set enough fund to creator
            Balances::make_free_balance_be(
                &creator,
                <Test as Config>::DomainInstantiationDeposit::get()
                    // for domain total issuance
                    + 1_000_000 * SSC
                    + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
            );

            // should fail due to invalid account ID type
            assert_err!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Error::FailedToGenerateRawGenesis(
                    crate::runtime_registry::Error::InvalidAccountIdType
                )
            );

            // duplicate accounts
            domain_config.initial_balances = vec![
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
                    ))),
                    1_000_000 * SSC,
                ),
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
                    ))),
                    1_000_000 * SSC,
                ),
            ];

            assert_err!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Error::DuplicateInitialAccounts
            );

            // max accounts
            domain_config.initial_balances = vec![
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
                    ))),
                    1_000_000 * SSC,
                ),
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cbc"
                    ))),
                    1_000_000 * SSC,
                ),
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566ccc"
                    ))),
                    1_000_000 * SSC,
                ),
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cdc"
                    ))),
                    1_000_000 * SSC,
                ),
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cec"
                    ))),
                    1_000_000 * SSC,
                ),
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cfc"
                    ))),
                    1_000_000 * SSC,
                ),
            ];

            assert_err!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Error::MaxInitialDomainAccounts
            );

            // min balance accounts
            domain_config.initial_balances = vec![(
                AccountId20Converter::convert(AccountId20::from(hex!(
                    "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
                ))),
                1,
            )];

            assert_err!(
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at),
                Error::MinInitialAccountBalance
            );

            domain_config.initial_balances = vec![(
                AccountId20Converter::convert(AccountId20::from(hex!(
                    "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
                ))),
                1_000_000 * SSC,
            )];

            // Set enough fund to creator
            Balances::make_free_balance_be(
                &creator,
                <Test as Config>::DomainInstantiationDeposit::get()
                    // for domain total issuance
                    + 1_000_000 * SSC
                    + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
            );

            // should be successful
            let domain_id =
                do_instantiate_domain::<Test>(domain_config.clone(), creator, created_at).unwrap();
            let domain_obj = DomainRegistry::<Test>::get(domain_id).unwrap();

            assert_eq!(domain_obj.owner_account_id, creator);
            assert_eq!(domain_obj.created_at, created_at);
            assert_eq!(domain_obj.domain_config, domain_config);
        });
    }
}
