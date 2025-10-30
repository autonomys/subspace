//! Domain registry for domains

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::block_tree::import_genesis_receipt;
use crate::pallet::DomainStakingSummary;
use crate::staking::StakingSummary;
use crate::{
    BalanceOf, Config, DomainHashingFor, DomainRegistry, DomainSudoCalls, EvmChainIds,
    ExecutionReceiptOf, HoldIdentifier, NextDomainId, RuntimeRegistry, into_complete_raw_genesis,
};
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use domain_runtime_primitives::MultiAccountId;
use frame_support::traits::fungible::{Inspect, Mutate, MutateHold};
use frame_support::traits::tokens::{Fortitude, Precision, Preservation};
use frame_support::weights::Weight;
use frame_support::{PalletError, ensure};
use frame_system::pallet_prelude::*;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::{
    DomainBundleLimit, DomainId, DomainRuntimeInfo, DomainSudoCall, DomainsDigestItem,
    DomainsTransfersTracker, OnDomainInstantiated, OperatorAllowList, RuntimeId, RuntimeType,
    calculate_max_bundle_weight_and_size, derive_domain_block_hash,
};
use sp_runtime::DigestItem;
use sp_runtime::traits::{CheckedAdd, Zero};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::btree_set::BTreeSet;

/// Domain registry specific errors
#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum Error {
    ExceedMaxDomainBlockWeight,
    ExceedMaxDomainBlockSize,
    MaxDomainId,
    InvalidEVMChainId,
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
    InvalidConfigForRuntimeType,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct DomainConfig<AccountId: Ord, Balance> {
    /// A user defined name for this domain, should be a human-readable UTF-8 encoded string.
    pub domain_name: String,
    /// A pointer to the `RuntimeRegistry` entry for this domain.
    pub runtime_id: RuntimeId,
    /// The max bundle size for this domain, may not exceed the system-wide `MaxDomainBlockSize` limit.
    pub max_bundle_size: u32,
    /// The max bundle weight for this domain, may not exceed the system-wide `MaxDomainBlockWeight` limit.
    pub max_bundle_weight: Weight,
    /// The probability of successful bundle in a slot (active slots coefficient). This defines the
    /// expected bundle production rate, must be `> 0` and `≤ 1`.
    pub bundle_slot_probability: (u64, u64),
    /// Accounts allowed to operate on this domain.
    pub operator_allow_list: OperatorAllowList<AccountId>,
    // Initial balances for this domain.
    pub initial_balances: Vec<(MultiAccountId, Balance)>,
}

/// Parameters of the `instantiate_domain` call, it is similar to `DomainConfig` except the `max_bundle_size/weight`
/// is replaced by a optional `maybe_bundle_limit`.
///
/// It is used to derive `DomainConfig`, and if `maybe_bundle_limit` is `None` a default `max_bundle_size/weight`
/// derived from the `bundle_slot_probability` and other system-wide parameters will be used.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct DomainConfigParams<AccountId: Ord, Balance> {
    pub domain_name: String,
    pub runtime_id: RuntimeId,
    pub maybe_bundle_limit: Option<DomainBundleLimit>,
    pub bundle_slot_probability: (u64, u64),
    pub operator_allow_list: OperatorAllowList<AccountId>,
    pub initial_balances: Vec<(MultiAccountId, Balance)>,
    /// Configurations for a specific type of domain runtime, for example, EVM.
    /// Currently these are all copied into `DomainObject.domain_runtime_info`, so they don't need
    /// to be in `DomainConfig`.
    pub domain_runtime_info: DomainRuntimeInfo,
}

pub fn into_domain_config<T: Config>(
    domain_config_params: DomainConfigParams<T::AccountId, BalanceOf<T>>,
) -> Result<DomainConfig<T::AccountId, BalanceOf<T>>, Error> {
    let DomainConfigParams {
        domain_name,
        runtime_id,
        maybe_bundle_limit,
        bundle_slot_probability,
        operator_allow_list,
        initial_balances,
        domain_runtime_info: _,
    } = domain_config_params;

    let DomainBundleLimit {
        max_bundle_size,
        max_bundle_weight,
    } = match maybe_bundle_limit {
        Some(b) => b,
        None => calculate_max_bundle_weight_and_size(
            T::MaxDomainBlockSize::get(),
            T::MaxDomainBlockWeight::get(),
            T::ConsensusSlotProbability::get(),
            bundle_slot_probability,
        )
        .ok_or(Error::BundleLimitCalculationOverflow)?,
    };

    Ok(DomainConfig {
        domain_name,
        runtime_id,
        max_bundle_size,
        max_bundle_weight,
        bundle_slot_probability,
        operator_allow_list,
        initial_balances,
    })
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
    /// The amount of balance hold on the domain owner account
    pub domain_instantiation_deposit: Balance,
}

pub(crate) fn can_instantiate_domain<T: Config>(
    owner_account_id: &T::AccountId,
    domain_config_params: DomainConfigParams<T::AccountId, BalanceOf<T>>,
) -> Result<DomainConfig<T::AccountId, BalanceOf<T>>, Error> {
    // `bundle_slot_probability` must be `> 0` and `≤ 1`
    let (numerator, denominator) = domain_config_params.bundle_slot_probability;
    ensure!(
        numerator != 0 && denominator != 0 && numerator <= denominator,
        Error::InvalidSlotProbability
    );

    let domain_config = into_domain_config::<T>(domain_config_params)?;

    ensure!(
        domain_config.domain_name.len() as u32 <= T::MaxDomainNameLength::get(),
        Error::DomainNameTooLong,
    );
    ensure!(
        RuntimeRegistry::<T>::contains_key(domain_config.runtime_id),
        Error::RuntimeNotFound
    );
    ensure!(
        domain_config.max_bundle_size <= T::MaxDomainBlockSize::get(),
        Error::ExceedMaxDomainBlockSize
    );
    ensure!(
        domain_config
            .max_bundle_weight
            .all_lte(T::MaxDomainBlockWeight::get()),
        Error::ExceedMaxDomainBlockWeight
    );

    ensure!(
        T::Currency::reducible_balance(owner_account_id, Preservation::Protect, Fortitude::Polite)
            >= T::DomainInstantiationDeposit::get(),
        Error::InsufficientFund
    );

    domain_config.check_initial_balances::<T>()?;

    Ok(domain_config)
}

pub(crate) fn do_instantiate_domain<T: Config>(
    domain_config_params: DomainConfigParams<T::AccountId, BalanceOf<T>>,
    owner_account_id: T::AccountId,
    created_at: BlockNumberFor<T>,
) -> Result<DomainId, Error> {
    let domain_runtime_info = domain_config_params.domain_runtime_info.clone();
    let domain_config = can_instantiate_domain::<T>(&owner_account_id, domain_config_params)?;

    let domain_instantiation_deposit = T::DomainInstantiationDeposit::get();
    let domain_id = NextDomainId::<T>::get();
    let runtime_obj = RuntimeRegistry::<T>::mutate(domain_config.runtime_id, |maybe_runtime_obj| {
        let mut runtime_object = maybe_runtime_obj
            .take()
            .expect("Runtime object must exist as checked in `can_instantiate_domain`; qed");
        runtime_object.instance_count = runtime_object.instance_count.saturating_add(1);
        *maybe_runtime_obj = Some(runtime_object.clone());
        runtime_object
    });

    let domain_runtime_info = match (runtime_obj.runtime_type, domain_runtime_info) {
        (
            RuntimeType::Evm,
            DomainRuntimeInfo::Evm {
                chain_id,
                domain_runtime_config,
            },
        ) => {
            // ensure chain_id is not already allocated.
            ensure!(
                !EvmChainIds::<T>::contains_key(chain_id),
                Error::InvalidEVMChainId
            );

            // allocate the chain_id to this domain
            EvmChainIds::<T>::insert(chain_id, domain_id);

            DomainRuntimeInfo::Evm {
                chain_id,
                domain_runtime_config,
            }
        }
        (
            RuntimeType::AutoId,
            DomainRuntimeInfo::AutoId {
                domain_runtime_config,
            },
        ) => DomainRuntimeInfo::AutoId {
            domain_runtime_config,
        },
        _ => return Err(Error::InvalidConfigForRuntimeType),
    };

    // burn total issuance on domain from owners account and track the domain balance
    let total_issuance = domain_config
        .total_issuance()
        .ok_or(Error::InitialBalanceOverflow)?;

    T::Currency::burn_from(
        &owner_account_id,
        total_issuance,
        Preservation::Expendable,
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
            &domain_runtime_info,
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
            T::CurrentBundleAndExecutionReceiptVersion::get().execution_receipt_version,
        )
    };
    let genesis_receipt_hash = genesis_receipt.hash::<DomainHashingFor<T>>();

    let domain_obj = DomainObject {
        owner_account_id: owner_account_id.clone(),
        created_at,
        genesis_receipt_hash,
        domain_config,
        domain_runtime_info,
        domain_instantiation_deposit,
    };
    DomainRegistry::<T>::insert(domain_id, domain_obj);

    let next_domain_id = domain_id.checked_add(&1.into()).ok_or(Error::MaxDomainId)?;
    NextDomainId::<T>::set(next_domain_id);

    // Lock up `domain_instantiation_deposit` amount of fund of the domain instance creator
    T::Currency::hold(
        &T::HoldIdentifier::domain_instantiation_id(),
        &owner_account_id,
        domain_instantiation_deposit,
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

    DomainSudoCalls::<T>::insert(domain_id, DomainSudoCall { maybe_call: None });

    frame_system::Pallet::<T>::deposit_log(DigestItem::domain_instantiation(domain_id));

    Ok(domain_id)
}

pub(crate) fn do_update_domain_allow_list<T: Config>(
    domain_owner: T::AccountId,
    domain_id: DomainId,
    updated_operator_allow_list: OperatorAllowList<T::AccountId>,
) -> Result<(), Error> {
    let mut domain_obj = DomainRegistry::<T>::get(domain_id).ok_or(Error::DomainNotFound)?;

    ensure!(
        domain_obj.owner_account_id == domain_owner,
        Error::NotDomainOwner,
    );

    domain_obj.domain_config.operator_allow_list = updated_operator_allow_list;
    DomainRegistry::<T>::insert(domain_id, domain_obj);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::Test;
    use crate::tests::{TEST_RUNTIME_APIS, new_test_ext};
    use domain_runtime_primitives::{AccountId20, AccountId20Converter, DEFAULT_EVM_CHAIN_ID};
    use frame_support::traits::Currency;
    use frame_support::{assert_err, assert_ok};
    use hex_literal::hex;
    use sp_domains::storage::RawGenesis;
    use sp_domains::{EvmDomainRuntimeConfig, EvmType, PermissionedActionAllowedBy, RuntimeObject};
    use sp_runtime::traits::Convert;
    use sp_std::vec;
    use sp_version::{RuntimeVersion, create_apis_vec};
    use subspace_runtime_primitives::AI3;

    type Balances = pallet_balances::Pallet<Test>;

    #[test]
    fn test_domain_instantiation() {
        let creator = 1u128;
        let created_at = 0u32;
        // Construct an invalid domain config initially
        let mut domain_config_params = DomainConfigParams {
            domain_name: String::from_utf8(vec![0; 1024]).unwrap(),
            runtime_id: 0,
            maybe_bundle_limit: Some(DomainBundleLimit {
                max_bundle_size: u32::MAX,
                max_bundle_weight: Weight::MAX,
            }),
            bundle_slot_probability: (0, 0),
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: Default::default(),
            domain_runtime_info: (DEFAULT_EVM_CHAIN_ID, Default::default()).into(),
        };

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            assert_eq!(NextDomainId::<Test>::get(), 0.into());

            // Failed to instantiate domain due to invalid `bundle_slot_probability`
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Err(Error::InvalidSlotProbability)
            );
            domain_config_params.bundle_slot_probability = (1, 0);
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Err(Error::InvalidSlotProbability)
            );
            domain_config_params.bundle_slot_probability = (0, 1);
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Err(Error::InvalidSlotProbability)
            );
            domain_config_params.bundle_slot_probability = (2, 1);
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Err(Error::InvalidSlotProbability)
            );
            // Recorrect `bundle_slot_probability`
            domain_config_params.bundle_slot_probability = (1, 1);

            // Failed to instantiate domain due to `domain_name` too long
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Err(Error::DomainNameTooLong)
            );
            // Recorrect `domain_name`
            "evm-domain".clone_into(&mut domain_config_params.domain_name);

            // Failed to instantiate domain due to using unregistered runtime id
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Err(Error::RuntimeNotFound)
            );
            // Register runtime id
            RuntimeRegistry::<Test>::insert(
                domain_config_params.runtime_id,
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
                        apis: create_apis_vec!(TEST_RUNTIME_APIS),
                        ..Default::default()
                    },
                    created_at: Default::default(),
                    updated_at: Default::default(),
                    instance_count: 0,
                },
            );

            // Failed to instantiate domain due to exceed max domain block size limit
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Err(Error::ExceedMaxDomainBlockSize)
            );
            // Recorrect `max_bundle_size`
            domain_config_params
                .maybe_bundle_limit
                .as_mut()
                .unwrap()
                .max_bundle_size = 1;

            // Failed to instantiate domain due to exceed max domain block weight limit
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Err(Error::ExceedMaxDomainBlockWeight)
            );
            // Recorrect `max_bundle_weight`
            domain_config_params
                .maybe_bundle_limit
                .as_mut()
                .unwrap()
                .max_bundle_weight = Weight::from_parts(1, 0);

            // Failed to instantiate domain due to creator don't have enough fund
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Err(Error::InsufficientFund)
            );
            // Set enough fund to creator
            Balances::make_free_balance_be(
                &creator,
                <Test as Config>::DomainInstantiationDeposit::get()
                    + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
            );
            // Set `maybe_bundle_limit` to use the default bundle limit
            domain_config_params.maybe_bundle_limit = None;

            // `instantiate_domain` must success now
            let domain_id =
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at)
                    .unwrap();
            let domain_obj = DomainRegistry::<Test>::get(domain_id).unwrap();

            assert_eq!(domain_obj.owner_account_id, creator);
            assert_eq!(domain_obj.created_at, created_at);
            assert_eq!(
                domain_obj.domain_config,
                into_domain_config::<Test>(domain_config_params.clone()).unwrap()
            );
            assert_eq!(NextDomainId::<Test>::get(), 1.into());
            // Fund locked up thus can't withdraw, and usable balance is zero since ED is 1
            assert_eq!(Balances::usable_balance(creator), Zero::zero());

            // instance count must be incremented
            let runtime_obj =
                RuntimeRegistry::<Test>::get(domain_config_params.runtime_id).unwrap();
            assert_eq!(runtime_obj.instance_count, 1);

            // cannot use the locked funds to create a new domain instance
            assert_eq!(
                do_instantiate_domain::<Test>(domain_config_params, creator, created_at),
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
        let created_at = 0u32;
        // Construct an invalid domain config initially
        let mut domain_config_params = DomainConfigParams {
            domain_name: "evm-domain".to_owned(),
            runtime_id: 0,
            maybe_bundle_limit: None,
            bundle_slot_probability: (1, 1),
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: vec![(MultiAccountId::Raw(vec![0, 1, 2, 3, 4, 5]), 1_000_000 * AI3)],
            domain_runtime_info: (DEFAULT_EVM_CHAIN_ID, Default::default()).into(),
        };

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            assert_eq!(NextDomainId::<Test>::get(), 0.into());
            // Register runtime id
            RuntimeRegistry::<Test>::insert(
                domain_config_params.runtime_id,
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
                        apis: create_apis_vec!(TEST_RUNTIME_APIS),
                        ..Default::default()
                    },
                    created_at: Default::default(),
                    updated_at: Default::default(),
                    instance_count: 0,
                },
            );

            // Set enough fund to creator
            Balances::make_free_balance_be(
                &creator,
                <Test as Config>::DomainInstantiationDeposit::get()
                    // for domain total issuance
                    + 1_000_000 * AI3
                    + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
            );

            // should fail due to invalid account ID type
            assert_err!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Error::FailedToGenerateRawGenesis(
                    crate::runtime_registry::Error::InvalidAccountIdType
                )
            );

            // duplicate accounts
            domain_config_params.initial_balances = vec![
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
                    ))),
                    1_000_000 * AI3,
                ),
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
                    ))),
                    1_000_000 * AI3,
                ),
            ];

            assert_err!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Error::DuplicateInitialAccounts
            );

            // max accounts
            domain_config_params.initial_balances = vec![
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
                    ))),
                    1_000_000 * AI3,
                ),
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cbc"
                    ))),
                    1_000_000 * AI3,
                ),
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566ccc"
                    ))),
                    1_000_000 * AI3,
                ),
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cdc"
                    ))),
                    1_000_000 * AI3,
                ),
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cec"
                    ))),
                    1_000_000 * AI3,
                ),
                (
                    AccountId20Converter::convert(AccountId20::from(hex!(
                        "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cfc"
                    ))),
                    1_000_000 * AI3,
                ),
            ];

            assert_err!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Error::MaxInitialDomainAccounts
            );

            // min balance accounts
            domain_config_params.initial_balances = vec![(
                AccountId20Converter::convert(AccountId20::from(hex!(
                    "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
                ))),
                1,
            )];

            assert_err!(
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at),
                Error::MinInitialAccountBalance
            );

            domain_config_params.initial_balances = vec![(
                AccountId20Converter::convert(AccountId20::from(hex!(
                    "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
                ))),
                1_000_000 * AI3,
            )];

            // Set enough fund to creator
            Balances::make_free_balance_be(
                &creator,
                <Test as Config>::DomainInstantiationDeposit::get()
                    // for domain total issuance
                    + 1_000_000 * AI3
                    + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
            );

            // should be successful
            domain_config_params.domain_runtime_info =
                (DEFAULT_EVM_CHAIN_ID + 1, Default::default()).into();
            let domain_id =
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at)
                    .unwrap();
            let domain_obj = DomainRegistry::<Test>::get(domain_id).unwrap();

            assert_eq!(domain_obj.owner_account_id, creator);
            assert_eq!(domain_obj.created_at, created_at);
            assert_eq!(
                domain_obj.domain_config,
                into_domain_config::<Test>(domain_config_params).unwrap()
            );
        });
    }

    #[test]
    fn test_domain_instantiation_evm_contract_allow_list() {
        let creator = 1u128;
        let created_at = 0u32;
        // Construct a valid default domain config
        let mut domain_config_params = DomainConfigParams {
            domain_name: "evm-domain".to_owned(),
            runtime_id: 0,
            maybe_bundle_limit: None,
            bundle_slot_probability: (1, 1),
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: vec![(
                AccountId20Converter::convert(AccountId20::from(hex!(
                    "f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"
                ))),
                1_000_000 * AI3,
            )],
            domain_runtime_info: (DEFAULT_EVM_CHAIN_ID, Default::default()).into(),
        };

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            assert_eq!(NextDomainId::<Test>::get(), 0.into());
            // Register runtime id
            RuntimeRegistry::<Test>::insert(
                domain_config_params.runtime_id,
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
                        apis: create_apis_vec!(TEST_RUNTIME_APIS),
                        ..Default::default()
                    },
                    created_at: Default::default(),
                    updated_at: Default::default(),
                    instance_count: 0,
                },
            );

            // Set enough fund to creator
            Balances::make_free_balance_be(
                &creator,
                <Test as Config>::DomainInstantiationDeposit::get()
                    // for domain total issuance
                    + 1_000_000 * AI3
                    + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
            );

            // should be successful
            let domain_id =
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at)
                    .unwrap();
            let domain_obj = DomainRegistry::<Test>::get(domain_id).unwrap();

            assert_eq!(domain_obj.owner_account_id, creator);
            assert_eq!(domain_obj.created_at, created_at);
            assert_eq!(
                domain_obj.domain_config,
                into_domain_config::<Test>(domain_config_params.clone()).unwrap()
            );
            assert_eq!(
                domain_obj
                    .domain_runtime_info
                    .initial_contract_creation_allow_list(),
                None,
                "default is public EVM, which does not have a contract creation allow list"
            );

            // Set public EVM
            domain_config_params.domain_runtime_info = (
                DEFAULT_EVM_CHAIN_ID + 1,
                EvmDomainRuntimeConfig {
                    evm_type: EvmType::Public,
                },
            )
                .into();

            // Set enough fund to creator
            Balances::make_free_balance_be(
                &creator,
                <Test as Config>::DomainInstantiationDeposit::get()
                                // for domain total issuance
                                + 1_000_000 * AI3
                                + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
            );

            // should be successful
            let domain_id =
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at)
                    .unwrap();
            let domain_obj = DomainRegistry::<Test>::get(domain_id).unwrap();

            assert_eq!(domain_obj.owner_account_id, creator);
            assert_eq!(domain_obj.created_at, created_at);
            assert_eq!(
                domain_obj.domain_config,
                into_domain_config::<Test>(domain_config_params.clone()).unwrap()
            );
            assert_eq!(
                domain_obj
                    .domain_runtime_info
                    .initial_contract_creation_allow_list(),
                None,
                "public EVMs do not have a contract creation allow list"
            );

            // Set empty list
            let mut list = vec![];
            domain_config_params.domain_runtime_info = (
                DEFAULT_EVM_CHAIN_ID + 2,
                EvmDomainRuntimeConfig {
                    evm_type: EvmType::Private {
                        initial_contract_creation_allow_list: PermissionedActionAllowedBy::Accounts(
                            list.clone(),
                        ),
                    },
                },
            )
                .into();

            // Set enough fund to creator
            Balances::make_free_balance_be(
                &creator,
                <Test as Config>::DomainInstantiationDeposit::get()
                    // for domain total issuance
                    + 1_000_000 * AI3
                    + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
            );

            // should be successful
            let domain_id =
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at)
                    .unwrap();
            let domain_obj = DomainRegistry::<Test>::get(domain_id).unwrap();

            assert_eq!(domain_obj.owner_account_id, creator);
            assert_eq!(domain_obj.created_at, created_at);
            assert_eq!(
                domain_obj.domain_config,
                into_domain_config::<Test>(domain_config_params.clone()).unwrap()
            );
            assert_eq!(
                domain_obj
                    .domain_runtime_info
                    .initial_contract_creation_allow_list(),
                Some(&PermissionedActionAllowedBy::Accounts(list)),
                "empty list should work"
            );

            // Set 1 account in list
            list = vec![hex!("0102030405060708091011121314151617181920").into()];
            domain_config_params.domain_runtime_info = (
                DEFAULT_EVM_CHAIN_ID + 3,
                EvmDomainRuntimeConfig {
                    evm_type: EvmType::Private {
                        initial_contract_creation_allow_list: PermissionedActionAllowedBy::Accounts(
                            list.clone(),
                        ),
                    },
                },
            )
                .into();

            // Set enough fund to creator
            Balances::make_free_balance_be(
                &creator,
                <Test as Config>::DomainInstantiationDeposit::get()
                    // for domain total issuance
                    + 1_000_000 * AI3
                    + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
            );

            // should be successful
            let domain_id =
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at)
                    .unwrap();
            let domain_obj = DomainRegistry::<Test>::get(domain_id).unwrap();

            assert_eq!(domain_obj.owner_account_id, creator);
            assert_eq!(domain_obj.created_at, created_at);
            assert_eq!(
                domain_obj.domain_config,
                into_domain_config::<Test>(domain_config_params.clone()).unwrap()
            );
            assert_eq!(
                domain_obj
                    .domain_runtime_info
                    .initial_contract_creation_allow_list(),
                Some(&PermissionedActionAllowedBy::Accounts(list)),
                "1 account list should work"
            );

            // Set multi account list
            list = vec![
                hex!("0102030405060708091011121314151617181920").into(),
                hex!("1102030405060708091011121314151617181920").into(),
                hex!("2102030405060708091011121314151617181920").into(),
            ];
            domain_config_params.domain_runtime_info = (
                DEFAULT_EVM_CHAIN_ID + 4,
                EvmDomainRuntimeConfig {
                    evm_type: EvmType::Private {
                        initial_contract_creation_allow_list: PermissionedActionAllowedBy::Accounts(
                            list.clone(),
                        ),
                    },
                },
            )
                .into();

            // Set enough fund to creator
            Balances::make_free_balance_be(
                &creator,
                <Test as Config>::DomainInstantiationDeposit::get()
                    // for domain total issuance
                    + 1_000_000 * AI3
                    + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
            );

            // should be successful
            let domain_id =
                do_instantiate_domain::<Test>(domain_config_params.clone(), creator, created_at)
                    .unwrap();
            let domain_obj = DomainRegistry::<Test>::get(domain_id).unwrap();

            assert_eq!(domain_obj.owner_account_id, creator);
            assert_eq!(domain_obj.created_at, created_at);
            assert_eq!(
                domain_obj.domain_config,
                into_domain_config::<Test>(domain_config_params.clone()).unwrap()
            );
            assert_eq!(
                domain_obj
                    .domain_runtime_info
                    .initial_contract_creation_allow_list(),
                Some(&PermissionedActionAllowedBy::Accounts(list)),
                "multi account list should work"
            );
        });
    }
}
