//! Benchmarking for `pallet-evm-tracker::check_contract` extension.

use super::*;
use crate::create_contract::CheckContractCreation;
use crate::traits::{AccountIdFor, MaybeIntoEthCall, MaybeIntoEvmCall};
use crate::{EthereumAccountId, PermissionedActionAllowedBy};
use frame_benchmarking::v2::*;
use frame_support::pallet_prelude::DispatchClass;
use frame_system::pallet_prelude::{OriginFor, RuntimeCallFor};
use pallet_evm::GasWeightMapping;
use scale_info::prelude::vec;
use scale_info::prelude::vec::Vec;
use sp_core::crypto::AccountId32;
use sp_core::{Get, H160};
use sp_runtime::traits::AsSystemOriginSigner;
use sp_runtime::transaction_validity::ValidTransaction;
use subspace_runtime_primitives::utility::MaybeNestedCall;

#[cfg(test)]
use crate::Pallet as EVMNoncetracker;

/// The number of accounts to use in the benchmark allow list.
/// We deliberately use a large number to generate a realistic weight.
const ACCOUNT_COUNT: usize = 10;

/// The amount of nesting to use in benchmarks.
/// This over-estimates the weight of some calls, but most calls will only have a few levels.
const NESTING_DEPTH: u8 = 5;

/// Returns an AccountId32 with a deterministic address.
pub fn account_id(seed: u128) -> AccountId32 {
    let mut account_id = [0u8; 32];
    account_id[0..16].copy_from_slice(&seed.to_be_bytes());
    account_id[16..32].copy_from_slice(&seed.to_be_bytes());

    AccountId32::from(Into::<[u8; 32]>::into(account_id))
}

/// The kind of account list to generate.
#[expect(dead_code)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EvmAccountList {
    Anyone,
    NoOne,
    One,
    Multiple,
}

/// Generate the supplied kind of account list.
pub fn generate_evm_account_list(
    account_ids: &[AccountId32],
    account_list_type: EvmAccountList,
) -> PermissionedActionAllowedBy<EthereumAccountId> {
    match account_list_type {
        EvmAccountList::Anyone => PermissionedActionAllowedBy::Anyone,
        EvmAccountList::NoOne => PermissionedActionAllowedBy::Accounts(Vec::new()),
        EvmAccountList::One => {
            PermissionedActionAllowedBy::Accounts(vec![EthereumAccountId::from(
                account_ids[0].clone(),
            )])
        }
        EvmAccountList::Multiple => PermissionedActionAllowedBy::Accounts(
            account_ids
                .iter()
                .map(|id| EthereumAccountId::from(id.clone()))
                .collect::<Vec<_>>(),
        ),
    }
}

pub fn max_extrinsic_gas<TestRuntime: frame_system::Config + pallet_evm::Config>(
    multiplier: u64,
) -> u64 {
    let limits: frame_system::limits::BlockWeights =
        <TestRuntime as frame_system::Config>::BlockWeights::get();
    // `limits.get(DispatchClass::Normal).max_extrinsic` is too large to use as `gas_limit`
    // thus use `base_extrinsic`
    let max_extrinsic = limits.get(DispatchClass::Normal).base_extrinsic * multiplier;

    <TestRuntime as pallet_evm::Config>::GasWeightMapping::weight_to_gas(max_extrinsic)
}

/// Generate a pallet-evm call, which can be passed to `construct_and_send_extrinsic()`.
/// `use_create` determines whether to use `create`, `create2`, or a non-create call.
/// `recursion_depth` determines the number of `pallet_utility::Call` wrappers to use.
pub fn generate_evm_domain_call<TestRuntime>(
    account_id: EthereumAccountId,
    use_create: bool,
    recursion_depth: u8,
    nonce: U256,
    gas_price: U256,
) -> RuntimeCallFor<TestRuntime>
where
    TestRuntime: frame_system::Config + pallet_evm::Config + pallet_utility::Config,
    RuntimeCallFor<TestRuntime>:
        From<pallet_utility::Call<TestRuntime>> + From<pallet_evm::Call<TestRuntime>>,
{
    if recursion_depth > 0 {
        let inner_call = generate_evm_domain_call::<TestRuntime>(
            account_id,
            use_create,
            recursion_depth - 1,
            nonce,
            gas_price,
        );

        // TODO:
        // - randomly choose from the 6 different utility wrapper calls
        // - test this call as the second call in a batch
        // - test __Ignore calls are ignored
        return pallet_utility::Call::<TestRuntime>::batch {
            calls: vec![inner_call.into()],
        }
        .into();
    }

    let call = if use_create {
        // TODO:
        // - randomly choose from Create or Create2 calls
        pallet_evm::Call::<TestRuntime>::create {
            source: account_id.into(),
            init: vec![0; 100],
            value: U256::zero(),
            gas_limit: max_extrinsic_gas::<TestRuntime>(1000),
            max_fee_per_gas: gas_price,
            access_list: vec![],
            max_priority_fee_per_gas: Some(U256::from(1)),
            nonce: Some(nonce),
        }
    } else {
        pallet_evm::Call::<TestRuntime>::call {
            source: account_id.into(),
            target: H160::default(),
            input: vec![0; 100],
            value: U256::zero(),
            gas_limit: max_extrinsic_gas::<TestRuntime>(1000),
            max_fee_per_gas: gas_price,
            max_priority_fee_per_gas: Some(U256::from(1)),
            nonce: Some(nonce),
            access_list: vec![],
        }
    };

    call.into()
}

#[allow(clippy::multiple_bound_locations)]
#[benchmarks(
    where
        T: frame_system::Config<AccountId = EthereumAccountId>,
        T: pallet_utility::Config,
        T: pallet_ethereum::Config,
        T: pallet_evm::Config,
        RuntimeCallFor<T>: MaybeIntoEthCall<T> + MaybeIntoEvmCall<T> + MaybeNestedCall<T> +
            From<pallet_utility::Call<T>> + From<pallet_evm::Call<T>>,
        Result<pallet_ethereum::RawOrigin, OriginFor<T>>: From<OriginFor<T>>,
        OriginFor<T>:
            AsSystemOriginSigner<AccountIdFor<T>> + From<Option<EthereumAccountId>> + Clone,
        T: scale_info::TypeInfo,
        T: core::fmt::Debug,
        T: core::marker::Send,
        T: core::marker::Sync,
    )]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn validate_nested_call() {
        let account_ids = (0..ACCOUNT_COUNT)
            .map(|i| account_id(i as u128))
            .collect::<Vec<AccountId32>>();
        let accounts = generate_evm_account_list(&account_ids, EvmAccountList::Multiple);

        ContractCreationAllowedBy::<T>::put(accounts);

        // Checking a disallowed account is more expensive, because we have to check if the
        // transaction contains any creates.
        let sender = EthereumAccountId::from(account_id((ACCOUNT_COUNT + 1) as u128));
        let sender_origin = Some(sender).into();

        let nested_call = generate_evm_domain_call::<T>(
            sender,
            // Checking a contract call is more expensive, because we can't early exit.
            // But in this case we only have one runtime call, so it doesn't matter.
            false,
            NESTING_DEPTH,
            U256::default(),
            U256::default(),
        );

        #[block]
        {
            assert_eq!(
                CheckContractCreation::<T>::do_validate(&sender_origin, &nested_call),
                Ok(ValidTransaction::default()),
            );
        }
    }

    impl_benchmark_test_suite!(
        EVMNoncetracker,
        crate::mock::new_test_ext(),
        crate::mock::MockRuntime,
    );
}
