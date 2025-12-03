//! Benchmarking for `pallet-evm-tracker::check_contract` extension.

use super::*;
use crate::create_contract::CheckContractCreation;
use crate::traits::{AccountIdFor, MaybeIntoEthCall, MaybeIntoEvmCall};
use crate::{EthereumAccountId, MAXIMUM_NUMBER_OF_CALLS, PermissionedActionAllowedBy};
use frame_benchmarking::v2::*;
use frame_support::pallet_prelude::DispatchClass;
use frame_system::pallet_prelude::{OriginFor, RuntimeCallFor};
use pallet_evm::GasWeightMapping;
use scale_info::prelude::vec;
use scale_info::prelude::vec::Vec;
use sp_core::crypto::AccountId32;
use sp_core::{Get, H160};
use sp_runtime::traits::AsSystemOriginSigner;
use static_assertions::const_assert;
use subspace_runtime_primitives::utility::MaybeNestedCall;

/// The number of accounts to use in the benchmark allow list.
/// We deliberately use a large number to generate a realistic weight.
const ACCOUNT_COUNT: usize = 10;

/// The number of calls we can recursively make without hitting the stack limit.
/// (Beyond this limit, the weight calculation code assumes a linear increase in weight.)
const MAXIMUM_NUMBER_OF_CALLS_ON_STACK: u32 = 1_300;

const_assert!(MAXIMUM_NUMBER_OF_CALLS_ON_STACK <= MAXIMUM_NUMBER_OF_CALLS);

#[allow(clippy::multiple_bound_locations)]
#[benchmarks(
    where
        T: frame_system::Config<AccountId = EthereumAccountId> + pallet_utility::Config +
            pallet_ethereum::Config + pallet_evm::Config + scale_info::TypeInfo +
            core::fmt::Debug + core::marker::Send + core::marker::Sync,
        RuntimeCallFor<T>: MaybeIntoEthCall<T> + MaybeIntoEvmCall<T> + MaybeNestedCall<T> +
            From<pallet_utility::Call<T>> + From<pallet_evm::Call<T>>,
        Result<pallet_ethereum::RawOrigin, OriginFor<T>>: From<OriginFor<T>>,
        OriginFor<T>:
            AsSystemOriginSigner<AccountIdFor<T>> + From<Option<EthereumAccountId>> + Clone,
    )]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn evm_contract_check_multiple(c: Linear<0, MAXIMUM_NUMBER_OF_CALLS>) {
        let account_ids = (0..ACCOUNT_COUNT)
            .map(|i| account_id(i as u128))
            .collect::<Vec<AccountId32>>();
        // Checking multiple accounts is more expensive than single or empty accounts, or Anyone.
        let accounts = generate_evm_account_list(&account_ids, EvmAccountList::Multiple);

        ContractCreationAllowedBy::<T>::put(accounts);

        // Checking a disallowed account is more expensive, because we have to check if the
        // transaction contains any creates.
        let sender = EthereumAccountId::from(account_id(ACCOUNT_COUNT as u128 + u128::from(c)));
        let sender_origin = Some(sender).into();

        let mut calls = Vec::with_capacity(c as usize + 1);
        for _i in 0..=c {
            let contract_call = generate_evm_domain_call::<T>(
                sender,
                // Checking a non-contract call is more expensive, because we can't early exit.
                // (We can only exit the check loop early if we encounter a contract call.)
                false,
                0,
                U256::default(),
                U256::default(),
            );

            calls.push(contract_call);
        }

        let call = construct_utility_call_list::<T>(calls);

        #[block]
        {
            // Checking signed is more expensive, because it has to check the allow list.
            let _ = CheckContractCreation::<T>::do_validate_signed(&sender_origin, &call);
        }
    }

    #[benchmark]
    fn evm_contract_check_nested(c: Linear<0, MAXIMUM_NUMBER_OF_CALLS_ON_STACK>) {
        let account_ids = (0..ACCOUNT_COUNT)
            .map(|i| account_id(i as u128))
            .collect::<Vec<AccountId32>>();
        let accounts = generate_evm_account_list(&account_ids, EvmAccountList::Multiple);

        ContractCreationAllowedBy::<T>::put(accounts);

        let sender = EthereumAccountId::from(account_id(ACCOUNT_COUNT as u128 + u128::from(c)));
        let sender_origin = Some(sender).into();

        let nested_call = generate_evm_domain_call::<T>(
            sender,
            // In this case, the call type doesn't matter, because we have to check each nested call.
            false,
            c,
            U256::default(),
            U256::default(),
        );

        #[block]
        {
            let _ = CheckContractCreation::<T>::do_validate_signed(&sender_origin, &nested_call);
        }
    }

    // TODO: impl_benchmark_test_suite!() aganst a mock runtime, when
    // `cargo test --features=runtime-benchmarks` is fixed for existing benchmark tests.
}

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
    recursion_depth: u32,
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
        return construct_utility_call::<TestRuntime>(inner_call);
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
            authorization_list: vec![],
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
            authorization_list: vec![],
        }
    };

    call.into()
}

fn construct_utility_call<T: pallet_utility::Config>(call: RuntimeCallFor<T>) -> RuntimeCallFor<T>
where
    RuntimeCallFor<T>: From<pallet_utility::Call<T>>,
{
    pallet_utility::Call::batch_all {
        calls: vec![call.into()],
    }
    .into()
}

fn construct_utility_call_list<T: pallet_utility::Config>(
    calls: Vec<RuntimeCallFor<T>>,
) -> RuntimeCallFor<T>
where
    RuntimeCallFor<T>: From<pallet_utility::Call<T>>,
{
    pallet_utility::Call::batch_all {
        calls: calls.into_iter().map(Into::into).collect(),
    }
    .into()
}
