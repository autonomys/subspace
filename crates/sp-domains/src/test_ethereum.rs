//! Test setup shared by sp-domains-fraud-proof and domain-operator tests

use crate::test_ethereum_tx::{
    AccountInfo, EIP1559UnsignedTransaction, EIP2930UnsignedTransaction, LegacyUnsignedTransaction,
};
use crate::{EthereumAccountId, PermissionedActionAllowedBy};
use ethereum::TransactionV2 as Transaction;
use frame_support::pallet_prelude::DispatchClass;
use frame_system::pallet_prelude::RuntimeCallFor;
use hex_literal::hex;
use pallet_evm::GasWeightMapping;
use sp_core::{Get, U256};

/// The kind of account list to generate.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EvmAccountList {
    Anyone,
    NoOne,
    One,
    Multiple,
}

/// Generate the supplied kind of account list.
pub fn generate_evm_account_list(
    account_infos: &[AccountInfo],
    account_list_type: EvmAccountList,
) -> PermissionedActionAllowedBy<EthereumAccountId> {
    // The signer of pallet-evm transactions is the EVM domain in some tests, so we also add it to
    // the account lists.
    let evm_domain_account = hex!("e04cc55ebee1cbce552f250e85c57b70b2e2625b");

    match account_list_type {
        EvmAccountList::Anyone => PermissionedActionAllowedBy::Anyone,
        EvmAccountList::NoOne => PermissionedActionAllowedBy::Accounts(Vec::new()),
        EvmAccountList::One => PermissionedActionAllowedBy::Accounts(vec![
            EthereumAccountId::from(evm_domain_account),
            EthereumAccountId::from(account_infos[0].address),
        ]),
        EvmAccountList::Multiple => PermissionedActionAllowedBy::Accounts(vec![
            EthereumAccountId::from(evm_domain_account),
            EthereumAccountId::from(account_infos[0].address),
            EthereumAccountId::from(account_infos[1].address),
            EthereumAccountId::from(account_infos[2].address),
        ]),
    }
}

/// Generate a pallet-evm call, which can be passed to `construct_and_send_extrinsic()`.
/// `use_create` determines whether to use `create`, `create2`, or a non-create call.
/// `recursion_depth` determines the number of `pallet_utility::Call` wrappers to use.
pub fn generate_evm_domain_call<TestRuntime>(
    account_info: AccountInfo,
    use_create: ethereum::TransactionAction,
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
            account_info,
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

    let call = match use_create {
        // TODO:
        // - randomly choose from Create or Create2 calls
        ethereum::TransactionAction::Create => pallet_evm::Call::<TestRuntime>::create {
            source: account_info.address,
            init: vec![0; 100],
            value: U256::zero(),
            gas_limit: max_extrinsic_gas::<TestRuntime>(1000),
            max_fee_per_gas: gas_price,
            access_list: vec![],
            max_priority_fee_per_gas: Some(U256::from(1)),
            nonce: Some(nonce),
        },
        ethereum::TransactionAction::Call(contract) => pallet_evm::Call::<TestRuntime>::call {
            source: account_info.address,
            target: contract,
            input: vec![0; 100],
            value: U256::zero(),
            gas_limit: max_extrinsic_gas::<TestRuntime>(1000),
            max_fee_per_gas: gas_price,
            max_priority_fee_per_gas: Some(U256::from(1)),
            nonce: Some(nonce),
            access_list: vec![],
        },
    };

    call.into()
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

pub fn generate_legacy_tx<TestRuntime: frame_system::Config + pallet_evm::Config>(
    account_info: AccountInfo,
    nonce: U256,
    action: ethereum::TransactionAction,
    input: Vec<u8>,
    gas_price: U256,
) -> Transaction {
    LegacyUnsignedTransaction {
        nonce,
        gas_price,
        gas_limit: U256::from(max_extrinsic_gas::<TestRuntime>(1000)),
        action,
        value: U256::zero(),
        input,
    }
    .sign(&account_info.private_key)
}

pub fn generate_eip2930_tx<TestRuntime: frame_system::Config + pallet_evm::Config>(
    account_info: AccountInfo,
    nonce: U256,
    action: ethereum::TransactionAction,
    input: Vec<u8>,
    gas_price: U256,
) -> Transaction {
    EIP2930UnsignedTransaction {
        nonce,
        gas_price,
        gas_limit: U256::from(max_extrinsic_gas::<TestRuntime>(100)),
        action,
        value: U256::one(),
        input,
    }
    .sign(&account_info.private_key, None)
}

pub fn generate_eip1559_tx<TestRuntime: frame_system::Config + pallet_evm::Config>(
    account_info: AccountInfo,
    nonce: U256,
    action: ethereum::TransactionAction,
    input: Vec<u8>,
    gas_price: U256,
) -> Transaction {
    EIP1559UnsignedTransaction {
        nonce,
        max_priority_fee_per_gas: U256::from(1),
        max_fee_per_gas: gas_price,
        gas_limit: U256::from(max_extrinsic_gas::<TestRuntime>(1000)),
        action,
        value: U256::zero(),
        input,
    }
    .sign(&account_info.private_key, None)
}
