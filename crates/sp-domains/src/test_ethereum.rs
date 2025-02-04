//! Test setup shared by sp-domains-fraud-proof and domain-operator tests

use crate::test_ethereum_tx::{
    AccountInfo, EIP1559UnsignedTransaction, EIP2930UnsignedTransaction, LegacyUnsignedTransaction,
};
use ethereum::TransactionV2 as Transaction;
use frame_support::pallet_prelude::DispatchClass;
use pallet_evm::GasWeightMapping;
use sp_core::{Get, U256};

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
