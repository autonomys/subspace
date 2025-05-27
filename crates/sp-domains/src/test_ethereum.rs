//! Test setup shared by sp-domains-fraud-proof and domain-operator tests

use crate::test_ethereum_tx::{
    AccountInfo, EIP1559UnsignedTransaction, EIP2930UnsignedTransaction, LegacyUnsignedTransaction,
};
use crate::{EthereumAccountId, PermissionedActionAllowedBy};
use ethereum::TransactionV2 as Transaction;
use frame_support::pallet_prelude::DispatchClass;
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
