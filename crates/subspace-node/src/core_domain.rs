pub(crate) mod core_evm_chain_spec;

use core_evm_runtime::AccountId as AccountId20;
use sp_core::crypto::AccountId32;
use sp_core::{ByteArray, H160};
use sp_runtime::traits::Convert;

pub struct AccountId32ToAccountId20Converter;

impl Convert<AccountId32, AccountId20> for AccountId32ToAccountId20Converter {
    fn convert(acc: AccountId32) -> AccountId20 {
        // Using the full hex key, truncating to the first 20 bytes (the first 40 hex chars)
        H160::from_slice(&acc.as_slice()[0..20]).into()
    }
}
