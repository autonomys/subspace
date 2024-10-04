use subspace_runtime_primitives::{AccountId, Balance};
use sp_core::crypto::Ss58Codec;
use serde_json::Value;
use sp_runtime::traits::Zero;

pub fn get_genesis_allocations() -> Vec<(AccountId, Balance)> {
    let file_content = include_str!("genesis_allocations.json");
    
    let allocations: Value = serde_json::from_str(file_content)
        .expect("Failed to parse genesis allocations JSON");

    allocations.as_array()
        .expect("Genesis allocations should be an array")
        .iter()
        .enumerate() // Add enumeration to get the index
        .map(|(index, allocation)| {
            let address = allocation["address"].as_str()
                .expect("Each allocation should have an 'address' field");
            let balance_str = allocation["balance"].as_str()
                .unwrap_or_else(|| panic!("Allocation at index {} should have a 'balance' field as a string. Found: {:?}", index, allocation["balance"]));
            
            let balance = balance_str.parse::<u128>()
                .unwrap_or_else(|_| panic!("Invalid balance at index {}: {}", index, balance_str)) as Balance;

            if balance.is_zero() {
                panic!("Balance at index {} is zero", index);
            }

            let account_id = AccountId::from_ss58check(address)
                .unwrap_or_else(|_| panic!("Invalid Subspace SS58 address in genesis allocations at index {}: {}", index, address));
            
            (account_id, balance)
        })
        .collect()
}
