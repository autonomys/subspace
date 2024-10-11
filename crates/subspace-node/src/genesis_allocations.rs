use serde::Deserialize;
use core::num::NonZeroU128;
use subspace_runtime_primitives::{AccountId, Balance};

/// Genesis allocations JSON content
pub const GENESIS_ALLOCATIONS: &str = include_str!("genesis_allocations.json");

#[derive(Deserialize)]
struct GenesisAllocation(
    AccountId,
    #[serde(with = "balance_string")] NonZeroU128
);

pub fn get_genesis_allocations(contents: &str) -> Vec<(AccountId, Balance)> {
    let allocations: Vec<GenesisAllocation> = serde_json::from_str(contents)
        .expect("Failed to parse genesis allocations JSON");
    
    allocations.into_iter()
        .map(|GenesisAllocation(account, balance)| (account, balance.get() as Balance))
        .collect()
}

mod balance_string {
    use super::*;
    use serde::{de, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<NonZeroU128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<u128>()
            .map_err(de::Error::custom)
            .and_then(|n| NonZeroU128::new(n).ok_or_else(|| de::Error::custom("Balance must be non-zero")))
    }
}
