// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Core EVM domain configurations.

use crate::chain_spec_utils::chain_spec_properties;
use core_evm_runtime::{
    AccountId, BalancesConfig, EVMChainIdConfig, GenesisConfig, MessengerConfig, Signature,
    SudoConfig, SystemConfig, WASM_BINARY,
};
use sc_service::ChainType;
use sc_subspace_chain_specs::ExecutionChainSpec;
use sp_core::{ecdsa, Pair, Public};
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::str::FromStr;
use subspace_runtime_primitives::SSC;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

pub type ChainSpec = ExecutionChainSpec<GenesisConfig>;

pub fn development_config() -> ExecutionChainSpec<GenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Development",
        // ID
        "core_evm_domain_dev",
        ChainType::Development,
        move || {
            testnet_genesis(
                vec![
                    get_account_id_from_seed::<ecdsa::Public>("Alice"),
                    get_account_id_from_seed::<ecdsa::Public>("Bob"),
                    get_account_id_from_seed::<ecdsa::Public>("Alice//stash"),
                    get_account_id_from_seed::<ecdsa::Public>("Bob//stash"),
                ],
                Some(get_account_id_from_seed::<ecdsa::Public>("Alice")),
                vec![(
                    get_account_id_from_seed::<ecdsa::Public>("Alice"),
                    get_account_id_from_seed::<ecdsa::Public>("Alice"),
                )],
                42,
            )
        },
        vec![],
        None,
        None,
        None,
        Some(chain_spec_properties()),
        None,
    )
}

pub fn local_testnet_config() -> ExecutionChainSpec<GenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Local Testnet",
        // ID
        "core_evm_domain_local_testnet",
        ChainType::Local,
        move || {
            testnet_genesis(
                vec![
                    get_account_id_from_seed::<ecdsa::Public>("Alice"),
                    get_account_id_from_seed::<ecdsa::Public>("Bob"),
                    get_account_id_from_seed::<ecdsa::Public>("Charlie"),
                    get_account_id_from_seed::<ecdsa::Public>("Dave"),
                    get_account_id_from_seed::<ecdsa::Public>("Eve"),
                    get_account_id_from_seed::<ecdsa::Public>("Ferdie"),
                    get_account_id_from_seed::<ecdsa::Public>("Alice//stash"),
                    get_account_id_from_seed::<ecdsa::Public>("Bob//stash"),
                    get_account_id_from_seed::<ecdsa::Public>("Charlie//stash"),
                    get_account_id_from_seed::<ecdsa::Public>("Dave//stash"),
                    get_account_id_from_seed::<ecdsa::Public>("Eve//stash"),
                    get_account_id_from_seed::<ecdsa::Public>("Ferdie//stash"),
                ],
                Some(get_account_id_from_seed::<ecdsa::Public>("Alice")),
                vec![
                    (
                        get_account_id_from_seed::<ecdsa::Public>("Alice"),
                        get_account_id_from_seed::<ecdsa::Public>("Alice"),
                    ),
                    (
                        get_account_id_from_seed::<ecdsa::Public>("Bob"),
                        get_account_id_from_seed::<ecdsa::Public>("Bob"),
                    ),
                ],
                43,
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("core-evm-local"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        None,
    )
}

pub fn gemini_3d_config() -> ExecutionChainSpec<GenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Subspace Gemini 3d Core EVM Domain",
        // ID
        "subspace_gemini_3d_core_evm_domain",
        ChainType::Live,
        move || {
            let sudo_account = AccountId::from_str("f31e60022e290708c17d6997c34de6a30d09438f")
                .expect("Invalid Sudo account");
            testnet_genesis(
                vec![
                    // Genesis executor
                    AccountId::from_str("2ac6c70c106138c8cd80da6b6a0e886b7eeee249")
                        .expect("Wrong executor account address"),
                    // Sudo account
                    sudo_account,
                ],
                Some(sudo_account),
                Default::default(),
                44,
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("subspace-gemini-3d-core-evm-domain"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        None,
    )
}

pub fn devnet_config() -> ExecutionChainSpec<GenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Subspace Devnet Core EVM Domain",
        // ID
        "subspace_devnet_core_evm_domain",
        ChainType::Custom("Testnet".to_string()),
        move || {
            let sudo_account = AccountId::from_str("b66a91845249464309fad766fd0ece8144547736")
                .expect("Invalid Sudo account");
            testnet_genesis(
                vec![
                    // Genesis executor
                    AccountId::from_str("cfdf9f58d9e532c3807ce62a5489cb19cfa6942d")
                        .expect("Wrong executor account address"),
                    // Sudo account
                    sudo_account,
                ],
                Some(sudo_account),
                vec![(
                    sudo_account,
                    AccountId::from_str("5b267fd1ba3ace6e3c3234f9576c49c877b5beb9")
                        .expect("Wrong relayer account address"),
                )],
                45,
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("subspace-devnet-core-evm-domain"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        None,
    )
}

pub fn load_chain_spec(spec_id: &str) -> std::result::Result<Box<dyn sc_cli::ChainSpec>, String> {
    let chain_spec = match spec_id {
        "dev" => development_config(),
        "gemini-3d" => gemini_3d_config(),
        "devnet" => devnet_config(),
        "" | "local" => local_testnet_config(),
        path => ChainSpec::from_json_file(std::path::PathBuf::from(path))?,
    };
    Ok(Box::new(chain_spec))
}

fn testnet_genesis(
    endowed_accounts: Vec<AccountId>,
    maybe_sudo_account: Option<AccountId>,
    relayers: Vec<(AccountId, AccountId)>,
    chain_id: u64,
) -> GenesisConfig {
    GenesisConfig {
        system: SystemConfig {
            code: WASM_BINARY
                .expect("WASM binary was not build, please build it!")
                .to_vec(),
        },
        sudo: SudoConfig {
            key: maybe_sudo_account,
        },
        transaction_payment: Default::default(),
        balances: BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 1_000_000 * SSC))
                .collect(),
        },
        messenger: MessengerConfig { relayers },
        evm_chain_id: EVMChainIdConfig { chain_id },
        evm: Default::default(),
        ethereum: Default::default(),
        dynamic_fee: Default::default(),
        base_fee: Default::default(),
    }
}
