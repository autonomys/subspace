// Copyright (C) 2023 Subspace Labs, Inc.
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

//! AutoId domain configurations.

use crate::chain_spec_utils::{chain_spec_properties, get_account_id_from_seed};
use crate::domain::cli::SpecId;
use auto_id_domain_runtime::{
    BalancesConfig, RuntimeGenesisConfig, SudoConfig, SystemConfig, WASM_BINARY,
};
use domain_runtime_primitives::{AccountIdConverter, MultiAccountId};
use sc_chain_spec::GenericChainSpec;
use sc_service::ChainType;
use sp_core::crypto::AccountId32;
use sp_runtime::traits::Convert;
use subspace_runtime_primitives::{Balance, SSC};

/// Development keys that will be injected automatically on polkadotjs apps
fn get_dev_accounts() -> Vec<AccountId32> {
    vec![
        get_account_id_from_seed("Alice"),
        get_account_id_from_seed("Bob"),
        get_account_id_from_seed("Alice//stash"),
        get_account_id_from_seed("Bob//stash"),
    ]
}

pub fn development_config<F: Fn() -> RuntimeGenesisConfig + 'static + Send + Sync>(
    constructor: F,
) -> GenericChainSpec<RuntimeGenesisConfig> {
    // TODO: Migrate once https://github.com/paritytech/polkadot-sdk/issues/2963 is un-broken
    #[allow(deprecated)]
    GenericChainSpec::from_genesis(
        // Name
        "Development",
        // ID
        "auto_id_domain_dev",
        ChainType::Development,
        constructor,
        vec![],
        None,
        None,
        None,
        Some(chain_spec_properties()),
        None,
        // Code
        WASM_BINARY.expect("WASM binary was not build, please build it!"),
    )
}

#[allow(dead_code)]
pub fn gemini_3h_config<F: Fn() -> RuntimeGenesisConfig + 'static + Send + Sync>(
    constructor: F,
) -> GenericChainSpec<RuntimeGenesisConfig> {
    // TODO: Migrate once https://github.com/paritytech/polkadot-sdk/issues/2963 is un-broken
    #[allow(deprecated)]
    GenericChainSpec::from_genesis(
        // Name
        "Subspace Gemini 3h AutoId Domain",
        // ID
        "subspace_gemini_3h_auto_id_domain",
        ChainType::Live,
        constructor,
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("subspace-gemini-3h-auto-id-domain"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        None,
        // Code
        WASM_BINARY.expect("WASM binary was not build, please build it!"),
    )
}

pub fn devnet_config<F: Fn() -> RuntimeGenesisConfig + 'static + Send + Sync>(
    constructor: F,
) -> GenericChainSpec<RuntimeGenesisConfig> {
    // TODO: Migrate once https://github.com/paritytech/polkadot-sdk/issues/2963 is un-broken
    #[allow(deprecated)]
    GenericChainSpec::from_genesis(
        // Name
        "Subspace Devnet AutoId Domain",
        // ID
        "subspace_devnet_auto_id_domain",
        ChainType::Custom("Testnet".to_string()),
        constructor,
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("subspace-devnet-auto-id-domain"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        None,
        // Code
        WASM_BINARY.expect("WASM binary was not build, please build it!"),
    )
}

pub fn load_chain_spec(spec_id: &str) -> Result<Box<dyn sc_cli::ChainSpec>, String> {
    let chain_spec = match spec_id {
        "gemini-3h" => gemini_3h_config(move || get_testnet_genesis_by_spec_id(SpecId::Gemini)),
        "devnet" => devnet_config(move || get_testnet_genesis_by_spec_id(SpecId::DevNet)),
        "dev" => development_config(move || get_testnet_genesis_by_spec_id(SpecId::Dev)),
        path => GenericChainSpec::from_json_file(std::path::PathBuf::from(path))?,
    };
    Ok(Box::new(chain_spec))
}

pub fn get_testnet_genesis_by_spec_id(spec_id: SpecId) -> RuntimeGenesisConfig {
    match spec_id {
        SpecId::Dev => {
            let accounts = get_dev_accounts();
            testnet_genesis(
                // Alice is Sudo
                Some(accounts[0].clone()),
            )
        }
        SpecId::Gemini => testnet_genesis(None),
        SpecId::DevNet => testnet_genesis(None),
    }
}

pub fn get_testnet_endowed_accounts_by_spec_id(spec_id: SpecId) -> Vec<(MultiAccountId, Balance)> {
    match spec_id {
        SpecId::Dev => get_dev_accounts()
            .into_iter()
            .map(|acc| (AccountIdConverter::convert(acc), 1_000_000 * SSC))
            .collect(),
        SpecId::DevNet => {
            let accounts = get_dev_accounts();
            let alice_account = accounts[0].clone();
            vec![(AccountIdConverter::convert(alice_account), 1_000_000 * SSC)]
        }
        SpecId::Gemini => vec![],
    }
}

fn testnet_genesis(maybe_sudo_account: Option<AccountId32>) -> RuntimeGenesisConfig {
    RuntimeGenesisConfig {
        system: SystemConfig::default(),
        sudo: SudoConfig {
            key: maybe_sudo_account,
        },
        balances: BalancesConfig::default(),
        ..Default::default()
    }
}
