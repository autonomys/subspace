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

//! EVM domain configurations.

use crate::chain_spec_utils::chain_spec_properties;
use evm_domain_runtime::{
    AccountId, BalancesConfig, EVMChainIdConfig, EVMConfig, Precompiles, RuntimeGenesisConfig,
    SudoConfig, SystemConfig, WASM_BINARY,
};
use hex_literal::hex;
use sc_service::ChainType;
use sc_subspace_chain_specs::ExecutionChainSpec;
use std::str::FromStr;
use subspace_runtime_primitives::SSC;

pub type ChainSpec = ExecutionChainSpec<RuntimeGenesisConfig>;

/// Development keys that will be injected automatically on polkadotjs apps
fn get_dev_accounts() -> Vec<AccountId> {
    vec![
        // Alith key
        AccountId::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")),
        // Baltathar key
        AccountId::from(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0")),
        // Charleth key
        AccountId::from(hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc")),
        // Dorothy
        AccountId::from(hex!("773539d4Ac0e786233D90A233654ccEE26a613D9")),
    ]
}

pub fn development_config<F: Fn() -> RuntimeGenesisConfig + 'static + Send + Sync>(
    constructor: F,
) -> ExecutionChainSpec<RuntimeGenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Development",
        // ID
        "evm_domain_dev",
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

pub fn gemini_3g_config<F: Fn() -> RuntimeGenesisConfig + 'static + Send + Sync>(
    constructor: F,
) -> ExecutionChainSpec<RuntimeGenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Subspace Gemini 3g EVM Domain",
        // ID
        "subspace_gemini_3g_evm_domain",
        ChainType::Live,
        constructor,
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("subspace-gemini-3g-evm-domain"),
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
) -> ExecutionChainSpec<RuntimeGenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Subspace Devnet EVM Domain",
        // ID
        "subspace_devnet_evm_domain",
        ChainType::Custom("Testnet".to_string()),
        constructor,
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("subspace-devnet-evm-domain"),
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
        "gemini-3g" => gemini_3g_config(move || get_testnet_genesis_by_spec_id(SpecId::Gemini)),
        "devnet" => devnet_config(move || get_testnet_genesis_by_spec_id(SpecId::DevNet)),
        "dev" => development_config(move || get_testnet_genesis_by_spec_id(SpecId::Dev)),
        path => ChainSpec::from_json_file(std::path::PathBuf::from(path))?,
    };
    Ok(Box::new(chain_spec))
}

#[derive(Debug, Copy, Clone)]
pub enum SpecId {
    Dev,
    Gemini,
    DevNet,
}

pub fn get_testnet_genesis_by_spec_id(spec_id: SpecId) -> RuntimeGenesisConfig {
    match spec_id {
        SpecId::Dev => {
            let accounts = get_dev_accounts();
            testnet_genesis(
                accounts.clone(),
                // Alith is Sudo
                Some(accounts[0]),
            )
        }
        SpecId::Gemini => {
            let sudo_account = AccountId::from_str("f31e60022e290708c17d6997c34de6a30d09438f")
                .expect("Invalid Sudo account");
            testnet_genesis(
                vec![
                    // Sudo account
                    sudo_account,
                ],
                Some(sudo_account),
            )
        }
        SpecId::DevNet => {
            let sudo_account = AccountId::from_str("b66a91845249464309fad766fd0ece8144547736")
                .expect("Invalid Sudo account");
            testnet_genesis(
                vec![
                    // Sudo account
                    sudo_account,
                ],
                Some(sudo_account),
            )
        }
    }
}

fn testnet_genesis(
    endowed_accounts: Vec<AccountId>,
    maybe_sudo_account: Option<AccountId>,
) -> RuntimeGenesisConfig {
    // This is the simplest bytecode to revert without returning any data.
    // We will pre-deploy it under all of our precompiles to ensure they can be called from
    // within contracts.
    // (PUSH1 0x00 PUSH1 0x00 REVERT)
    let revert_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xFD];

    RuntimeGenesisConfig {
        system: SystemConfig::default(),
        sudo: SudoConfig {
            key: maybe_sudo_account,
        },
        balances: BalancesConfig {
            // TODO: remove `endowed_accounts` once XDM is ready
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 1_000_000 * SSC))
                .collect(),
        },
        // this is set to default and chain_id will be set into genesis during the domain
        // instantiation on Consensus runtime.
        evm_chain_id: EVMChainIdConfig::default(),
        evm: EVMConfig {
            // We need _some_ code inserted at the precompile address so that
            // the evm will actually call the address.
            accounts: Precompiles::used_addresses()
                .into_iter()
                .map(|addr| {
                    (
                        addr,
                        fp_evm::GenesisAccount {
                            nonce: Default::default(),
                            balance: Default::default(),
                            storage: Default::default(),
                            code: revert_bytecode.clone(),
                        },
                    )
                })
                .collect(),
            ..Default::default()
        },
        ..Default::default()
    }
}
