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
use domain_runtime_primitives::{AccountId20Converter, MultiAccountId};
use evm_domain_runtime::{
    AccountId, BalancesConfig, EVMChainIdConfig, EVMConfig, Precompiles, RuntimeGenesisConfig,
    SudoConfig, SystemConfig, WASM_BINARY,
};
use hex_literal::hex;
use sc_chain_spec::GenericChainSpec;
use sc_service::ChainType;
use sp_runtime::traits::Convert;
use subspace_runtime_primitives::{Balance, SSC};

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

pub fn development_config(
    runtime_genesis_config: RuntimeGenesisConfig,
) -> Result<GenericChainSpec<RuntimeGenesisConfig>, String> {
    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "WASM binary was not build, please build it!".to_string())?,
        None,
    )
    .with_name("Development")
    .with_id("evm_domain_dev")
    .with_chain_type(ChainType::Development)
    .with_genesis_config(
        serde_json::to_value(runtime_genesis_config)
            .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
    )
    .with_properties(chain_spec_properties())
    .build())
}

pub fn gemini_3h_config(
    runtime_genesis_config: RuntimeGenesisConfig,
) -> Result<GenericChainSpec<RuntimeGenesisConfig>, String> {
    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "WASM binary was not build, please build it!".to_string())?,
        None,
    )
    .with_name("Subspace Gemini 3h EVM Domain")
    .with_id("subspace_gemini_3h_evm_domain")
    .with_chain_type(ChainType::Live)
    .with_genesis_config(
        serde_json::to_value(runtime_genesis_config)
            .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
    )
    .with_protocol_id("subspace-gemini-3h-evm-domain")
    .with_properties(chain_spec_properties())
    .build())
}

pub fn devnet_config(
    runtime_genesis_config: RuntimeGenesisConfig,
) -> Result<GenericChainSpec<RuntimeGenesisConfig>, String> {
    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "WASM binary was not build, please build it!".to_string())?,
        None,
    )
    .with_name("Subspace Devnet EVM Domain")
    .with_id("subspace_devnet_evm_domain")
    .with_chain_type(ChainType::Custom("Testnet".to_string()))
    .with_genesis_config(
        serde_json::to_value(runtime_genesis_config)
            .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
    )
    .with_protocol_id("subspace-devnet-evm-domain")
    .with_properties(chain_spec_properties())
    .build())
}

pub fn load_chain_spec(spec_id: &str) -> Result<Box<dyn sc_cli::ChainSpec>, String> {
    let chain_spec = match spec_id {
        "gemini-3h" => gemini_3h_config(get_testnet_genesis_by_spec_id(SpecId::Gemini))?,
        "devnet" => devnet_config(get_testnet_genesis_by_spec_id(SpecId::DevNet))?,
        "dev" => development_config(get_testnet_genesis_by_spec_id(SpecId::Dev))?,
        path => GenericChainSpec::from_json_file(std::path::PathBuf::from(path))?,
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
                // Alith is Sudo
                Some(accounts[0]),
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
            .map(|acc| (AccountId20Converter::convert(acc), 1_000_000 * SSC))
            .collect(),
        SpecId::DevNet | SpecId::Gemini => vec![],
    }
}

fn testnet_genesis(maybe_sudo_account: Option<AccountId>) -> RuntimeGenesisConfig {
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
        balances: BalancesConfig::default(),
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
