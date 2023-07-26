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
use crate::domain::AccountId32ToAccountId20Converter;
use evm_domain_runtime::{
    AccountId, BalancesConfig, EVMChainIdConfig, EVMConfig, GenesisConfig, MessengerConfig,
    Precompiles, SelfDomainIdConfig, SudoConfig, SystemConfig, WASM_BINARY,
};
use hex_literal::hex;
use once_cell::sync::OnceCell;
use sc_service::ChainType;
use sc_subspace_chain_specs::ExecutionChainSpec;
use sp_core::{sr25519, Pair, Public};
use sp_domains::{DomainId, DomainInstanceData, RuntimeType};
use sp_runtime::traits::Convert;
use std::str::FromStr;
use subspace_runtime_primitives::SSC;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

pub type ChainSpec = ExecutionChainSpec<GenesisConfig>;

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

pub fn development_config<F: Fn() -> GenesisConfig + 'static + Send + Sync>(
    constructor: F,
) -> ExecutionChainSpec<GenesisConfig> {
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
    )
}

pub fn local_testnet_config<F: Fn() -> GenesisConfig + 'static + Send + Sync>(
    constructor: F,
) -> ExecutionChainSpec<GenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Local Testnet",
        // ID
        "evm_domain_local_testnet",
        ChainType::Local,
        constructor,
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("evm-local"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        None,
    )
}

pub fn gemini_3e_config<F: Fn() -> GenesisConfig + 'static + Send + Sync>(
    constructor: F,
) -> ExecutionChainSpec<GenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Subspace Gemini 3e EVM Domain",
        // ID
        "subspace_gemini_3e_evm_domain",
        ChainType::Live,
        constructor,
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("subspace-gemini-3e-evm-domain"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        None,
    )
}

pub fn devnet_config<F: Fn() -> GenesisConfig + 'static + Send + Sync>(
    constructor: F,
) -> ExecutionChainSpec<GenesisConfig> {
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
    )
}

pub fn load_chain_spec(spec_id: &str) -> Result<Box<dyn sc_cli::ChainSpec>, String> {
    let chain_spec = match spec_id {
        "dev" => development_config(move || get_testnet_genesis_by_spec_id(SpecId::Dev)),
        "gemini-3e" => gemini_3e_config(move || get_testnet_genesis_by_spec_id(SpecId::Gemini)),
        "devnet" => devnet_config(move || get_testnet_genesis_by_spec_id(SpecId::DevNet)),
        "" | "local" => local_testnet_config(move || get_testnet_genesis_by_spec_id(SpecId::Local)),
        path => ChainSpec::from_json_file(std::path::PathBuf::from(path))?,
    };
    Ok(Box::new(chain_spec))
}

pub enum SpecId {
    Dev,
    Gemini,
    DevNet,
    Local,
}

pub fn get_testnet_genesis_by_spec_id(spec_id: SpecId) -> GenesisConfig {
    let accounts = get_dev_accounts();
    match spec_id {
        SpecId::Dev => {
            testnet_genesis(
                accounts.clone(),
                // Alith is Sudo
                Some(accounts[0]),
                vec![(
                    accounts[0],
                    AccountId32ToAccountId20Converter::convert(
                        get_from_seed::<sr25519::Public>("Alice").into(),
                    ),
                )],
                1000,
            )
        }
        SpecId::Gemini => {
            let sudo_account = AccountId::from_str("f31e60022e290708c17d6997c34de6a30d09438f")
                .expect("Invalid Sudo account");
            testnet_genesis(
                vec![
                    // Genesis operator
                    AccountId::from_str("2ac6c70c106138c8cd80da6b6a0e886b7eeee249")
                        .expect("Wrong executor account address"),
                    // Sudo account
                    sudo_account,
                ],
                Some(sudo_account),
                Default::default(),
                1002,
            )
        }
        SpecId::DevNet => {
            let sudo_account = AccountId::from_str("b66a91845249464309fad766fd0ece8144547736")
                .expect("Invalid Sudo account");
            testnet_genesis(
                vec![
                    // Genesis operator
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
                1003,
            )
        }
        SpecId::Local => {
            testnet_genesis(
                accounts.clone(),
                // Alith is sudo
                Some(accounts[0]),
                vec![(accounts[0], accounts[0]), (accounts[1], accounts[1])],
                1001,
            )
        }
    }
}

// HACK: `ChainSpec::from_genesis` is only allow to create hardcoded spec and `GenesisConfig`
// dosen't derive `Clone`, using global variable and serialization/deserialization to workaround
// these limits.
static GENESIS_CONFIG: OnceCell<Vec<u8>> = OnceCell::new();

// Load chain spec that contains the given `GenesisConfig`
fn load_chain_spec_with(
    spec_id: &str,
    genesis_config: GenesisConfig,
) -> Result<Box<dyn sc_cli::ChainSpec>, String> {
    GENESIS_CONFIG
        .set(
            serde_json::to_vec(&genesis_config)
                .expect("Genesis config serialization never fails; qed"),
        )
        .expect("This function should only call once upon node initialization");
    let constructor = || {
        let raw_genesis_config = GENESIS_CONFIG.get().expect("Value just set; qed");
        serde_json::from_slice(raw_genesis_config)
            .expect("Genesis config deserialization never fails; qed")
    };

    let chain_spec = match spec_id {
        "dev" => development_config(constructor),
        "gemini-3e" => gemini_3e_config(constructor),
        "devnet" => devnet_config(constructor),
        "" | "local" => local_testnet_config(constructor),
        path => ChainSpec::from_json_file(std::path::PathBuf::from(path))?,
    };

    Ok(Box::new(chain_spec))
}

fn domain_instance_genesis_config(domain_id: DomainId, runtime_code: Vec<u8>) -> GenesisConfig {
    let mut cfg = GenesisConfig::default();
    cfg.system.code = runtime_code;
    cfg.self_domain_id.domain_id = Some(domain_id);
    cfg
}

pub fn create_domain_spec(
    domain_id: DomainId,
    chain_id: &str,
    domain_instance_data: DomainInstanceData,
) -> Result<Box<dyn sc_cli::ChainSpec>, String> {
    let DomainInstanceData {
        runtime_type,
        runtime_code,
    } = domain_instance_data;

    match runtime_type {
        RuntimeType::Evm => {
            let genesis_config = domain_instance_genesis_config(domain_id, runtime_code);
            let spec = load_chain_spec_with(chain_id, genesis_config)?;
            Ok(spec)
        }
    }
}

fn testnet_genesis(
    endowed_accounts: Vec<AccountId>,
    maybe_sudo_account: Option<AccountId>,
    relayers: Vec<(AccountId, AccountId)>,
    chain_id: u64,
) -> GenesisConfig {
    // This is the simplest bytecode to revert without returning any data.
    // We will pre-deploy it under all of our precompiles to ensure they can be called from
    // within contracts.
    // (PUSH1 0x00 PUSH1 0x00 REVERT)
    let revert_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xFD];

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
        },
        ethereum: Default::default(),
        base_fee: Default::default(),
        self_domain_id: SelfDomainIdConfig {
            // Id of the genesis domain
            domain_id: Some(DomainId::new(0)),
        },
    }
}
