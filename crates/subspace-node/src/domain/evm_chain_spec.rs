//! EVM domain configurations.

use crate::chain_spec_utils::{chain_spec_properties, get_public_key_from_seed};
use crate::domain::cli::{GenesisDomain, GenesisOperatorParams, SpecId};
use domain_runtime_primitives::{AccountId20Converter, MultiAccountId};
use evm_domain_runtime::{
    AccountId, BalancesConfig, EVMChainIdConfig, EVMConfig, Precompiles, RuntimeGenesisConfig,
    SystemConfig, WASM_BINARY,
};
use hex_literal::hex;
use parity_scale_codec::Encode;
use sc_chain_spec::GenericChainSpec;
use sc_service::ChainType;
use sp_core::crypto::UncheckedFrom;
use sp_domains::storage::RawGenesis;
use sp_domains::{
    EvmDomainRuntimeConfig, EvmType, OperatorAllowList, OperatorPublicKey, RuntimeType,
};
use sp_runtime::BuildStorage;
use sp_runtime::traits::Convert;
use subspace_runtime_primitives::{AI3, Balance};

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
) -> Result<GenericChainSpec, String> {
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

pub fn chronos_config(
    runtime_genesis_config: RuntimeGenesisConfig,
) -> Result<GenericChainSpec, String> {
    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "WASM binary was not build, please build it!".to_string())?,
        None,
    )
    .with_name("Autonomys Chronos EVM Domain")
    .with_id("autonomys_chronos_evm_domain")
    .with_chain_type(ChainType::Live)
    .with_genesis_config(
        serde_json::to_value(runtime_genesis_config)
            .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
    )
    .with_protocol_id("autonomys-chronos-evm-domain")
    .with_properties(chain_spec_properties())
    .build())
}

pub fn mainnet_config(
    runtime_genesis_config: RuntimeGenesisConfig,
) -> Result<GenericChainSpec, String> {
    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "WASM binary was not build, please build it!".to_string())?,
        None,
    )
    .with_name("Autonomys EVM Domain")
    .with_id("autonomys_evm_domain")
    .with_chain_type(ChainType::Live)
    .with_genesis_config(
        serde_json::to_value(runtime_genesis_config)
            .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
    )
    .with_protocol_id("autonomys-evm-domain")
    .with_properties(chain_spec_properties())
    .build())
}

pub fn devnet_config(
    runtime_genesis_config: RuntimeGenesisConfig,
) -> Result<GenericChainSpec, String> {
    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "WASM binary was not build, please build it!".to_string())?,
        None,
    )
    .with_name("Subspace Devnet EVM Domain")
    .with_id("subspace_devnet_evm_domain")
    .with_chain_type(ChainType::Custom("Devnet".to_string()))
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
        "chronos" => chronos_config(get_testnet_genesis_by_spec_id(SpecId::Chronos))?,
        "devnet" => devnet_config(get_testnet_genesis_by_spec_id(SpecId::DevNet))?,
        "dev" => development_config(get_testnet_genesis_by_spec_id(SpecId::Dev))?,
        "mainnet" => mainnet_config(get_testnet_genesis_by_spec_id(SpecId::Mainnet))?,
        path => GenericChainSpec::from_json_file(std::path::PathBuf::from(path))?,
    };
    Ok(Box::new(chain_spec))
}

pub fn get_testnet_genesis_by_spec_id(_: SpecId) -> RuntimeGenesisConfig {
    empty_genesis()
}

pub fn get_testnet_endowed_accounts_by_spec_id(spec_id: SpecId) -> Vec<(MultiAccountId, Balance)> {
    match spec_id {
        SpecId::Dev => get_dev_accounts()
            .into_iter()
            .map(|acc| (AccountId20Converter::convert(acc), 1_000_000 * AI3))
            .collect(),
        SpecId::DevNet | SpecId::Chronos | SpecId::Mainnet => vec![],
    }
}

fn empty_genesis() -> RuntimeGenesisConfig {
    // This is the simplest bytecode to revert without returning any data.
    // We will pre-deploy it under all of our precompiles to ensure they can be called from
    // within contracts.
    // (PUSH1 0x00 PUSH1 0x00 REVERT)
    let revert_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xFD];

    RuntimeGenesisConfig {
        system: SystemConfig::default(),
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

fn get_operator_params(spec_id: SpecId) -> GenesisOperatorParams {
    match spec_id {
        SpecId::Dev => GenesisOperatorParams {
            operator_allow_list: OperatorAllowList::Anyone,
            operator_signing_key: get_public_key_from_seed::<OperatorPublicKey>("Bob"),
        },
        SpecId::DevNet => GenesisOperatorParams {
            operator_allow_list: OperatorAllowList::Anyone,
            operator_signing_key: OperatorPublicKey::unchecked_from(hex!(
                "701184b4a34873117e075768adfbff7ce798f89108203e211d7d4b5ad8164e20"
            )),
        },
        // mainnet/chronos should never be called for genesis domain instantiation since
        // actual consensus mainnet/chronos has no genesis domains.
        SpecId::Mainnet | SpecId::Chronos => {
            panic!("mainnet/chronos domains does not have any operator parameters")
        }
    }
}

pub fn get_genesis_domain(spec_id: SpecId, evm_type: EvmType) -> Result<GenesisDomain, String> {
    let chain_spec = match spec_id {
        SpecId::Dev => development_config(get_testnet_genesis_by_spec_id(spec_id))?,
        SpecId::Chronos => chronos_config(get_testnet_genesis_by_spec_id(spec_id))?,
        SpecId::DevNet => devnet_config(get_testnet_genesis_by_spec_id(spec_id))?,
        SpecId::Mainnet => return Err("No genesis domain available for mainnet spec.".to_string()),
    };

    let GenesisOperatorParams {
        operator_allow_list,
        operator_signing_key,
    } = get_operator_params(spec_id);

    let storage = chain_spec
        .build_storage()
        .expect("Failed to build genesis storage from genesis runtime config");
    let raw_genesis = RawGenesis::from_storage(storage);
    Ok(GenesisDomain {
        raw_genesis: raw_genesis.encode(),
        runtime_name: "evm".to_string(),
        runtime_type: RuntimeType::Evm,
        runtime_version: evm_domain_runtime::VERSION,
        domain_name: "nova".to_string(),
        initial_balances: get_testnet_endowed_accounts_by_spec_id(spec_id),
        operator_allow_list,
        operator_signing_key,
        domain_runtime_config: EvmDomainRuntimeConfig { evm_type }.into(),
    })
}
