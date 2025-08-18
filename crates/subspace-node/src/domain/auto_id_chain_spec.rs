//! AutoId domain configurations.

use crate::chain_spec_utils::{
    chain_spec_properties, get_account_id_from_seed, get_public_key_from_seed,
};
use crate::domain::cli::{GenesisDomain, GenesisOperatorParams, SpecId};
use auto_id_domain_runtime::{BalancesConfig, RuntimeGenesisConfig, SystemConfig, WASM_BINARY};
use domain_runtime_primitives::{AccountIdConverter, MultiAccountId};
use hex_literal::hex;
use parity_scale_codec::Encode;
use sc_chain_spec::GenericChainSpec;
use sc_service::ChainType;
use sp_core::crypto::{AccountId32, UncheckedFrom};
use sp_domains::storage::RawGenesis;
use sp_domains::{DomainRuntimeInfo, OperatorAllowList, OperatorPublicKey, RuntimeType};
use sp_runtime::BuildStorage;
use sp_runtime::traits::Convert;
use subspace_runtime_primitives::{AI3, Balance};

/// Development keys that will be injected automatically on polkadotjs apps
fn get_dev_accounts() -> Vec<AccountId32> {
    vec![
        get_account_id_from_seed("Alice"),
        get_account_id_from_seed("Bob"),
        get_account_id_from_seed("Alice//stash"),
        get_account_id_from_seed("Bob//stash"),
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
    .with_id("auto_id_domain_dev")
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
    .with_name("Autonomys Chronos AutoId Domain")
    .with_id("autonomys_chronos_auto_id_domain")
    .with_chain_type(ChainType::Live)
    .with_genesis_config(
        serde_json::to_value(runtime_genesis_config)
            .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
    )
    .with_protocol_id("autonomys-chronos-auto-id-domain")
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
    .with_name("Autonomys AutoId Domain")
    .with_id("autonomys_auto_id_domain")
    .with_chain_type(ChainType::Live)
    .with_genesis_config(
        serde_json::to_value(runtime_genesis_config)
            .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
    )
    .with_protocol_id("autonomys-auto-id-domain")
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
    .with_name("Subspace Devnet AutoId Domain")
    .with_id("subspace_devnet_auto_id_domain")
    .with_chain_type(ChainType::Custom("Devnet".to_string()))
    .with_genesis_config(
        serde_json::to_value(runtime_genesis_config)
            .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
    )
    .with_protocol_id("subspace-devnet-auto-id-domain")
    .with_properties(chain_spec_properties())
    .build())
}

pub fn load_chain_spec(spec_id: &str) -> Result<Box<dyn sc_cli::ChainSpec>, String> {
    let chain_spec = match spec_id {
        "chronos" => chronos_config(get_genesis_by_spec_id(SpecId::Chronos))?,
        "devnet" => devnet_config(get_genesis_by_spec_id(SpecId::DevNet))?,
        "dev" => development_config(get_genesis_by_spec_id(SpecId::Dev))?,
        "mainnet" => mainnet_config(get_genesis_by_spec_id(SpecId::Mainnet))?,
        path => GenericChainSpec::from_json_file(std::path::PathBuf::from(path))?,
    };
    Ok(Box::new(chain_spec))
}

pub fn get_genesis_by_spec_id(_: SpecId) -> RuntimeGenesisConfig {
    empty_genesis()
}

pub fn get_endowed_accounts_by_spec_id(spec_id: SpecId) -> Vec<(MultiAccountId, Balance)> {
    match spec_id {
        SpecId::Dev => get_dev_accounts()
            .into_iter()
            .map(|acc| (AccountIdConverter::convert(acc), 1_000_000 * AI3))
            .collect(),
        SpecId::DevNet => {
            let accounts = get_dev_accounts();
            let alice_account = accounts[0].clone();
            vec![(AccountIdConverter::convert(alice_account), 1_000_000 * AI3)]
        }
        SpecId::Chronos | SpecId::Mainnet => vec![],
    }
}

fn empty_genesis() -> RuntimeGenesisConfig {
    RuntimeGenesisConfig {
        system: SystemConfig::default(),
        balances: BalancesConfig::default(),
        ..Default::default()
    }
}

fn get_operator_params(spec_id: SpecId) -> GenesisOperatorParams {
    match spec_id {
        SpecId::Dev => GenesisOperatorParams {
            operator_allow_list: OperatorAllowList::Anyone,
            operator_signing_key: get_public_key_from_seed::<OperatorPublicKey>("Alice"),
        },
        SpecId::DevNet => GenesisOperatorParams {
            operator_allow_list: OperatorAllowList::Anyone,
            operator_signing_key: OperatorPublicKey::unchecked_from(hex!(
                "18df97b9335e11f239f8f3f8041819d42f27b60845cf209416fdba8de15f4b7c"
            )),
        },
        // mainnet/chronos should never be called for genesis domain instantiation since
        // actual consensus mainnet/chronos testnet has no genesis domains.
        SpecId::Mainnet | SpecId::Chronos => {
            panic!("mainnet/chronos domains does not have any operator parameters")
        }
    }
}

/// Returns AutoId genesis domain.
/// Note: Currently unused since dev or devnet uses EVM domain and not AutoId
#[expect(dead_code)]
pub fn get_genesis_domain(spec_id: SpecId) -> Result<GenesisDomain, String> {
    let chain_spec = match spec_id {
        SpecId::Dev => development_config(get_genesis_by_spec_id(spec_id))?,
        SpecId::Chronos => chronos_config(get_genesis_by_spec_id(spec_id))?,
        SpecId::DevNet => devnet_config(get_genesis_by_spec_id(spec_id))?,
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
        runtime_name: "auto-id".to_string(),
        runtime_type: RuntimeType::AutoId,
        runtime_version: auto_id_domain_runtime::VERSION,
        domain_name: "auto-id".to_string(),
        initial_balances: get_endowed_accounts_by_spec_id(spec_id),
        operator_allow_list,
        operator_signing_key,
        domain_runtime_info: DomainRuntimeInfo::AutoId {
            domain_runtime_config: Default::default(),
        },
    })
}
