use evm_domain_runtime::{AccountId as AccountId20, EVMChainIdConfig, EVMConfig, Precompiles};
use hex_literal::hex;
use parity_scale_codec::Encode;
use sc_service::{ChainSpec, ChainType, NoExtension};
use sc_subspace_chain_specs::{ConsensusChainSpec, ExecutionChainSpec};
use sp_core::crypto::AccountId32;
use sp_core::{sr25519, Pair, Public};
use sp_domains::storage::RawGenesis;
use sp_domains::{OperatorAllowList, OperatorPublicKey, RuntimeType};
use sp_runtime::traits::IdentifyAccount;
use sp_runtime::{BuildStorage, MultiSigner, Percent};
use std::marker::PhantomData;
use std::num::NonZeroU32;
use subspace_runtime::{
    AllowAuthoringBy, DomainsConfig, EnableRewardsAt, MaxDomainBlockSize, MaxDomainBlockWeight,
    RuntimeConfigsConfig, SubspaceConfig, VestingConfig,
};
use subspace_runtime_primitives::{AccountId, Balance, BlockNumber, SSC};

pub fn domain_dev_config() -> ExecutionChainSpec<evm_domain_runtime::RuntimeGenesisConfig> {
    let endowed_accounts = [
        // Alith key
        AccountId20::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")),
        // Baltathar key
        AccountId20::from(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0")),
        // Charleth key
        AccountId20::from(hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc")),
        // Dorothy
        AccountId20::from(hex!("773539d4Ac0e786233D90A233654ccEE26a613D9")),
    ];
    let sudo_account = endowed_accounts[0];

    ExecutionChainSpec::from_genesis(
        // Name
        "Development",
        // ID
        "evm_domain_dev",
        ChainType::Development,
        move || {
            // This is the simplest bytecode to revert without returning any data.
            // We will pre-deploy it under all of our precompiles to ensure they can be called from
            // within contracts.
            // (PUSH1 0x00 PUSH1 0x00 REVERT)
            let revert_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xFD];

            evm_domain_runtime::RuntimeGenesisConfig {
                system: evm_domain_runtime::SystemConfig::default(),
                sudo: evm_domain_runtime::SudoConfig {
                    key: Some(sudo_account),
                },
                balances: evm_domain_runtime::BalancesConfig {
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
        },
        vec![],
        None,
        None,
        None,
        None,
        None,
        evm_domain_runtime::WASM_BINARY.expect("WASM binary was not build, please build it!"),
    )
}

pub fn create_domain_spec(
    chain_id: &str,
    raw_genesis: RawGenesis,
) -> Result<Box<dyn sc_cli::ChainSpec>, String> {
    let mut chain_spec = match chain_id {
        "dev" => domain_dev_config(),
        path => ExecutionChainSpec::<evm_domain_runtime::RuntimeGenesisConfig>::from_json_file(
            std::path::PathBuf::from(path),
        )?,
    };
    chain_spec.set_storage(raw_genesis.into_storage());
    Ok(Box::new(chain_spec))
}

pub fn load_domain_chain_spec(spec_id: &str) -> Result<Box<dyn sc_cli::ChainSpec>, String> {
    let chain_spec = match spec_id {
        "dev" => domain_dev_config(),
        path => ExecutionChainSpec::<evm_domain_runtime::RuntimeGenesisConfig>::from_json_file(
            std::path::PathBuf::from(path),
        )?,
    };
    Ok(Box::new(chain_spec))
}

/// Get public key from keypair seed.
fn get_public_key_from_seed<TPublic: Public>(
    seed: &'static str,
) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{seed}"), None)
        .expect("Static values are valid; qed")
        .public()
}

/// Generate an account ID from seed.
fn get_account_id_from_seed(seed: &'static str) -> AccountId32 {
    MultiSigner::from(get_public_key_from_seed::<sr25519::Public>(seed)).into_account()
}

/// Additional subspace specific genesis parameters.
struct GenesisParams {
    enable_rewards_at: EnableRewardsAt<BlockNumber>,
    enable_storage_access: bool,
    allow_authoring_by: AllowAuthoringBy,
    pot_slot_iterations: NonZeroU32,
    enable_domains: bool,
    enable_balance_transfers: bool,
    confirmation_depth_k: u32,
}

struct GenesisDomainParams {
    domain_name: String,
    operator_allow_list: OperatorAllowList<AccountId>,
    operator_signing_key: OperatorPublicKey,
    raw_genesis_storage: Vec<u8>,
}

pub fn dev_config() -> Result<ConsensusChainSpec<subspace_runtime::RuntimeGenesisConfig>, String> {
    let wasm_binary = subspace_runtime::WASM_BINARY
        .ok_or_else(|| "Development wasm not available".to_string())?;

    let raw_genesis_storage = {
        let domain_genesis_config = domain_dev_config();
        let storage = domain_genesis_config
            .build_storage()
            .expect("Failed to build genesis storage from genesis runtime config");
        let raw_genesis = RawGenesis::from_storage(storage);
        raw_genesis.encode()
    };

    Ok(ConsensusChainSpec::from_genesis(
        // Name
        "Subspace development",
        // ID
        "subspace_dev",
        ChainType::Development,
        move || {
            subspace_genesis_config(
                // Sudo account
                get_account_id_from_seed("Alice"),
                // Pre-funded accounts
                vec![
                    (get_account_id_from_seed("Alice"), Balance::MAX / 2),
                    (get_account_id_from_seed("Bob"), 1_000 * SSC),
                    (get_account_id_from_seed("Alice//stash"), 1_000 * SSC),
                    (get_account_id_from_seed("Bob//stash"), 1_000 * SSC),
                ],
                vec![],
                GenesisParams {
                    enable_rewards_at: EnableRewardsAt::Manually,
                    enable_storage_access: true,
                    allow_authoring_by: AllowAuthoringBy::Anyone,
                    pot_slot_iterations: NonZeroU32::new(100_000_000).expect("Not zero; qed"),
                    enable_domains: true,
                    enable_balance_transfers: true,
                    confirmation_depth_k: 5,
                },
                GenesisDomainParams {
                    domain_name: "evm-domain".to_owned(),
                    operator_allow_list: OperatorAllowList::Anyone,
                    operator_signing_key: get_public_key_from_seed::<OperatorPublicKey>("Alice"),
                    raw_genesis_storage: raw_genesis_storage.clone(),
                },
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        None,
        None,
        // Properties
        None,
        // Extensions
        NoExtension::None,
        // Code
        wasm_binary,
    ))
}

/// Configure initial storage state for FRAME modules.
fn subspace_genesis_config(
    sudo_account: AccountId,
    balances: Vec<(AccountId, Balance)>,
    // who, start, period, period_count, per_period
    vesting: Vec<(AccountId, BlockNumber, BlockNumber, u32, Balance)>,
    genesis_params: GenesisParams,
    genesis_domain_params: GenesisDomainParams,
) -> subspace_runtime::RuntimeGenesisConfig {
    let GenesisParams {
        enable_rewards_at,
        enable_storage_access,
        allow_authoring_by,
        pot_slot_iterations,
        enable_domains,
        enable_balance_transfers,
        confirmation_depth_k,
    } = genesis_params;

    subspace_runtime::RuntimeGenesisConfig {
        system: subspace_runtime::SystemConfig::default(),
        balances: subspace_runtime::BalancesConfig { balances },
        transaction_payment: Default::default(),
        sudo: subspace_runtime::SudoConfig {
            // Assign network admin rights.
            key: Some(sudo_account.clone()),
        },
        subspace: SubspaceConfig {
            enable_rewards_at,
            enable_storage_access,
            allow_authoring_by,
            pot_slot_iterations,
            phantom: PhantomData,
        },
        vesting: VestingConfig { vesting },
        runtime_configs: RuntimeConfigsConfig {
            enable_domains,
            enable_balance_transfers,
            confirmation_depth_k,
        },
        domains: DomainsConfig {
            genesis_domain: Some(sp_domains::GenesisDomain {
                runtime_name: "evm".to_owned(),
                runtime_type: RuntimeType::Evm,
                runtime_version: evm_domain_runtime::VERSION,
                raw_genesis_storage: genesis_domain_params.raw_genesis_storage,

                // Domain config, mainly for placeholder the concrete value TBD
                owner_account_id: sudo_account,
                domain_name: genesis_domain_params.domain_name,
                max_block_size: MaxDomainBlockSize::get(),
                max_block_weight: MaxDomainBlockWeight::get(),
                bundle_slot_probability: (1, 1),
                target_bundles_per_block: 10,
                operator_allow_list: genesis_domain_params.operator_allow_list,
                signing_key: genesis_domain_params.operator_signing_key,
                nomination_tax: Percent::from_percent(5),
                minimum_nominator_stake: 100 * SSC,
            }),
        },
    }
}
