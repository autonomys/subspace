//! Subspace chain configurations.

use crate::chain_spec_utils::{chain_spec_properties, get_account_id_from_seed};
use crate::domain::cli::{GenesisDomain, SpecId};
use crate::domain::evm_chain_spec::{self};
use sc_chain_spec::GenericChainSpec;
use sc_service::ChainType;
use sc_subspace_chain_specs::{DEVNET_CHAIN_SPEC, MAINNET_CHAIN_SPEC, TAURUS_CHAIN_SPEC};
use sc_telemetry::TelemetryEndpoints;
use serde::Deserialize;
use sp_core::crypto::Ss58Codec;
use sp_domains::{EvmType, PermissionedActionAllowedBy};
use sp_runtime::{BoundedVec, Percent};
use std::marker::PhantomData;
use std::num::{NonZeroU32, NonZeroU128};
use subspace_core_primitives::PublicKey;
use subspace_core_primitives::pot::PotKey;
use subspace_runtime::{
    AllowAuthoringBy, BalancesConfig, CouncilConfig, DemocracyConfig, DomainsConfig,
    EnableRewardsAt, RewardPoint, RewardsConfig, RuntimeConfigsConfig, RuntimeGenesisConfig,
    SubspaceConfig, SudoConfig, SystemConfig, WASM_BINARY,
};
use subspace_runtime_primitives::{
    AI3, AccountId, Balance, BlockNumber, CouncilDemocracyConfigParams, GenesisConfigParams,
};

const SUBSPACE_TELEMETRY_URL: &str = "wss://telemetry.subspace.foundation/submit/";

/// Additional subspace specific genesis parameters.
struct GenesisParams {
    enable_rewards_at: EnableRewardsAt<BlockNumber>,
    allow_authoring_by: AllowAuthoringBy,
    pot_slot_iterations: NonZeroU32,
    enable_domains: bool,
    enable_dynamic_cost_of_storage: bool,
    enable_balance_transfers: bool,
    confirmation_depth_k: u32,
    rewards_config: RewardsConfig,
    domain_block_pruning_depth: u32,
    staking_withdrawal_period: u32,
}

struct GenesisDomainParams {
    permissioned_action_allowed_by: PermissionedActionAllowedBy<AccountId>,
    genesis_domains: Vec<GenesisDomain>,
}

/// Genesis token balances allocations
const GENESIS_ALLOCATIONS: &str = include_str!("genesis_allocations.json");

#[derive(Deserialize)]
struct GenesisAllocation(AccountId, NonZeroU128);

fn get_genesis_allocations(contents: &str) -> Vec<(AccountId, Balance)> {
    let allocations: Vec<GenesisAllocation> =
        serde_json::from_str(contents).expect("Failed to parse genesis allocations JSON");

    allocations
        .into_iter()
        .map(|GenesisAllocation(account, balance)| (account, balance.get() * AI3))
        .collect()
}

pub fn mainnet_compiled() -> Result<GenericChainSpec, String> {
    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Wasm binary must be built for Mainnet".to_string())?,
        None,
    )
    .with_name("Autonomys Mainnet")
    // ID
    .with_id("autonomys_mainnet")
    // This is a Live chain, but we use Custom here to display the correct chain name across a
    // range of clients.
    .with_chain_type(ChainType::Custom("Autonomys Mainnet".to_string()))
    .with_telemetry_endpoints(
        TelemetryEndpoints::new(vec![(SUBSPACE_TELEMETRY_URL.into(), 1)])
            .map_err(|error| error.to_string())?,
    )
    .with_protocol_id("autonomys-mainnet")
    .with_properties({
        let mut properties = chain_spec_properties();
        properties.insert(
            "potExternalEntropy".to_string(),
            serde_json::to_value(None::<PotKey>).expect("Serialization is infallible; qed"),
        );
        properties
    })
    .with_genesis_config({
        let sudo_account =
            AccountId::from_ss58check("5EHHtxGtDEPFX2x2PCVg8uhhg6kDdt9znQLr2oqUA9sYL5n6")
                .expect("Wrong root account address");
        let council_members = [
            "5EhEcKAfGXzEkEqYdN9Ntc4f2KJrVvabWTUceCVtDPTYxVit",
            "5G9GUNK2Vp1jgpENPmcy9TLoprkmHBTSg9bgvMa8er5ZLYjb",
            "5CAtkaN1tDiaiuaYbxeDNNnix2WhAQxu5RobMFaiaStiCcTx",
            "5CJ8ezmRwcNJmutA92ZmRpaL8e6BCPSdfnt3e6kZZWLAVUZK",
            "5CiFrTxvxmehJ7okLdEc8z3cxvWfrMpShPJy9GKymRqEgF7T",
        ]
        .iter()
        .map(|address| {
            AccountId::from_ss58check(address)
                .map_err(|_| format!("Invalid council SS58 address: {address}"))
        })
        .collect::<Result<Vec<AccountId>, String>>()?;

        let council_config = CouncilConfig {
            phantom: PhantomData,
            members: council_members,
        };
        let balances = get_genesis_allocations(GENESIS_ALLOCATIONS);

        let GenesisConfigParams {
            confirmation_depth_k,
            domain_block_pruning_depth,
            staking_withdrawal_period,
        } = GenesisConfigParams::production_params();

        serde_json::to_value(subspace_genesis_config(
            sudo_account.clone(),
            balances,
            GenesisParams {
                enable_rewards_at: EnableRewardsAt::Manually,
                allow_authoring_by: AllowAuthoringBy::RootFarmer(PublicKey::from(
                    hex_literal::hex!(
                        "e6a489dab63b650cf475431fc46649f4256167443fea241fca0bb3f86b29837a"
                    ),
                )),
                // TODO: Adjust once we bench PoT on faster hardware
                // About 1s on 6.2 GHz Raptor Lake CPU (14900KS)
                pot_slot_iterations: NonZeroU32::new(206_557_520).expect("Not zero; qed"),
                enable_domains: false,
                enable_dynamic_cost_of_storage: false,
                enable_balance_transfers: false,
                confirmation_depth_k,
                rewards_config: RewardsConfig {
                    remaining_issuance: 350_000_000 * AI3,
                    proposer_subsidy_points: BoundedVec::try_from(vec![
                        RewardPoint {
                            block: 0,
                            subsidy: 454545454545455000,
                        },
                        RewardPoint {
                            block: 10512000,
                            subsidy: 423672207997007000,
                        },
                        RewardPoint {
                            block: 26280000,
                            subsidy: 333635878252228000,
                        },
                        RewardPoint {
                            block: 42048000,
                            subsidy: 262825353875519000,
                        },
                        RewardPoint {
                            block: 57816000,
                            subsidy: 207116053874914000,
                        },
                        RewardPoint {
                            block: 73584000,
                            subsidy: 163272262877830000,
                        },
                        RewardPoint {
                            block: 94608000,
                            subsidy: 118963574070561000,
                        },
                        RewardPoint {
                            block: 120888000,
                            subsidy: 80153245846642200,
                        },
                        RewardPoint {
                            block: 149796000,
                            subsidy: 51971522998131200,
                        },
                        RewardPoint {
                            block: 183960000,
                            subsidy: 31192714495359900,
                        },
                        RewardPoint {
                            block: 220752000,
                            subsidy: 18033114698427300,
                        },
                    ])
                    .expect("Number of elements is below configured MaxRewardPoints; qed"),
                    voter_subsidy_points: BoundedVec::try_from(vec![
                        RewardPoint {
                            block: 0,
                            subsidy: 454545454545455000,
                        },
                        RewardPoint {
                            block: 10512000,
                            subsidy: 423672207997007000,
                        },
                        RewardPoint {
                            block: 26280000,
                            subsidy: 333635878252228000,
                        },
                        RewardPoint {
                            block: 42048000,
                            subsidy: 262825353875519000,
                        },
                        RewardPoint {
                            block: 57816000,
                            subsidy: 207116053874914000,
                        },
                        RewardPoint {
                            block: 73584000,
                            subsidy: 163272262877830000,
                        },
                        RewardPoint {
                            block: 94608000,
                            subsidy: 118963574070561000,
                        },
                        RewardPoint {
                            block: 120888000,
                            subsidy: 80153245846642200,
                        },
                        RewardPoint {
                            block: 149796000,
                            subsidy: 51971522998131200,
                        },
                        RewardPoint {
                            block: 183960000,
                            subsidy: 31192714495359900,
                        },
                        RewardPoint {
                            block: 220752000,
                            subsidy: 18033114698427300,
                        },
                    ])
                    .expect("Number of elements is below configured MaxRewardPoints; qed"),
                },
                domain_block_pruning_depth,
                staking_withdrawal_period,
            },
            GenesisDomainParams {
                permissioned_action_allowed_by: PermissionedActionAllowedBy::Accounts(vec![
                    sudo_account.clone(),
                ]),
                genesis_domains: vec![],
            },
            CouncilDemocracyConfigParams::<BlockNumber>::production_params(),
            council_config,
        )?)
        .map_err(|error| format!("Failed to serialize genesis config: {error}"))?
    })
    .build())
}

pub fn mainnet_config() -> Result<GenericChainSpec, String> {
    GenericChainSpec::from_json_bytes(MAINNET_CHAIN_SPEC.as_bytes())
}

#[allow(dead_code)]
pub fn chronos_compiled() -> Result<GenericChainSpec, String> {
    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Wasm binary must be built for Chronos".to_string())?,
        None,
    )
    .with_name("Autonomys Chronos Testnet")
    // ID
    .with_id("autonomys_chronos")
    // This is a Live chain, but we use Custom here to display the correct chain name across a
    // range of clients.
    .with_chain_type(ChainType::Custom("Autonomys Chronos Testnet".to_string()))
    .with_telemetry_endpoints(
        TelemetryEndpoints::new(vec![(SUBSPACE_TELEMETRY_URL.into(), 1)])
            .map_err(|error| error.to_string())?,
    )
    .with_protocol_id("autonomys-chronos")
    .with_properties({
        let mut properties = chain_spec_properties();
        properties.insert(
            "potExternalEntropy".to_string(),
            serde_json::to_value(None::<PotKey>).expect("Serialization is infallible; qed"),
        );
        properties.insert("tokenSymbol".to_string(), "tAI3".into());
        properties
    })
    .with_genesis_config({
        let sudo_account =
            AccountId::from_ss58check("sucRSe7k7UnLBTk5hd1MKmaMFuQ19BCGFSdDPrpHfGXRsNCmv")
                .expect("Wrong root account address");
        let council_members = [
            "sudee2jQSuUzpGkpbNF2zzvGj4huUwtdRdpaccsqcC38DeaNj",
            "sufR5BiWoMnHJcx769i7YugyeHPrdZznKqVVuRY8kw4QUYzCq",
            "sufCbHYMJLZaquWSnEFMz8BEDKHo2u9v9WaPoYQrfUFA4fxHV",
        ]
        .iter()
        .map(|address| {
            AccountId::from_ss58check(address)
                .map_err(|_| format!("Invalid council SS58 address: {address}"))
        })
        .collect::<Result<Vec<AccountId>, String>>()?;

        let council_config = CouncilConfig {
            phantom: PhantomData,
            members: council_members.clone(),
        };

        let mut balances = council_members
            .into_iter()
            .map(|member| (member, 1000 * AI3))
            .collect::<Vec<(AccountId, Balance)>>();
        balances.push((sudo_account.clone(), 1000 * AI3));

        let GenesisConfigParams {
            confirmation_depth_k,
            domain_block_pruning_depth,
            staking_withdrawal_period,
        } = GenesisConfigParams::production_params();

        serde_json::to_value(subspace_genesis_config(
            sudo_account.clone(),
            balances,
            GenesisParams {
                enable_rewards_at: EnableRewardsAt::Manually,
                allow_authoring_by: AllowAuthoringBy::FirstFarmer,
                // TODO: Adjust once we bench PoT on faster hardware
                // About 1s on 6.2 GHz Raptor Lake CPU (14900KS)
                pot_slot_iterations: NonZeroU32::new(206_557_520).expect("Not zero; qed"),
                enable_domains: false,
                enable_dynamic_cost_of_storage: false,
                enable_balance_transfers: false,
                confirmation_depth_k,
                rewards_config: RewardsConfig {
                    remaining_issuance: 350_000_000 * AI3,
                    proposer_subsidy_points: BoundedVec::try_from(vec![
                        RewardPoint {
                            block: 0,
                            subsidy: 454545454545455000,
                        },
                        RewardPoint {
                            block: 10512000,
                            subsidy: 423672207997007000,
                        },
                        RewardPoint {
                            block: 26280000,
                            subsidy: 333635878252228000,
                        },
                        RewardPoint {
                            block: 42048000,
                            subsidy: 262825353875519000,
                        },
                        RewardPoint {
                            block: 57816000,
                            subsidy: 207116053874914000,
                        },
                        RewardPoint {
                            block: 73584000,
                            subsidy: 163272262877830000,
                        },
                        RewardPoint {
                            block: 94608000,
                            subsidy: 118963574070561000,
                        },
                        RewardPoint {
                            block: 120888000,
                            subsidy: 80153245846642200,
                        },
                        RewardPoint {
                            block: 149796000,
                            subsidy: 51971522998131200,
                        },
                        RewardPoint {
                            block: 183960000,
                            subsidy: 31192714495359900,
                        },
                        RewardPoint {
                            block: 220752000,
                            subsidy: 18033114698427300,
                        },
                    ])
                    .expect("Number of elements is below configured MaxRewardPoints; qed"),
                    voter_subsidy_points: BoundedVec::try_from(vec![
                        RewardPoint {
                            block: 0,
                            subsidy: 454545454545455000,
                        },
                        RewardPoint {
                            block: 10512000,
                            subsidy: 423672207997007000,
                        },
                        RewardPoint {
                            block: 26280000,
                            subsidy: 333635878252228000,
                        },
                        RewardPoint {
                            block: 42048000,
                            subsidy: 262825353875519000,
                        },
                        RewardPoint {
                            block: 57816000,
                            subsidy: 207116053874914000,
                        },
                        RewardPoint {
                            block: 73584000,
                            subsidy: 163272262877830000,
                        },
                        RewardPoint {
                            block: 94608000,
                            subsidy: 118963574070561000,
                        },
                        RewardPoint {
                            block: 120888000,
                            subsidy: 80153245846642200,
                        },
                        RewardPoint {
                            block: 149796000,
                            subsidy: 51971522998131200,
                        },
                        RewardPoint {
                            block: 183960000,
                            subsidy: 31192714495359900,
                        },
                        RewardPoint {
                            block: 220752000,
                            subsidy: 18033114698427300,
                        },
                    ])
                    .expect("Number of elements is below configured MaxRewardPoints; qed"),
                },
                domain_block_pruning_depth,
                staking_withdrawal_period,
            },
            GenesisDomainParams {
                permissioned_action_allowed_by: PermissionedActionAllowedBy::Accounts(vec![
                    sudo_account.clone(),
                ]),
                genesis_domains: vec![],
            },
            CouncilDemocracyConfigParams::<BlockNumber>::production_params(),
            council_config,
        )?)
        .map_err(|error| format!("Failed to serialize genesis config: {error}"))?
    })
    .build())
}

pub fn taurus_config() -> Result<GenericChainSpec, String> {
    GenericChainSpec::from_json_bytes(TAURUS_CHAIN_SPEC.as_bytes())
}

pub fn devnet_config() -> Result<GenericChainSpec, String> {
    GenericChainSpec::from_json_bytes(DEVNET_CHAIN_SPEC.as_bytes())
}

pub fn devnet_config_compiled() -> Result<GenericChainSpec, String> {
    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Wasm binary must be built for Devnet".to_string())?,
        None,
    )
    .with_name("Subspace Dev network")
    .with_id("subspace_devnet")
    .with_chain_type(ChainType::Custom("Testnet".to_string()))
    .with_telemetry_endpoints(
        TelemetryEndpoints::new(vec![(SUBSPACE_TELEMETRY_URL.into(), 1)])
            .map_err(|error| error.to_string())?,
    )
    .with_protocol_id("subspace-devnet")
    .with_properties({
        let mut properties = chain_spec_properties();
        properties.insert(
            "potExternalEntropy".to_string(),
            serde_json::to_value(None::<PotKey>).expect("Serialization is infallible; qed"),
        );
        properties
    })
    .with_genesis_config({
        let sudo_account = get_account_id_from_seed("Alice");

        let balances = vec![(sudo_account.clone(), Balance::MAX / 2)];
        let GenesisConfigParams {
            confirmation_depth_k,
            domain_block_pruning_depth,
            staking_withdrawal_period,
        } = GenesisConfigParams::dev_params();
        serde_json::to_value(subspace_genesis_config(
            sudo_account.clone(),
            balances,
            GenesisParams {
                enable_rewards_at: EnableRewardsAt::Manually,
                allow_authoring_by: AllowAuthoringBy::FirstFarmer,
                pot_slot_iterations: NonZeroU32::new(150_000_000).expect("Not zero; qed"),
                enable_domains: true,
                enable_dynamic_cost_of_storage: false,
                enable_balance_transfers: true,
                confirmation_depth_k,
                rewards_config: RewardsConfig {
                    remaining_issuance: 1_000_000_000 * AI3,
                    proposer_subsidy_points: Default::default(),
                    voter_subsidy_points: Default::default(),
                },
                domain_block_pruning_depth,
                staking_withdrawal_period,
            },
            GenesisDomainParams {
                permissioned_action_allowed_by: PermissionedActionAllowedBy::Accounts(vec![
                    sudo_account.clone(),
                ]),
                genesis_domains: vec![evm_chain_spec::get_genesis_domain(
                    SpecId::DevNet,
                    sudo_account.clone(),
                    EvmType::Public,
                )?],
            },
            CouncilDemocracyConfigParams::<BlockNumber>::fast_params(),
            CouncilConfig::default(),
        )?)
        .map_err(|error| format!("Failed to serialize genesis config: {error}"))?
    })
    .build())
}

pub fn dev_config() -> Result<GenericChainSpec, String> {
    let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;
    let sudo_account = get_account_id_from_seed("Alice");
    let GenesisConfigParams {
        confirmation_depth_k,
        domain_block_pruning_depth,
        staking_withdrawal_period,
    } = GenesisConfigParams::dev_params();

    Ok(GenericChainSpec::builder(wasm_binary, None)
        .with_name("Subspace development")
        .with_id("subspace_dev")
        .with_chain_type(ChainType::Development)
        .with_properties({
            let mut properties = chain_spec_properties();
            properties.insert(
                "potExternalEntropy".to_string(),
                serde_json::to_value(None::<PotKey>).expect("Serialization is infallible; qed"),
            );
            properties
        })
        .with_genesis_config(
            serde_json::to_value(subspace_genesis_config(
                // Sudo account
                sudo_account.clone(),
                // Pre-funded accounts
                vec![
                    (sudo_account.clone(), Balance::MAX / 2),
                    (get_account_id_from_seed("Bob"), 1_000 * AI3),
                    (get_account_id_from_seed("Alice//stash"), 1_000 * AI3),
                    (get_account_id_from_seed("Bob//stash"), 1_000 * AI3),
                ],
                GenesisParams {
                    enable_rewards_at: EnableRewardsAt::Manually,
                    allow_authoring_by: AllowAuthoringBy::Anyone,
                    pot_slot_iterations: NonZeroU32::new(100_000_000).expect("Not zero; qed"),
                    enable_domains: true,
                    enable_dynamic_cost_of_storage: false,
                    enable_balance_transfers: true,
                    confirmation_depth_k,
                    rewards_config: RewardsConfig {
                        remaining_issuance: 1_000_000 * AI3,
                        proposer_subsidy_points: Default::default(),
                        voter_subsidy_points: Default::default(),
                    },
                    domain_block_pruning_depth,
                    staking_withdrawal_period,
                },
                GenesisDomainParams {
                    permissioned_action_allowed_by: PermissionedActionAllowedBy::Accounts(vec![
                        sudo_account.clone(),
                    ]),
                    genesis_domains: vec![evm_chain_spec::get_genesis_domain(
                        SpecId::Dev,
                        sudo_account,
                        // TODO: in production configs, set this to Public, unless we specifically want a private EVM
                        EvmType::Private {
                            initial_contract_creation_allow_list:
                                PermissionedActionAllowedBy::Anyone,
                        },
                    )?],
                },
                CouncilDemocracyConfigParams::<BlockNumber>::fast_params(),
                CouncilConfig::default(),
            )?)
            .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
        )
        .build())
}

/// Configure initial storage state for FRAME modules.
fn subspace_genesis_config(
    sudo_account: AccountId,
    balances: Vec<(AccountId, Balance)>,
    genesis_params: GenesisParams,
    genesis_domain_params: GenesisDomainParams,
    council_democracy_config_params: CouncilDemocracyConfigParams<BlockNumber>,
    council_config: CouncilConfig,
) -> Result<RuntimeGenesisConfig, String> {
    let GenesisParams {
        enable_rewards_at,
        allow_authoring_by,
        pot_slot_iterations,
        enable_domains,
        enable_dynamic_cost_of_storage,
        enable_balance_transfers,
        confirmation_depth_k,
        rewards_config,
        domain_block_pruning_depth,
        staking_withdrawal_period,
    } = genesis_params;

    let genesis_domains = if enable_domains {
        genesis_domain_params
            .genesis_domains
            .into_iter()
            .map(|genesis_domain| {
                sp_domains::GenesisDomain {
                    runtime_name: genesis_domain.runtime_name,
                    runtime_type: genesis_domain.runtime_type,
                    runtime_version: genesis_domain.runtime_version,
                    raw_genesis_storage: genesis_domain.raw_genesis,

                    // Domain config, mainly for placeholder the concrete value TBD
                    owner_account_id: sudo_account.clone(),
                    domain_name: genesis_domain.domain_name,
                    bundle_slot_probability: (1, 1),
                    operator_allow_list: genesis_domain.operator_allow_list.clone(),
                    signing_key: genesis_domain.operator_signing_key.clone(),
                    nomination_tax: Percent::from_percent(5),
                    minimum_nominator_stake: 100 * AI3,
                    initial_balances: genesis_domain.initial_balances,
                    domain_runtime_config: genesis_domain.domain_runtime_config,
                }
            })
            .collect()
    } else {
        vec![]
    };

    Ok(RuntimeGenesisConfig {
        system: SystemConfig::default(),
        balances: BalancesConfig { balances },
        transaction_payment: Default::default(),
        sudo: SudoConfig {
            // Assign network admin rights.
            key: Some(sudo_account.clone()),
        },
        subspace: SubspaceConfig {
            enable_rewards_at,
            allow_authoring_by,
            pot_slot_iterations,
            phantom: PhantomData,
        },
        rewards: rewards_config,
        council: council_config,
        democracy: DemocracyConfig::default(),
        runtime_configs: RuntimeConfigsConfig {
            enable_domains,
            enable_dynamic_cost_of_storage,
            enable_balance_transfers,
            confirmation_depth_k,
            council_democracy_config_params,
            domain_block_pruning_depth,
            staking_withdrawal_period,
        },
        domains: DomainsConfig {
            permissioned_action_allowed_by: enable_domains
                .then_some(genesis_domain_params.permissioned_action_allowed_by),
            genesis_domains,
        },
    })
}
