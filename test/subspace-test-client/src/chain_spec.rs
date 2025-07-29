//! Chain specification for the test runtime.

use sc_chain_spec::{ChainType, GenericChainSpec};
use sp_core::{Pair, Public, sr25519};
use sp_domains::{EvmType, PermissionedActionAllowedBy};
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::marker::PhantomData;
use std::num::NonZeroU32;
use subspace_runtime_primitives::{
    AI3, AccountId, Balance, CouncilDemocracyConfigParams, Signature,
};
use subspace_test_runtime::{
    AllowAuthoringBy, BalancesConfig, DomainsConfig, EnableRewardsAt, RewardsConfig,
    RuntimeConfigsConfig, RuntimeGenesisConfig, SubspaceConfig, SudoConfig, SystemConfig,
    WASM_BINARY,
};

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{seed}"), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
pub fn get_account_id_from_seed(seed: &str) -> AccountId {
    AccountPublic::from(get_from_seed::<sr25519::Public>(seed)).into_account()
}

/// Local testnet config (multivalidator Alice + Bob).
///
/// If `private_evm` is `true`, contract creation will have an allow list, which is set to `Anyone` by default.
/// Otherwise, any account can create contracts, and the allow list can't be changed.
///
/// If the EVM owner account isn't specified, `sudo_account` will be used.
pub fn subspace_local_testnet_config(
    private_evm: bool,
    evm_owner_account: Option<AccountId>,
) -> Result<GenericChainSpec, String> {
    let evm_type = if private_evm {
        EvmType::Private {
            initial_contract_creation_allow_list: PermissionedActionAllowedBy::Anyone,
        }
    } else {
        EvmType::Public
    };

    let sudo_account = get_account_id_from_seed("Alice");
    let evm_owner_account = evm_owner_account.unwrap_or_else(|| sudo_account.clone());

    // Pre-funded accounts
    // Alice and the EVM owner get more funds that are used during domain instantiation
    let mut balances = vec![
        (get_account_id_from_seed("Alice"), 1_000_000_000 * AI3),
        (get_account_id_from_seed("Bob"), 1_000 * AI3),
        (get_account_id_from_seed("Charlie"), 1_000 * AI3),
        (get_account_id_from_seed("Dave"), 1_000 * AI3),
        (get_account_id_from_seed("Eve"), 1_000 * AI3),
        (get_account_id_from_seed("Ferdie"), 1_000 * AI3),
        (get_account_id_from_seed("Alice//stash"), 1_000 * AI3),
        (get_account_id_from_seed("Bob//stash"), 1_000 * AI3),
        (get_account_id_from_seed("Charlie//stash"), 1_000 * AI3),
        (get_account_id_from_seed("Dave//stash"), 1_000 * AI3),
        (get_account_id_from_seed("Eve//stash"), 1_000 * AI3),
        (get_account_id_from_seed("Ferdie//stash"), 1_000 * AI3),
    ];

    if let Some((_existing_account, balance)) = balances
        .iter_mut()
        .find(|(account_id, _balance)| account_id == &evm_owner_account)
    {
        *balance = 1_000_000_000 * AI3;
    } else {
        balances.push((evm_owner_account.clone(), 1_000_000_000 * AI3));
    }

    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
        None,
    )
    .with_name("Local Testnet")
    .with_id("local_testnet")
    .with_chain_type(ChainType::Local)
    .with_genesis_config(
        serde_json::to_value(create_genesis_config(
            // Sudo account
            sudo_account,
            balances,
            evm_type,
            evm_owner_account,
        )?)
        .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
    )
    .with_protocol_id("subspace-test")
    .build())
}

/// Configure initial storage state for FRAME modules.
fn create_genesis_config(
    sudo_account: AccountId,
    balances: Vec<(AccountId, Balance)>,
    evm_type: EvmType,
    evm_owner_account: AccountId,
) -> Result<RuntimeGenesisConfig, String> {
    Ok(RuntimeGenesisConfig {
        system: SystemConfig::default(),
        balances: BalancesConfig { balances },
        transaction_payment: Default::default(),
        sudo: SudoConfig {
            // Assign network admin rights.
            key: Some(sudo_account.clone()),
        },
        subspace: SubspaceConfig {
            enable_rewards_at: EnableRewardsAt::Manually,
            allow_authoring_by: AllowAuthoringBy::Anyone,
            pot_slot_iterations: NonZeroU32::new(50_000_000).expect("Not zero; qed"),
            phantom: PhantomData,
        },
        rewards: RewardsConfig {
            remaining_issuance: 1_000_000 * AI3,
            proposer_subsidy_points: Default::default(),
            voter_subsidy_points: Default::default(),
        },
        domains: DomainsConfig {
            permissioned_action_allowed_by: Some(sp_domains::PermissionedActionAllowedBy::Anyone),
            genesis_domains: vec![
                crate::evm_domain_chain_spec::get_genesis_domain(evm_owner_account, evm_type)
                    .expect("hard-coded values are valid; qed"),
                crate::auto_id_domain_chain_spec::get_genesis_domain(sudo_account)
                    .expect("hard-coded values are valid; qed"),
            ],
        },
        runtime_configs: RuntimeConfigsConfig {
            enable_domains: true,
            enable_dynamic_cost_of_storage: false,
            enable_balance_transfers: false,
            confirmation_depth_k: 100u32,
            council_democracy_config_params: CouncilDemocracyConfigParams::default(),
            domain_block_pruning_depth: 14_400u32,
            staking_withdrawal_period: 14_400u32,
        },
    })
}
