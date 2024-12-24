//! Chain specification for the test runtime.

use sc_chain_spec::{ChainType, GenericChainSpec};
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::marker::PhantomData;
use std::num::NonZeroU32;
use subspace_runtime_primitives::{AccountId, Balance, Signature, SSC};
use subspace_test_runtime::{
    AllowAuthoringBy, BalancesConfig, DomainsConfig, EnableRewardsAt, RewardsConfig,
    RuntimeGenesisConfig, SubspaceConfig, SudoConfig, SystemConfig, WASM_BINARY,
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
pub fn subspace_local_testnet_config() -> Result<GenericChainSpec, String> {
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
            get_account_id_from_seed("Alice"),
            // Pre-funded accounts
            // Alice also get more funds that are used during the domain instantiation
            vec![
                (get_account_id_from_seed("Alice"), 1_000_000_000 * SSC),
                (get_account_id_from_seed("Bob"), 1_000 * SSC),
                (get_account_id_from_seed("Charlie"), 1_000 * SSC),
                (get_account_id_from_seed("Dave"), 1_000 * SSC),
                (get_account_id_from_seed("Eve"), 1_000 * SSC),
                (get_account_id_from_seed("Ferdie"), 1_000 * SSC),
                (get_account_id_from_seed("Alice//stash"), 1_000 * SSC),
                (get_account_id_from_seed("Bob//stash"), 1_000 * SSC),
                (get_account_id_from_seed("Charlie//stash"), 1_000 * SSC),
                (get_account_id_from_seed("Dave//stash"), 1_000 * SSC),
                (get_account_id_from_seed("Eve//stash"), 1_000 * SSC),
                (get_account_id_from_seed("Ferdie//stash"), 1_000 * SSC),
            ],
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
            remaining_issuance: 1_000_000 * SSC,
            proposer_subsidy_points: Default::default(),
            voter_subsidy_points: Default::default(),
        },
        domains: DomainsConfig {
            permissioned_action_allowed_by: Some(sp_domains::PermissionedActionAllowedBy::Anyone),
            genesis_domains: vec![
                crate::evm_domain_chain_spec::get_genesis_domain(sudo_account.clone())
                    .expect("Must success"),
                crate::auto_id_domain_chain_spec::get_genesis_domain(sudo_account.clone())
                    .expect("Must success"),
            ],
        },
        runtime_configs: Default::default(),
    })
}
