//! Chain specification for the test runtime.

use crate::domain_chain_spec::testnet_evm_genesis;
use codec::Encode;
use domain_runtime_primitives::AccountId20Converter;
use sc_chain_spec::{ChainType, GenericChainSpec};
use sp_core::{sr25519, Pair, Public};
use sp_domains::storage::RawGenesis;
use sp_domains::{GenesisDomain, OperatorAllowList, OperatorPublicKey, RuntimeType};
use sp_runtime::traits::{Convert, IdentifyAccount, Verify};
use sp_runtime::{BuildStorage, Percent};
use std::marker::PhantomData;
use std::num::NonZeroU32;
use subspace_runtime_primitives::{AccountId, Balance, BlockNumber, Signature};
use subspace_test_runtime::{
    AllowAuthoringBy, BalancesConfig, DomainsConfig, EnableRewardsAt, MaxDomainBlockSize,
    MaxDomainBlockWeight, RewardsConfig, RuntimeGenesisConfig, SubspaceConfig, SudoConfig,
    SystemConfig, VestingConfig, SSC, WASM_BINARY,
};

/// The `ChainSpec` parameterized for subspace test runtime.
pub type TestChainSpec = sc_service::GenericChainSpec<RuntimeGenesisConfig>;

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
pub fn subspace_local_testnet_config() -> TestChainSpec {
    let wasm_binary = WASM_BINARY.expect("Development wasm not available");
    // TODO: Migrate once https://github.com/paritytech/polkadot-sdk/issues/2963 is un-broken
    #[allow(deprecated)]
    TestChainSpec::from_genesis(
        "Local Testnet",
        "local_testnet",
        ChainType::Local,
        || {
            create_genesis_config(
                // Sudo account
                get_account_id_from_seed("Alice"),
                // Pre-funded accounts
                // Alice also get more funds that are used during the domain instantiation
                vec![
                    (
                        get_account_id_from_seed("Alice"),
                        (5_000
                            + crate::domain_chain_spec::endowed_accounts().len() as Balance
                                * 2_000_000)
                            * SSC,
                    ),
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
                vec![],
            )
        },
        vec![],
        None,
        Some("subspace-test"),
        None,
        None,
        Default::default(),
        wasm_binary,
    )
}

/// Configure initial storage state for FRAME modules.
fn create_genesis_config(
    sudo_account: AccountId,
    balances: Vec<(AccountId, Balance)>,
    // who, start, period, period_count, per_period
    vesting: Vec<(AccountId, BlockNumber, BlockNumber, u32, Balance)>,
) -> RuntimeGenesisConfig {
    let raw_genesis_storage = {
        // TODO: Migrate once https://github.com/paritytech/polkadot-sdk/issues/2963 is un-broken
        #[allow(deprecated)]
        let domain_chain_spec = GenericChainSpec::<_, _, ()>::from_genesis(
            "",
            "",
            ChainType::Development,
            testnet_evm_genesis,
            Vec::new(),
            None,
            None,
            None,
            None,
            None::<()>,
            evm_domain_test_runtime::WASM_BINARY.expect("Development wasm not available"),
        );
        let storage = domain_chain_spec
            .build_storage()
            .expect("Failed to build genesis storage from genesis runtime config");
        let raw_genesis = RawGenesis::from_storage(storage);
        raw_genesis.encode()
    };
    RuntimeGenesisConfig {
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
        vesting: VestingConfig { vesting },
        domains: DomainsConfig {
            permissioned_action_allowed_by: Some(sp_domains::PermissionedActionAllowedBy::Anyone),
            genesis_domains: vec![GenesisDomain {
                runtime_name: "evm".to_owned(),
                runtime_type: RuntimeType::Evm,
                runtime_version: evm_domain_test_runtime::VERSION,
                raw_genesis_storage,

                // Domain config, mainly for placeholder the concrete value TBD
                owner_account_id: sudo_account,
                domain_name: "evm-domain".to_owned(),
                max_block_size: MaxDomainBlockSize::get(),
                max_block_weight: MaxDomainBlockWeight::get(),
                bundle_slot_probability: (1, 1),
                target_bundles_per_block: 10,
                operator_allow_list: OperatorAllowList::Anyone,

                signing_key: get_from_seed::<OperatorPublicKey>("Alice"),
                minimum_nominator_stake: 100 * SSC,
                nomination_tax: Percent::from_percent(5),
                initial_balances: crate::domain_chain_spec::endowed_accounts()
                    .iter()
                    .cloned()
                    .map(|k| {
                        (
                            AccountId20Converter::convert(k),
                            2_000_000 * subspace_runtime_primitives::SSC,
                        )
                    })
                    .collect(),
            }],
        },
    }
}
