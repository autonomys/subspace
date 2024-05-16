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
pub fn subspace_local_testnet_config() -> Result<GenericChainSpec<RuntimeGenesisConfig>, String> {
    Ok(GenericChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
        None,
    )
    .with_name("Local Testnet")
    .with_id("local_testnet")
    .with_chain_type(ChainType::Local)
    .with_genesis_config(patch_domain_runtime_version(
        serde_json::to_value(create_genesis_config(
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
        )?)
        .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
    ))
    .with_protocol_id("subspace-test")
    .build())
}

/// Configure initial storage state for FRAME modules.
fn create_genesis_config(
    sudo_account: AccountId,
    balances: Vec<(AccountId, Balance)>,
    // who, start, period, period_count, per_period
    vesting: Vec<(AccountId, BlockNumber, BlockNumber, u32, Balance)>,
) -> Result<RuntimeGenesisConfig, String> {
    let raw_genesis_storage = {
        let domain_chain_spec =
            GenericChainSpec::<evm_domain_test_runtime::RuntimeGenesisConfig>::builder(
                evm_domain_test_runtime::WASM_BINARY
                    .ok_or_else(|| "Development wasm not available".to_string())?,
                None,
            )
            .with_chain_type(ChainType::Development)
            .with_genesis_config(
                serde_json::to_value(testnet_evm_genesis())
                    .map_err(|error| format!("Failed to serialize genesis config: {error}"))?,
            )
            .build();
        let storage = domain_chain_spec
            .build_storage()
            .expect("Failed to build genesis storage from genesis runtime config");
        let raw_genesis = RawGenesis::from_storage(storage);
        raw_genesis.encode()
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
        runtime_configs: Default::default(),
    })
}

// TODO: Workaround for https://github.com/paritytech/polkadot-sdk/issues/4001
fn patch_domain_runtime_version(mut genesis_config: serde_json::Value) -> serde_json::Value {
    let Some(genesis_domains) = genesis_config
        .get_mut("domains")
        .and_then(|domains| domains.get_mut("genesisDomains"))
        .and_then(|genesis_domains| genesis_domains.as_array_mut())
    else {
        return genesis_config;
    };

    for genesis_domain in genesis_domains {
        let Some(runtime_version) = genesis_domain.get_mut("runtime_version") else {
            continue;
        };

        if let Some(spec_name) = runtime_version.get_mut("specName") {
            if let Some(spec_name_bytes) = spec_name
                .as_str()
                .map(|spec_name| spec_name.as_bytes().to_vec())
            {
                *spec_name = serde_json::to_value(spec_name_bytes)
                    .expect("Bytes serialization doesn't fail; qed");
            }
        }

        if let Some(impl_name) = runtime_version.get_mut("implName") {
            if let Some(impl_name_bytes) = impl_name
                .as_str()
                .map(|impl_name| impl_name.as_bytes().to_vec())
            {
                *impl_name = serde_json::to_value(impl_name_bytes)
                    .expect("Bytes serialization doesn't fail; qed");
            }
        }
    }

    genesis_config
}
