//! Chain specification for the domain test runtime.

use domain_test_runtime::{AccountId, Balance, Signature};
use sc_service::ChainType;
use sp_core::{sr25519, Pair, Public};
use sp_domains::ExecutorPublicKey;
use sp_runtime::traits::{IdentifyAccount, Verify};
use subspace_runtime_primitives::SSC;

/// Specialized `ChainSpec` for the normal parachain runtime.
pub type ChainSpec = sc_service::GenericChainSpec<domain_test_runtime::GenesisConfig>;

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Helper function to generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Get the chain spec for a specific parachain ID.
pub fn get_chain_spec() -> ChainSpec {
    ChainSpec::from_genesis(
        "Local Testnet",
        "local_testnet",
        ChainType::Local,
        local_testnet_genesis,
        vec![],
        None,
        None,
        None,
        None,
        Default::default(),
    )
}

/// Local testnet genesis for testing.
pub fn local_testnet_genesis() -> domain_test_runtime::GenesisConfig {
    testnet_genesis(
        get_account_id_from_seed::<sr25519::Public>("Alice"),
        vec![
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            get_account_id_from_seed::<sr25519::Public>("Bob"),
            get_account_id_from_seed::<sr25519::Public>("Charlie"),
            get_account_id_from_seed::<sr25519::Public>("Dave"),
            get_account_id_from_seed::<sr25519::Public>("Eve"),
            get_account_id_from_seed::<sr25519::Public>("Ferdie"),
            get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
            get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
            get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
            get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
            get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
            get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
        ],
        vec![(
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            1_000 * SSC,
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            get_from_seed::<ExecutorPublicKey>("Alice"),
        )],
    )
}

fn testnet_genesis(
    _root_key: AccountId,
    endowed_accounts: Vec<AccountId>,
    executors: Vec<(AccountId, Balance, AccountId, ExecutorPublicKey)>,
) -> domain_test_runtime::GenesisConfig {
    domain_test_runtime::GenesisConfig {
        system: domain_test_runtime::SystemConfig {
            code: domain_test_runtime::WASM_BINARY
                .expect("WASM binary was not build, please build it!")
                .to_vec(),
        },
        transaction_payment: Default::default(),
        balances: domain_test_runtime::BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 1_000_000 * SSC))
                .collect(),
        },
        executor_registry: domain_test_runtime::ExecutorRegistryConfig {
            executors,
            slot_probability: (1, 1),
        },
    }
}
