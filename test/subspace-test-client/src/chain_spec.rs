//! Chain specification for the test runtime.

use sc_chain_spec::ChainType;
use sp_core::{sr25519, Pair, Public};
use sp_executor::ExecutorPublicKey;
use sp_runtime::traits::{IdentifyAccount, Verify};
use subspace_runtime_primitives::{AccountId, Balance, BlockNumber, Signature};
use subspace_test_runtime::{
    AllowAuthoringBy, BalancesConfig, ExecutorConfig, GenesisConfig, SubspaceConfig, SudoConfig,
    SystemConfig, VestingConfig, SSC, WASM_BINARY,
};

/// The `ChainSpec` parameterized for subspace test runtime.
pub type TestChainSpec = sc_service::GenericChainSpec<subspace_test_runtime::GenesisConfig>;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
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
    TestChainSpec::from_genesis(
        "Local Testnet",
        "local_testnet",
        ChainType::Local,
        || {
            create_genesis_config(
                wasm_binary,
                // Sudo account
                get_account_id_from_seed("Alice"),
                // Pre-funded accounts
                vec![
                    (get_account_id_from_seed("Alice"), 1_000 * SSC),
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
                (
                    get_account_id_from_seed("Alice"),
                    get_from_seed::<ExecutorPublicKey>("Alice"),
                ),
            )
        },
        vec![],
        None,
        Some("subspace-test"),
        None,
        None,
        Default::default(),
    )
}

/// Configure initial storage state for FRAME modules.
fn create_genesis_config(
    wasm_binary: &[u8],
    sudo_account: AccountId,
    balances: Vec<(AccountId, Balance)>,
    // who, start, period, period_count, per_period
    vesting: Vec<(AccountId, BlockNumber, BlockNumber, u32, Balance)>,
    executor_authority: (AccountId, ExecutorPublicKey),
) -> GenesisConfig {
    GenesisConfig {
        system: SystemConfig {
            // Add Wasm runtime to storage.
            code: wasm_binary.to_vec(),
        },
        balances: BalancesConfig { balances },
        transaction_payment: Default::default(),
        sudo: SudoConfig {
            // Assign network admin rights.
            key: Some(sudo_account),
        },
        subspace: SubspaceConfig {
            enable_rewards: false,
            enable_storage_access: false,
            allow_authoring_by: AllowAuthoringBy::Anyone,
        },
        vesting: VestingConfig { vesting },
        executor: ExecutorConfig {
            executor: Some(executor_authority),
        },
    }
}
