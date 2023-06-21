//! Chain specification for the domain test runtime.
use crate::Keyring::{Alice, Bob, Charlie, Dave, Eve, Ferdie};
use domain_runtime_primitives::{AccountId, Signature};
use sc_service::{ChainSpec, ChainType, GenericChainSpec};
use sp_application_crypto::UncheckedFrom;
use sp_core::{sr25519, Pair, Public};
use sp_domains::{DomainId, ExecutorPublicKey};
use sp_runtime::traits::{IdentifyAccount, Verify};
use subspace_runtime_primitives::SSC;

type AccountPublic = <Signature as Verify>::Signer;

/// Helper function to generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(
        TPublic::Pair::from_string(&format!("//{seed}"), None)
            .expect("static values are valid; qed")
            .public(),
    )
    .into_account()
}

/// Get the chain spec for the given domain.
///
/// Note: for convenience, the returned chain spec give some specific accounts the ability to
/// win the bundle election for a specific domain with (nearly) 100% probability in each slot:
/// [System domain => Alice]
/// [Core payments domain => Bob]
/// [Core eth relay domain => Charlie]
pub fn get_chain_spec(domain_id: DomainId) -> Box<dyn ChainSpec> {
    macro_rules! chain_spec_from_genesis {
        ( $constructor:expr ) => {{
            GenericChainSpec::from_genesis(
                "Local Testnet",
                "local_testnet",
                ChainType::Local,
                $constructor,
                vec![],
                None,
                None,
                None,
                None,
                None,
            )
        }};
    }
    match domain_id {
        DomainId::SYSTEM => Box::new(chain_spec_from_genesis!(testnet_system_genesis)),
        _ => panic!("{domain_id:?} unimplemented"),
    }
}

fn endowed_accounts() -> Vec<AccountId> {
    vec![
        Alice.to_account_id(),
        Bob.to_account_id(),
        Charlie.to_account_id(),
        Dave.to_account_id(),
        Eve.to_account_id(),
        Ferdie.to_account_id(),
        get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
        get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
        get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
        get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
        get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
        get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
    ]
}

fn testnet_system_genesis() -> system_domain_test_runtime::GenesisConfig {
    system_domain_test_runtime::GenesisConfig {
        system: system_domain_test_runtime::SystemConfig {
            code: system_domain_test_runtime::WASM_BINARY
                .expect("WASM binary was not build, please build it!")
                .to_vec(),
        },
        transaction_payment: Default::default(),
        balances: system_domain_test_runtime::BalancesConfig {
            balances: endowed_accounts()
                .iter()
                .cloned()
                .map(|k| (k, 2_000_000 * SSC))
                .collect(),
        },
        executor_registry: system_domain_test_runtime::ExecutorRegistryConfig {
            // Make Alice has a dominant executor stake such that it can produce bundle for the system domain
            // in each slot with high probability (nearly 100%).
            executors: vec![
                (
                    Alice.to_account_id(),
                    1_000_000 * SSC,
                    Alice.to_account_id(),
                    ExecutorPublicKey::unchecked_from(Alice.public().0),
                ),
                (
                    Bob.to_account_id(),
                    SSC,
                    Bob.to_account_id(),
                    ExecutorPublicKey::unchecked_from(Bob.public().0),
                ),
                (
                    Charlie.to_account_id(),
                    SSC,
                    Charlie.to_account_id(),
                    ExecutorPublicKey::unchecked_from(Charlie.public().0),
                ),
            ],
            slot_probability: (1, 1),
        },
        domain_registry: system_domain_test_runtime::DomainRegistryConfig::default(),
        messenger: system_domain_test_runtime::MessengerConfig {
            relayers: vec![(Alice.to_account_id(), Alice.to_account_id())],
        },
        sudo: system_domain_test_runtime::SudoConfig {
            key: Some(Alice.to_account_id()),
        },
    }
}
