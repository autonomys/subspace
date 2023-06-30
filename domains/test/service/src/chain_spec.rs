//! Chain specification for the domain test runtime.
use crate::EcdsaKeyring::{Alice, Bob, Charlie, Dave, Eve, Ferdie};
use evm_domain_test_runtime::{AccountId as AccountId20, Precompiles, Signature};
use sc_service::{ChainSpec, ChainType, GenericChainSpec};
use sp_core::{ecdsa, Pair, Public};
use sp_runtime::traits::{IdentifyAccount, Verify};
use subspace_runtime_primitives::SSC;

type AccountPublic = <Signature as Verify>::Signer;

/// Helper function to generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId20
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
/// [Evm domain => Alice]
pub fn get_chain_spec() -> Box<dyn ChainSpec> {
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
    Box::new(chain_spec_from_genesis!(testnet_evm_genesis))
}

fn endowed_accounts() -> Vec<AccountId20> {
    vec![
        Alice.to_account_id(),
        Bob.to_account_id(),
        Charlie.to_account_id(),
        Dave.to_account_id(),
        Eve.to_account_id(),
        Ferdie.to_account_id(),
        get_account_id_from_seed::<ecdsa::Public>("Alice//stash"),
        get_account_id_from_seed::<ecdsa::Public>("Bob//stash"),
        get_account_id_from_seed::<ecdsa::Public>("Charlie//stash"),
        get_account_id_from_seed::<ecdsa::Public>("Dave//stash"),
        get_account_id_from_seed::<ecdsa::Public>("Eve//stash"),
        get_account_id_from_seed::<ecdsa::Public>("Ferdie//stash"),
    ]
}

fn testnet_evm_genesis() -> evm_domain_test_runtime::GenesisConfig {
    // This is the simplest bytecode to revert without returning any data.
    // We will pre-deploy it under all of our precompiles to ensure they can be called from
    // within contracts.
    // (PUSH1 0x00 PUSH1 0x00 REVERT)
    let revert_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xFD];

    evm_domain_test_runtime::GenesisConfig {
        system: evm_domain_test_runtime::SystemConfig {
            code: evm_domain_test_runtime::WASM_BINARY
                .expect("WASM binary was not build, please build it!")
                .to_vec(),
        },
        transaction_payment: Default::default(),
        balances: evm_domain_test_runtime::BalancesConfig {
            balances: endowed_accounts()
                .iter()
                .cloned()
                .map(|k| (k, 2_000_000 * SSC))
                .collect(),
        },
        messenger: evm_domain_test_runtime::MessengerConfig {
            relayers: vec![(Alice.to_account_id(), Alice.to_account_id())],
        },
        sudo: evm_domain_test_runtime::SudoConfig {
            key: Some(Alice.to_account_id()),
        },
        evm_chain_id: evm_domain_test_runtime::EVMChainIdConfig { chain_id: 100 },
        evm: evm_domain_test_runtime::EVMConfig {
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
        },
        ethereum: Default::default(),
        base_fee: Default::default(),
    }
}
