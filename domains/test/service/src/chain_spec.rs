//! Chain specification for the domain test runtime.
use crate::EcdsaKeyring::{Alice, Bob, Charlie, Dave, Eve, Ferdie};
use evm_domain_test_runtime::{AccountId as AccountId20, GenesisConfig, Precompiles, Signature};
use once_cell::sync::OnceCell;
use sc_service::{ChainSpec, ChainType, GenericChainSpec};
use sp_core::{ecdsa, Pair, Public};
use sp_domains::DomainId;
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

/// Get the chain spec for the given domain.
///
/// Note: for convenience, the returned chain spec give some specific accounts the ability to
/// win the bundle election for a specific domain with (nearly) 100% probability in each slot:
/// [Evm domain => Alice]
pub fn get_chain_spec() -> Box<dyn ChainSpec> {
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

fn testnet_evm_genesis() -> GenesisConfig {
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
        self_domain_id: evm_domain_test_runtime::SelfDomainIdConfig {
            // Id of the genesis domain
            domain_id: Some(DomainId::new(0)),
        },
    }
}

/// HACK: `ChainSpec::from_genesis` is only allow to create hardcoded spec and `GenesisConfig`
/// dosen't derive `Clone`, using global variable and serialization/deserialization to workaround
/// these limits
// TODO: find a better solution, tests will run parallelly thus `load_chain_spec_with` multiple
// time, when we support more domain in the future the genesis domain of different domain will
// mixup in the current workaround.
static GENESIS_CONFIG: OnceCell<Vec<u8>> = OnceCell::new();

/// Load chain spec that contains the given `GenesisConfig`
fn load_chain_spec_with(genesis_config: GenesisConfig) -> Box<dyn ChainSpec> {
    let _ = GENESIS_CONFIG.set(
        serde_json::to_vec(&genesis_config).expect("Genesis config serialization never fails; qed"),
    );
    let constructor = || {
        let raw_genesis_config = GENESIS_CONFIG.get().expect("Value just set; qed");
        serde_json::from_slice::<GenesisConfig>(raw_genesis_config)
            .expect("Genesis config deserialization never fails; qed")
    };

    Box::new(chain_spec_from_genesis!(constructor))
}

/// Create chain spec
pub fn create_domain_spec(
    domain_id: DomainId,
    domain_instance_data: DomainInstanceData,
) -> Box<dyn ChainSpec> {
    let DomainInstanceData {
        runtime_type,
        runtime_code,
        raw_genesis_config,
    } = domain_instance_data;

    match runtime_type {
        RuntimeType::Evm => {
            let mut genesis_config = match raw_genesis_config {
                Some(raw_genesis_config) => serde_json::from_slice(&raw_genesis_config)
                    .expect("Raw genesis config should be well-formatted"),
                None => GenesisConfig::default(),
            };
            genesis_config.system.code = runtime_code;
            genesis_config.self_domain_id.domain_id = Some(domain_id);

            load_chain_spec_with(genesis_config)
        }
    }
}
