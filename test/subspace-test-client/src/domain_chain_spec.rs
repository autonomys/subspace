//! Chain specification for the evm domain.

use evm_domain_test_runtime::{
    AccountId as AccountId20, Precompiles, RuntimeGenesisConfig, Signature,
};
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

fn endowed_accounts() -> Vec<AccountId20> {
    vec![
        get_account_id_from_seed::<ecdsa::Public>("Alice"),
        get_account_id_from_seed::<ecdsa::Public>("Bob"),
        get_account_id_from_seed::<ecdsa::Public>("Charlie"),
        get_account_id_from_seed::<ecdsa::Public>("Dave"),
        get_account_id_from_seed::<ecdsa::Public>("Eve"),
        get_account_id_from_seed::<ecdsa::Public>("Ferdie"),
        get_account_id_from_seed::<ecdsa::Public>("Alice//stash"),
        get_account_id_from_seed::<ecdsa::Public>("Bob//stash"),
        get_account_id_from_seed::<ecdsa::Public>("Charlie//stash"),
        get_account_id_from_seed::<ecdsa::Public>("Dave//stash"),
        get_account_id_from_seed::<ecdsa::Public>("Eve//stash"),
        get_account_id_from_seed::<ecdsa::Public>("Ferdie//stash"),
    ]
}

/// Get the genesis config of the evm domain
pub fn testnet_evm_genesis() -> RuntimeGenesisConfig {
    // This is the simplest bytecode to revert without returning any data.
    // We will pre-deploy it under all of our precompiles to ensure they can be called from
    // within contracts.
    // (PUSH1 0x00 PUSH1 0x00 REVERT)
    let revert_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xFD];

    let alice = get_account_id_from_seed::<ecdsa::Public>("Alice");

    RuntimeGenesisConfig {
        system: evm_domain_test_runtime::SystemConfig {
            code: evm_domain_test_runtime::WASM_BINARY
                .expect("WASM binary was not build, please build it!")
                .to_vec(),
            ..Default::default()
        },
        transaction_payment: Default::default(),
        balances: evm_domain_test_runtime::BalancesConfig {
            balances: endowed_accounts()
                .iter()
                .cloned()
                .map(|k| (k, 2_000_000 * SSC))
                .collect(),
        },
        sudo: evm_domain_test_runtime::SudoConfig { key: Some(alice) },
        evm_chain_id: evm_domain_test_runtime::EVMChainIdConfig {
            chain_id: 100,
            ..Default::default()
        },
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
            ..Default::default()
        },
        ethereum: Default::default(),
        base_fee: Default::default(),
        self_domain_id: evm_domain_test_runtime::SelfDomainIdConfig {
            // Id of the genesis domain
            domain_id: Some(DomainId::new(0)),
            ..Default::default()
        },
    }
}
