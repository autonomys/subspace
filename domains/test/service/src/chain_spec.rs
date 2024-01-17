//! Chain specification for the domain test runtime.

use evm_domain_test_runtime::RuntimeGenesisConfig;
use sc_service::{ChainSpec, ChainType, GenericChainSpec};
use sp_domains::storage::RawGenesis;

/// Create chain spec
pub fn create_domain_spec(raw_genesis: RawGenesis) -> Box<dyn ChainSpec> {
    // TODO: Migrate once https://github.com/paritytech/polkadot-sdk/issues/2963 is un-broken
    #[allow(deprecated)]
    let mut chain_spec = GenericChainSpec::<_, _, ()>::from_genesis(
        "Local Testnet",
        "local_testnet",
        ChainType::Local,
        // The value of the `RuntimeGenesisConfig` doesn't matter since it will be overwritten later
        RuntimeGenesisConfig::default,
        vec![],
        None,
        None,
        None,
        None,
        None,
        evm_domain_test_runtime::WASM_BINARY.expect("WASM binary was not build, please build it!"),
    );

    chain_spec.set_storage(raw_genesis.into_storage());

    Box::new(chain_spec)
}
