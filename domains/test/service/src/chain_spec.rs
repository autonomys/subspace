//! Chain specification for the domain test runtime.

use evm_domain_test_runtime::RuntimeGenesisConfig;
use sc_service::{ChainSpec, ChainType, GenericChainSpec};
use sp_domains::storage::RawGenesis;

/// Create chain spec
pub fn create_domain_spec(raw_genesis: RawGenesis) -> Box<dyn ChainSpec> {
    let mut chain_spec = GenericChainSpec::from_genesis(
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
    );

    chain_spec.set_storage(raw_genesis.into_storage());

    Box::new(chain_spec)
}
