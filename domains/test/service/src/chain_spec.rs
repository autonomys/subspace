//! Chain specification for the domain test runtime.

use evm_domain_test_runtime::RuntimeGenesisConfig;
use sc_service::{ChainSpec, ChainType, GenericChainSpec};
use sp_domains::storage::RawGenesis;

/// Create chain spec
pub fn create_domain_spec(raw_genesis: RawGenesis) -> GenericChainSpec<RuntimeGenesisConfig> {
    let mut chain_spec = GenericChainSpec::builder(
        evm_domain_test_runtime::WASM_BINARY.expect("WASM binary was not build, please build it!"),
        None,
    )
    .with_name("Local Testnet")
    .with_id("local_testnet")
    .with_chain_type(ChainType::Local)
    .build();

    chain_spec.set_storage(raw_genesis.into_storage());

    chain_spec
}
