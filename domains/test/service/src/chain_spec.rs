//! Chain specification for the domain test runtime.

use sc_service::{ChainType, GenericChainSpec};

/// Create chain spec
pub fn create_domain_spec() -> GenericChainSpec {
    GenericChainSpec::builder(
        // Code doesn't matter, it will be replaced before running just like genesis storage
        &[],
        None,
    )
    .with_name("Local Testnet")
    .with_id("local_testnet")
    .with_chain_type(ChainType::Local)
    .build()
}
