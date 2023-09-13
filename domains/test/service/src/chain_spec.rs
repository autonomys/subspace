//! Chain specification for the domain test runtime.

use evm_domain_test_runtime::RuntimeGenesisConfig;
use sc_service::{ChainSpec, ChainType, GenericChainSpec};
use sp_domains::{DomainId, DomainInstanceData, RuntimeType};
use std::sync::OnceLock;

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

/// HACK: `ChainSpec::from_genesis` is only allow to create hardcoded spec and `RuntimeGenesisConfig`
/// dosen't derive `Clone`, using global variable and serialization/deserialization to workaround
/// these limits
// TODO: find a better solution, tests will run parallelly thus `load_chain_spec_with` multiple
// time, when we support more domain in the future the genesis domain of different domain will
// mixup in the current workaround.
static GENESIS_CONFIG: OnceLock<Vec<u8>> = OnceLock::new();

/// Load chain spec that contains the given `RuntimeGenesisConfig`
fn load_chain_spec_with(genesis_config: RuntimeGenesisConfig) -> Box<dyn ChainSpec> {
    let _ = GENESIS_CONFIG.set(
        serde_json::to_vec(&genesis_config).expect("Genesis config serialization never fails; qed"),
    );
    let constructor = || {
        let raw_genesis_config = GENESIS_CONFIG.get().expect("Value just set; qed");
        serde_json::from_slice::<RuntimeGenesisConfig>(raw_genesis_config)
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
                None => RuntimeGenesisConfig::default(),
            };
            genesis_config.system.code = runtime_code;
            genesis_config.self_domain_id.domain_id = Some(domain_id);

            load_chain_spec_with(genesis_config)
        }
    }
}
