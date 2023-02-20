//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

mod core_domain;
mod rpc;
mod system_domain;

pub use self::core_domain::{new_full_core, CoreDomainParams, NewFullCore};
pub use self::system_domain::{new_full_system, FullPool, NewFullSystem};
use domain_runtime_primitives::opaque::Block;
use domain_runtime_primitives::RelayerId;
use sc_executor::NativeElseWasmExecutor;
use sc_service::{Configuration as ServiceConfiguration, TFullClient};

/// Domain full client.
pub type FullClient<RuntimeApi, ExecutorDispatch> =
    TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;

pub type FullBackend = sc_service::TFullBackend<Block>;

/// Domain configuration.
pub struct DomainConfiguration {
    pub service_config: ServiceConfiguration,
    pub maybe_relayer_id: Option<RelayerId>,
}
