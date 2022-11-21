//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

mod core_domain;
mod pool_wrapper;
mod rpc;
mod system_domain;

pub use self::core_domain::{
    new_full as new_full_core, new_partial as new_partial_core, CorePaymentsDomainExecutorDispatch,
    NewFull as NewFullCore, PartialComponents as CoreDomainPartialComponents,
};
pub use self::system_domain::{
    new_full, new_partial, NewFull, PartialComponents as SystemDomainPartialComponents,
    SystemDomainExecutorDispatch,
};
pub use crate::pool_wrapper::DomainTransactionPoolRouter;
use domain_runtime_primitives::RelayerId;
use sc_service::Configuration as ServiceConfiguration;

/// Secondary chain configuration.
pub struct Configuration {
    service_config: ServiceConfiguration,
    maybe_relayer_id: Option<RelayerId>,
}

impl Configuration {
    pub fn new(service_config: ServiceConfiguration, maybe_relayer_id: Option<RelayerId>) -> Self {
        Configuration {
            service_config,
            maybe_relayer_id,
        }
    }
}
