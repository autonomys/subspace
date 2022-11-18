//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

mod core_domain;
mod pool_wrapper;
mod rpc;
mod system_domain;

pub use self::core_domain::{
    new_full as new_full_core, CorePaymentsDomainExecutorDispatch, NewFull as NewFullCore,
};
pub use self::system_domain::{new_full, NewFull, SystemDomainExecutorDispatch};
pub use crate::pool_wrapper::DomainTransactionPoolWrapper;
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
