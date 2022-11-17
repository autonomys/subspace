//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

mod core_domain;
mod rpc;
mod system_domain;

pub use self::core_domain::{new_full as new_full_core, NewFull as NewFullCore};
pub use self::system_domain::{new_full, NewFull};
use domain_runtime_primitives::RelayerId;
use sc_service::Configuration as ServiceConfiguration;
use sp_core::crypto::Ss58Codec;

/// Secondary chain configuration.
pub struct Configuration {
    service_config: ServiceConfiguration,
    maybe_relayer_id: Option<RelayerId>,
}

/// Configuration error for secondary chain.
#[derive(Debug)]
pub enum ConfigurationError {
    /// Emits when the relayer id is invalid.
    InvalidRelayerId,
}

impl Configuration {
    pub fn new(
        service_config: ServiceConfiguration,
        maybe_relayer_id: Option<String>,
    ) -> Result<Self, ConfigurationError> {
        let maybe_relayer_id = match maybe_relayer_id {
            None => None,
            Some(relayer_id) => {
                let relayer_id = RelayerId::from_ss58check(&relayer_id)
                    .map_err(|_| ConfigurationError::InvalidRelayerId)?;
                Some(relayer_id)
            }
        };

        Ok(Configuration {
            service_config,
            maybe_relayer_id,
        })
    }
}
