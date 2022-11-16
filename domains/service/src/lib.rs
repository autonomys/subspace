//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

mod core_domain;
mod rpc;
mod system_domain;

pub use self::core_domain::{new_full as new_full_core, NewFull as NewFullCore};
pub use self::system_domain::{new_full, Configuration, NewFull};
