//! Block relay implementation.

mod consensus;
mod protocol;
mod types;
mod utils;

pub use crate::consensus::relay::{build_consensus_relay, BlockRelayConfigurationError};
pub use crate::utils::NetworkWrapper;

pub(crate) const LOG_TARGET: &str = "block_relay";
