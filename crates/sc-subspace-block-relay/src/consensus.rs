//! Relay implementation for consensus blocks.

mod relay;
mod types;

pub use relay::{build_consensus_relay, BlockRelayConfigurationError};
