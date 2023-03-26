mod protocol;
mod runner;

pub(crate) const LOG_TARGET: &str = "block_relay";

pub use crate::protocol::{build_block_relay, init_block_relay_config};
