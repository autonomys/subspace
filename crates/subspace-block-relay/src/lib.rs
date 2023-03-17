
mod protocol;
mod runner;
pub mod worker;

pub(crate) const LOG_TARGET: &str = "block_relay";

pub use crate::worker::{init_block_relay_config, BlockRelayWorker};
