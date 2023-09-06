//! Subspace block relay implementation.

#![feature(const_option)]

mod consensus;
mod protocol;
mod types;
mod utils;

pub use crate::consensus::build_consensus_relay;
pub use crate::utils::NetworkWrapper;

pub(crate) const LOG_TARGET: &str = "block_relay";
