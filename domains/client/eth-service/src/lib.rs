#![allow(dead_code)]
#![deny(unused_crate_dependencies)]

pub mod provider;
pub(crate) mod rpc;
mod service;

pub use rpc::DefaultEthConfig;
