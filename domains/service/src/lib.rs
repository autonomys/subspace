//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

pub mod config;
mod domain;
pub mod network;
pub mod providers;
pub mod rpc;

pub use self::domain::{DomainOperator, DomainParams, FullPool, NewFull, new_full};
use sc_domains::RuntimeExecutor;
use sc_service::TFullClient;

/// Domain full client.
pub type FullClient<Block, RuntimeApi> = TFullClient<Block, RuntimeApi, RuntimeExecutor>;

pub type FullBackend<Block> = sc_service::TFullBackend<Block>;
