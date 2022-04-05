//! subspace-farmer library implementation overview
//!
//! This library provides droppable/interruptable instances of two processes that can be
//! run in parallel: `plotting` and `farming`.
//!
//! During plotting we create a binary plot file, which contains subspace-encoded pieces one
//! after another as well as RocksDB key-value database with tags, where key is tag (first 8 bytes
//! of `hmac(encoding, salt)`) and value is an offset of corresponding encoded piece in the plot (we
//! can do this because all pieces have the same size). So for every 4096 bytes we also store a
//! record with 8-bytes tag and 8-bytes index (+some overhead of RocksDB itself).
//!
//! During farming we receive a global challenge and need to find a solution, given target and
//! solution range. In order to find solution we derive local challenge as our target and do range
//! query in RocksDB. For that we interpret target as 64-bit unsigned integer, and find all of the
//! keys in tags database that are `target ± solution range` (while also handing overflow/underflow)
//! converted back to bytes.

#![feature(try_blocks, hash_drain_filter, int_log, io_error_other)]

pub(crate) mod commitments;
pub(crate) mod farming;
pub(crate) mod identity;
pub mod multi_farming;
pub(crate) mod object_mappings;
pub(crate) mod plot;
pub(crate) mod plotting;
pub(crate) mod rpc;
pub(crate) mod ws_rpc;
pub mod ws_rpc_server;

#[cfg(test)]
mod mock_rpc;

pub use commitments::{CommitmentError, Commitments};
pub use farming::{Farming, FarmingError};
pub use identity::Identity;
pub use jsonrpsee;
pub use object_mappings::{ObjectMappingError, ObjectMappings};
pub use plot::{retrieve_piece_from_plots, Plot, PlotError};
pub use plotting::{FarmerData, Plotting, PlottingError};
pub use rpc::RpcClient;
pub use ws_rpc::WsRpc;
