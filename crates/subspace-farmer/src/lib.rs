#![doc = include_str!("../docs/README.md")]
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
