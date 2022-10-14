#![feature(
    const_option,
    drain_filter,
    hash_drain_filter,
    int_log,
    io_error_other,
    map_first_last,
    trait_alias,
    try_blocks
)]

//! # `subspace-farmer` library implementation overview
//!
//! This library provides droppable/interruptable instances of two processes that can be run in
//! parallel: `plotting` and `farming`.
//!
//! During plotting we create:
//! * a binary plot file, which contains subspace-encoded pieces one after another
//! * a RocksDB commitments database, where key is a tag (first 8 bytes of `hmac(encoding, salt)`)
//!   and value is an offset of corresponding encoded piece in the plot (we can do this because all
//!   pieces have the same size).
//!
//! In short, for every piece we also store a record with 8-bytes tag and 8-bytes index (+some
//! overhead of RocksDB itself).
//!
//! During farming we receive a global challenge and need to find a solution based on *target* and
//! *solution range*. In order to find solution, we derive *local challenge* and use first 8 bytes
//! (the same as tag size) as our *target* and do range query in RocksDB. For that we interpret
//! *target* as 64-bit big-endian unsigned integer and find all of the keys in tags database that
//! are `target ± ½ * solution range` (while also handing overflow/underflow) when interpreted as
//! 64-bit unsigned integers.

pub(crate) mod archiving;
pub(crate) mod commitments;
pub(crate) mod dsn;
pub(crate) mod farming;
mod file_ext;
pub(crate) mod identity;
pub(crate) mod object_mappings;
pub(crate) mod plot;
pub mod reward_signing;
pub mod rpc_client;
pub mod single_disk_farm;
pub mod single_disk_plot;
pub mod single_plot_farm;
mod utils;
pub mod ws_rpc_server;

pub use archiving::{Archiving, ArchivingError};
pub use commitments::{CommitmentError, Commitments};
pub use farming::{Farming, FarmingError};
pub use identity::Identity;
pub use jsonrpsee;
pub use object_mappings::{ObjectMappingError, ObjectMappings};
pub use plot::{PieceOffset, Plot, PlotError, PlotFile};
pub use rpc_client::node_rpc_client::NodeRpcClient;
pub use rpc_client::{Error as RpcClientError, RpcClient};
