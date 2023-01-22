#![feature(
    const_option,
    drain_filter,
    hash_drain_filter,
    io_error_other,
    let_chains,
    trait_alias,
    try_blocks,
    type_changing_struct_update
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

pub(crate) mod identity;
pub mod node_client;
pub(crate) mod object_mappings;
pub mod reward_signing;
pub mod single_disk_plot;
pub mod utils;
pub mod ws_rpc_server;

pub use identity::Identity;
pub use jsonrpsee;
pub use node_client::node_rpc_client::NodeRpcClient;
pub use node_client::{Error as RpcClientError, NodeClient};
pub use object_mappings::{ObjectMappingError, ObjectMappings};
