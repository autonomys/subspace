#![feature(
    array_chunks,
    array_windows,
    assert_matches,
    const_option,
    duration_constructors,
    exact_size_is_empty,
    fmt_helpers_for_derive,
    hash_extract_if,
    impl_trait_in_assoc_type,
    int_roundings,
    iter_collect_into,
    let_chains,
    never_type,
    slice_flatten,
    split_at_checked,
    trait_alias,
    try_blocks,
    type_alias_impl_trait,
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

pub mod cluster;
pub mod farm;
pub mod farmer_cache;
pub(crate) mod identity;
pub mod node_client;
pub mod piece_cache;
pub mod plotter;
pub mod reward_signing;
pub mod single_disk_farm;
pub mod thread_pool_manager;
pub mod utils;

pub use identity::Identity;
pub use jsonrpsee;
use std::num::NonZeroUsize;

/// Size of the LRU cache for peers.
pub const KNOWN_PEERS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(100).expect("Not zero; qed");
