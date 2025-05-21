#![feature(
    array_chunks,
    array_windows,
    assert_matches,
    btree_extract_if,
    duration_constructors_lite,
    exact_size_is_empty,
    fmt_helpers_for_derive,
    future_join,
    impl_trait_in_assoc_type,
    int_roundings,
    iter_collect_into,
    never_type,
    result_flattening,
    trait_alias,
    try_blocks,
    type_alias_impl_trait,
    type_changing_struct_update
)]
#![warn(rust_2018_idioms, missing_debug_implementations, missing_docs)]

//! `subspace-farmer` is both a library and an app for everything related to farming on Subspace.
//!
//! # Library
//!
//! Library exposes all the necessary utilities for plotting, maintaining and farming plots.
//! Conceptually [`farm::Farm`] is an abstraction that contains a plot, a small piece cache and
//! corresponding metadata. [`single_disk_farm::SingleDiskFarm`] is the primary abstraction that
//! implements [`farm::Farm`] and encapsulates those components stored on local disk with high-level
//! API with events that allow to orchestrate farms from the outside (for example in CLI).
//!
//! While local farming is one option, there is also a way to have cluster setup, implemented in
//! [`cluster`] module. Cluster contains a special implementation of [`farm::Farm`] and other
//! components that are not stored on local disk, but rather are somewhere on the network (typically
//! LAN). This allows to better manage resources, which is primarily useful for large farmers.
//! Cluster setup usually consists from heterogeneous machines where different machines are
//! specialized with different tasks (some machines do farming, some plotting, some both, etc.).
//! Cluster setup also allows for even greater composition and allows for combining various pieces
//! of the software from different vendors (like unofficial plotters for example).
//!
//! Since various key components are implementations of traits, it is possible to use some part of
//! the library as is (like farming), while swapping others (like plotting). The library is meant to
//! be somewhat generic and allowing different composition scenarios.
//!
//! # CLI
//!
//! CLI provides reference implementation of the farmer software, it wraps library components and
//! orchestrates them as a final user-facing application.
//!
//! CLI exposes many key options to fine tune various aspects, but primarily for experimentation and
//! improving defaults, the goal is for default behavior to be already as optimal as efficient as
//! possible.

#[cfg(feature = "cluster")]
pub mod cluster;
pub mod disk_piece_cache;
pub mod farm;
pub mod farmer_cache;
pub mod farmer_piece_getter;
pub mod node_client;
pub mod plotter;
pub mod single_disk_farm;
pub mod thread_pool_manager;
pub mod utils;

/// Size of the LRU cache for peers.
pub const KNOWN_PEERS_CACHE_SIZE: u32 = 100;
