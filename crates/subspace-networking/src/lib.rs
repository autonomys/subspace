//! Networking functionality of Subspace Network, primarily used for DSN (Distributed Storage
//! Network).

#![feature(
    exact_size_is_empty,
    impl_trait_in_assoc_type,
    ip,
    trivial_bounds,
    try_blocks
)]
#![warn(missing_docs)]

mod behavior;
mod constructor;
mod node;
mod node_runner;
pub mod protocols;

mod shared;
pub mod utils;

pub use crate::behavior::persistent_parameters::{
    KnownPeersManager, KnownPeersManagerConfig, KnownPeersManagerPersistenceError,
    KnownPeersRegistry, PeerAddressRemovedEvent,
};
pub use crate::node::{
    GetClosestPeersError, Node, SendRequestError, SubscribeError, TopicSubscription, WeakNode,
};
pub use crate::node_runner::NodeRunner;
pub use constructor::{Config, CreationError, KademliaMode, construct, peer_id};
pub use libp2p;
pub use shared::PeerDiscovered;
pub use utils::PeerAddress;
pub use utils::key_with_distance::KeyWithDistance;
pub use utils::multihash::Multihash;
