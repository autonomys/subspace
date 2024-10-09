//! Data structures shared between node and node runner, facilitating exchange and creation of
//! queries, subscriptions, various events and shared information.

use crate::protocols::request_response::request_response_factory::RequestFailure;
use crate::utils::multihash::Multihash;
use crate::utils::rate_limiter::RateLimiter;
use crate::utils::Handler;
use bytes::Bytes;
use futures::channel::{mpsc, oneshot};
use libp2p::gossipsub::{PublishError, Sha256Topic, SubscriptionError};
use libp2p::kad::{PeerRecord, RecordKey};
use libp2p::{Multiaddr, PeerId};
use parking_lot::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;

/// Represents Kademlia events (RoutablePeer, PendingRoutablePeer, UnroutablePeer).
#[derive(Clone, Debug)]
pub enum PeerDiscovered {
    /// Kademlia's unroutable peer event.
    UnroutablePeer {
        /// Peer ID
        peer_id: PeerId,
    },

    /// Kademlia's routable or pending routable peer event.
    RoutablePeer {
        /// Peer ID
        peer_id: PeerId,
        /// Peer address
        address: Multiaddr,
    },
}

impl PeerDiscovered {
    /// Extracts peer ID from event.
    pub fn peer_id(&self) -> PeerId {
        match self {
            PeerDiscovered::UnroutablePeer { peer_id } => *peer_id,
            PeerDiscovered::RoutablePeer { peer_id, .. } => *peer_id,
        }
    }
}

#[derive(Debug)]
pub(crate) struct CreatedSubscription {
    /// Subscription ID to be used for unsubscribing.
    pub(crate) subscription_id: usize,
    /// Receiver side of the channel with new messages.
    pub(crate) receiver: mpsc::UnboundedReceiver<Bytes>,
}

#[derive(Debug)]
pub(crate) enum Command {
    GetValue {
        key: Multihash,
        result_sender: mpsc::UnboundedSender<PeerRecord>,
        permit: OwnedSemaphorePermit,
    },
    PutValue {
        key: Multihash,
        value: Vec<u8>,
        result_sender: mpsc::UnboundedSender<()>,
        permit: OwnedSemaphorePermit,
    },
    Subscribe {
        topic: Sha256Topic,
        result_sender: oneshot::Sender<Result<CreatedSubscription, SubscriptionError>>,
    },
    Unsubscribe {
        topic: Sha256Topic,
        subscription_id: usize,
    },
    Publish {
        topic: Sha256Topic,
        message: Vec<u8>,
        result_sender: oneshot::Sender<Result<(), PublishError>>,
    },
    GetClosestPeers {
        key: Multihash,
        result_sender: mpsc::UnboundedSender<PeerId>,
        permit: Option<OwnedSemaphorePermit>,
    },
    GetClosestLocalPeers {
        key: Multihash,
        source: Option<PeerId>,
        result_sender: oneshot::Sender<Vec<(PeerId, Vec<Multiaddr>)>>,
    },
    GenericRequest {
        peer_id: PeerId,
        protocol_name: &'static str,
        request: Vec<u8>,
        result_sender: oneshot::Sender<Result<Vec<u8>, RequestFailure>>,
    },
    GetProviders {
        key: RecordKey,
        result_sender: mpsc::UnboundedSender<PeerId>,
        permit: Option<OwnedSemaphorePermit>,
    },
    BanPeer {
        peer_id: PeerId,
    },
    Dial {
        address: Multiaddr,
    },
    ConnectedPeers {
        result_sender: oneshot::Sender<Vec<PeerId>>,
    },
    Bootstrap {
        // No result sender means background async bootstrapping
        result_sender: Option<mpsc::UnboundedSender<()>>,
    },
}

#[derive(Default, Debug)]
pub(crate) struct Handlers {
    pub(crate) new_listener: Handler<Multiaddr>,
    pub(crate) num_established_peer_connections_change: Handler<usize>,
    pub(crate) connected_peer: Handler<PeerId>,
    pub(crate) disconnected_peer: Handler<PeerId>,
    pub(crate) peer_discovered: Handler<PeerDiscovered>,
}

#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) handlers: Handlers,
    pub(crate) id: PeerId,
    /// Addresses on which node is listening for incoming requests.
    pub(crate) listeners: Mutex<Vec<Multiaddr>>,
    pub(crate) external_addresses: Mutex<Vec<Multiaddr>>,
    pub(crate) num_established_peer_connections: Arc<AtomicUsize>,
    /// Sender end of the channel for sending commands to the swarm.
    pub(crate) command_sender: mpsc::Sender<Command>,
    pub(crate) rate_limiter: RateLimiter,
}

impl Shared {
    pub(crate) fn new(
        id: PeerId,
        command_sender: mpsc::Sender<Command>,
        rate_limiter: RateLimiter,
    ) -> Self {
        Self {
            handlers: Handlers::default(),
            id,
            listeners: Mutex::default(),
            external_addresses: Mutex::default(),
            num_established_peer_connections: Arc::new(AtomicUsize::new(0)),
            command_sender,
            rate_limiter,
        }
    }
}
