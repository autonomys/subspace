//! Data structures shared between node and node runner, facilitating exchange and creation of
//! queries, subscriptions, various events and shared information.

use crate::request_responses::RequestFailure;
use crate::utils::{ResizableSemaphore, ResizableSemaphorePermit};
use bytes::Bytes;
use event_listener_primitives::Bag;
use futures::channel::{mpsc, oneshot};
use libp2p::core::multihash::Multihash;
use libp2p::gossipsub::error::{PublishError, SubscriptionError};
use libp2p::gossipsub::Sha256Topic;
use libp2p::kad::record::Key;
use libp2p::kad::{PeerRecord, ProviderRecord};
use libp2p::{Multiaddr, PeerId};
use parking_lot::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::sync::watch;

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
        permit: ResizableSemaphorePermit,
    },
    PutValue {
        key: Multihash,
        value: Vec<u8>,
        result_sender: mpsc::UnboundedSender<()>,
        permit: ResizableSemaphorePermit,
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
        permit: ResizableSemaphorePermit,
    },
    GenericRequest {
        peer_id: PeerId,
        protocol_name: &'static str,
        request: Vec<u8>,
        result_sender: oneshot::Sender<Result<Vec<u8>, RequestFailure>>,
    },
    CheckConnectedPeers {
        result_sender: oneshot::Sender<bool>,
    },
    StartLocalAnnouncing {
        key: Key,
        result_sender: oneshot::Sender<bool>,
    },
    StopLocalAnnouncing {
        key: Multihash,
        result_sender: oneshot::Sender<()>,
    },
    GetProviders {
        key: Multihash,
        result_sender: mpsc::UnboundedSender<PeerId>,
        permit: ResizableSemaphorePermit,
    },
    BanPeer {
        peer_id: PeerId,
    },
    Dial {
        address: Multiaddr,
    },
}

pub(crate) type HandlerFn<A> = Arc<dyn Fn(&A) + Send + Sync + 'static>;
type Handler<A> = Bag<HandlerFn<A>, A>;

#[derive(Default, Debug)]
pub(crate) struct Handlers {
    pub(crate) new_listener: Handler<Multiaddr>,
    pub(crate) announcement: Handler<ProviderRecord>,
}

#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) handlers: Handlers,
    pub(crate) id: PeerId,
    /// Addresses on which node is listening for incoming requests.
    pub(crate) listeners: Mutex<Vec<Multiaddr>>,
    pub(crate) external_addresses: Mutex<Vec<Multiaddr>>,
    pub(crate) connected_peers_count: Arc<AtomicUsize>,
    /// Sender end of the channel for sending commands to the swarm.
    pub(crate) command_sender: mpsc::Sender<Command>,
    pub(crate) kademlia_tasks_semaphore: ResizableSemaphore,
    pub(crate) regular_tasks_semaphore: ResizableSemaphore,
    pub(crate) online_status_observer_rx: watch::Receiver<bool>,
}

impl Shared {
    pub(crate) fn new(
        id: PeerId,
        command_sender: mpsc::Sender<Command>,
        kademlia_tasks_semaphore: ResizableSemaphore,
        regular_tasks_semaphore: ResizableSemaphore,
        online_status_observer_rx: watch::Receiver<bool>,
    ) -> Self {
        Self {
            handlers: Handlers::default(),
            id,
            listeners: Mutex::default(),
            external_addresses: Mutex::default(),
            connected_peers_count: Arc::new(AtomicUsize::new(0)),
            command_sender,
            kademlia_tasks_semaphore,
            regular_tasks_semaphore,
            online_status_observer_rx,
        }
    }
}
