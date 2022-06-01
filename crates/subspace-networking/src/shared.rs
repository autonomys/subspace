//! Data structures shared between node and node runner, facilitating exchange and creation of
//! queries, subscriptions, various events and shared information.

use crate::request_responses::RequestFailure;
use crate::Request;
use bytes::Bytes;
use event_listener_primitives::Bag;
use futures::channel::{mpsc, oneshot};
use libp2p::core::multihash::Multihash;
use libp2p::gossipsub::error::{PublishError, SubscriptionError};
use libp2p::gossipsub::Sha256Topic;
use libp2p::kad::kbucket::Key;
use libp2p::{Multiaddr, PeerId};
use parking_lot::Mutex;
use std::borrow::Borrow;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct CreatedSubscription {
    /// Subscription ID to be used for unsubscribing.
    pub(crate) subscription_id: usize,
    /// Receiver side of the channel with new messages.
    pub(crate) receiver: mpsc::UnboundedReceiver<Bytes>,
}

#[derive(Debug)]
pub(crate) enum Command {
    // TODO: We might want to have more specific gets eventually
    GetValue {
        key: Multihash,
        result_sender: oneshot::Sender<Option<Vec<u8>>>,
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
        key: ExactKademliaKey,
        result_sender: oneshot::Sender<Option<Vec<PeerId>>>,
    },
    Request {
        peer_id: PeerId,
        request: Request,
        result_sender: oneshot::Sender<Result<Vec<u8>, RequestFailure>>, //TODO: error
    },
}

#[derive(Debug, Clone)]
pub(crate) struct ExactKademliaKey {
    hash: [u8; 32],
}

impl ExactKademliaKey {
    pub fn new(hash: [u8; 32]) -> Self {
        Self { hash }
    }
}

impl Borrow<[u8]> for ExactKademliaKey {
    fn borrow(&self) -> &[u8] {
        &self.hash
    }
}

impl From<ExactKademliaKey> for Key<ExactKademliaKey> {
    fn from(key: ExactKademliaKey) -> Key<ExactKademliaKey> {
        let mut data = [0u8; 64];

        data[..32].copy_from_slice(key.borrow());

        unsafe { std::mem::transmute::<[u8; 64], Key<ExactKademliaKey>>(data) }
    }
}

impl From<ExactKademliaKey> for Vec<u8> {
    fn from(key: ExactKademliaKey) -> Vec<u8> {
        key.hash.to_vec()
    }
}

#[derive(Default, Debug)]
pub(crate) struct Handlers {
    pub(crate) new_listener: Bag<Arc<dyn Fn(&Multiaddr) + Send + Sync + 'static>, Multiaddr>,
}

#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) handlers: Handlers,
    pub(crate) id: PeerId,
    /// Addresses on which node is listening for incoming requests.
    pub(crate) listeners: Mutex<Vec<Multiaddr>>,
    pub(crate) connected_peers_count: AtomicUsize,
    /// Sender end of the channel for sending commands to the swarm.
    pub(crate) command_sender: mpsc::Sender<Command>,
}

impl Shared {
    pub(crate) fn new(id: PeerId, command_sender: mpsc::Sender<Command>) -> Self {
        Self {
            handlers: Handlers::default(),
            id,
            listeners: Mutex::default(),
            connected_peers_count: AtomicUsize::new(0),
            command_sender,
        }
    }
}
