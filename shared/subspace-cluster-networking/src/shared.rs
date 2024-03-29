//! Data structures shared between node and node runner, facilitating exchange and creation of
//! queries, subscriptions, various events and shared information.

use event_listener_primitives::Bag;
use futures::channel::{mpsc, oneshot};
use libp2p::request_response::OutboundFailure;
use libp2p::{Multiaddr, PeerId};
use parking_lot::Mutex;
use std::sync::Arc;

pub(crate) type HandlerFn<A> = Arc<dyn Fn(&A) + Send + Sync + 'static>;
pub(crate) type Handler<A> = Bag<HandlerFn<A>, A>;

#[derive(Debug)]
pub(crate) enum Command {
    Request {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: Vec<u8>,
        result_sender: oneshot::Sender<Result<Vec<u8>, OutboundFailure>>,
    },
}

#[derive(Default, Debug)]
pub(crate) struct Handlers {
    pub(crate) new_listener: Handler<Multiaddr>,
    pub(crate) connected_peer: Handler<PeerId>,
    pub(crate) disconnected_peer: Handler<PeerId>,
}

#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) handlers: Handlers,
    /// Addresses on which node is listening for incoming requests.
    pub(crate) listeners: Mutex<Vec<Multiaddr>>,
    /// Sender end of the channel for sending commands to the swarm.
    pub(crate) command_sender: mpsc::Sender<Command>,
}

impl Shared {
    pub(crate) fn new(command_sender: mpsc::Sender<Command>) -> Self {
        Self {
            handlers: Handlers::default(),
            listeners: Mutex::default(),
            command_sender,
        }
    }
}
