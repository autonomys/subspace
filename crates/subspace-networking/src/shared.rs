use event_listener_primitives::Bag;
use futures::channel::mpsc;
use libp2p::{Multiaddr, PeerId};
use parking_lot::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) enum Command {
    // TODO
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
