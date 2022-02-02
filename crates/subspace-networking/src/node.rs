use crate::shared::Shared;
use event_listener_primitives::HandlerId;
use libp2p::{Multiaddr, PeerId};
use std::sync::Arc;

/// Implementation of a network node on Subspace Network.
#[derive(Debug, Clone)]
pub struct Node {
    pub(crate) shared: Arc<Shared>,
}

impl Node {
    /// Node's own local ID.
    pub fn id(&self) -> PeerId {
        self.shared.id
    }

    /// Node's own addresses where it listens for incoming requests.
    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.shared.listeners.lock().clone()
    }

    /// Callback is called when node starts listening on new address.
    pub fn on_new_listener(
        &self,
        callback: Arc<dyn Fn(&Multiaddr) + Send + Sync + 'static>,
    ) -> HandlerId {
        self.shared.handlers.new_listener.add(callback)
    }
}
