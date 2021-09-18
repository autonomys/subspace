use super::client::ClientEvent;
use super::core::{ComposedBehaviour, ComposedEvent};
use super::*;

pub struct EventLoop {
    swarm: Swarm<ComposedBehaviour>,
    client_rx: Receiver<ClientEvent>,
    network_tx: Sender<ComposedEvent>,
}

impl EventLoop {
    /// Create new event loop
    pub fn new(
        swarm: Swarm<ComposedBehaviour>,
        client_rx: Receiver<ClientEvent>,
        network_tx: Sender<ComposedEvent>,
    ) -> Self {
        EventLoop {
            swarm,
            client_rx,
            network_tx,
        }
    }
    /// Run event loop. We will use this method to spawn the event loop in a background task.
    pub async fn run(&mut self) {}
}
