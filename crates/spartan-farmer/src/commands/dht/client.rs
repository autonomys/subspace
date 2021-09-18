use super::core::{create_swarm, ComposedEvent};
use super::eventloop::EventLoop;
use super::*;

#[derive(Debug)]
pub enum ClientEvent {
    Listen { addr: Multiaddr },
    Dial,
    Provide,
    Find,
}

pub struct Client {
    network_rx: Receiver<ComposedEvent>,
    client_tx: Sender<ClientEvent>,
}

/// This method will construct a new Swarm and EventLoop object.
pub async fn dht_listener() -> (Client, EventLoop) {
    let (network_tx, network_rx) = channel(10);
    let (client_tx, client_rx) = channel(10);

    return (
        Client::new(network_rx, client_tx),
        EventLoop::new(create_swarm().await, client_rx, network_tx),
    );
}

impl Client {
    pub fn new(network_rx: Receiver<ComposedEvent>, client_tx: Sender<ClientEvent>) -> Self {
        Client {
            network_rx,
            client_tx,
        }
    }

    pub async fn start_listening(&mut self, addr: Multiaddr) {
        self.client_tx
            .send(ClientEvent::Listen { addr })
            .await
            .expect("Listening failed.");
    }
}
