use super::core::{create_swarm, ComposedEvent};
use super::eventloop::EventLoop;
use super::*;

pub enum ClientEvent {
    StartListening,
    Dial,
    Provide,
    Find,
}

pub struct Client {
    network_rx: Receiver<ComposedEvent>,
    client_tx: Sender<ClientEvent>,
}

pub async fn dht_listener() -> (Client, EventLoop) {
    let (network_tx, network_rx) = channel(10);
    let (client_tx, client_rx) = channel(10);

    return (
        Client::new(network_rx, client_tx),
        EventLoop::new(create_swarm().await, client_rx, network_tx),
    );
}

impl Client {
    /// This method will construct a new Swarm and eventloop.
    pub fn new(network_rx: Receiver<ComposedEvent>, client_tx: Sender<ClientEvent>) -> Self {
        Client {
            network_rx,
            client_tx,
        }
    }
    pub fn start_listening(&mut self) {
    }
}
