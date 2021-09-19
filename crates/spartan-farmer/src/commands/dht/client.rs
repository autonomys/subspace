use super::core::{create_swarm, ComposedBehaviour};
use super::eventloop::EventLoop;
use super::*;

#[derive(Debug)]
pub enum ClientEvent {
    Listen { addr: Multiaddr },
    ReturnListen { addr: Multiaddr },
    Dial,
    Provide,
    Find,
}

pub struct Client {
    network_rx: Receiver<ClientEvent>,
    client_tx: Sender<ClientEvent>,
}

impl Client {
    pub fn new(network_rx: Receiver<ClientEvent>, client_tx: Sender<ClientEvent>) -> Self {
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

pub struct ClientConfig {
    // This will be true, if we are running a bootstrap node.
    pub bootstrap: bool,
}

/// This method will construct a new Swarm and EventLoop object.
pub async fn dht_listener(config: ClientConfig) -> (Client, EventLoop) {
    let (network_tx, network_rx) = channel(10);
    let (client_tx, client_rx) = channel(10);

    let client = Client::new(network_rx, client_tx);
    let eventloop = EventLoop::new(create_swarm(config.bootstrap).await, client_rx, network_tx);

    return (client, eventloop);
}

pub fn handle_client_event(swarm: &mut Swarm<ComposedBehaviour>, event: ClientEvent) {
    match event {
        ClientEvent::Listen { addr } => match swarm.listen_on(addr) {
            Ok(_) => {}
            Err(e) => info!("{:?}", e),
        },
        _ => {}
    }
}
