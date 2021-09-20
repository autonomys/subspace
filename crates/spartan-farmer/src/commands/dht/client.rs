use super::core::{create_bootstrap, create_node, ComposedBehaviour};
use super::eventloop::EventLoop;
use super::*;

#[derive(Debug)]
pub enum ClientEvent {
    // Event for adding a listening address.
    Listen {
        addr: Multiaddr,
        sender: oneshot::Sender<OneshotType>,
    },
}

pub enum ClientType {
    // Bootstrap node. It uses the following fields from `ClientConfig`:
    // 1. `bootstrap_keys`: Private keys/private key location to create bootstrap node peerId.
    // 2. `listen_addr`: Listening address for Bootstrap node.
    Bootstrap,
    // Normal node. It uses the following fields from `ClientConfig`:
    // 1. `bootstrap_nodes`: Bootstrap nodes addresses that the normal node must connect to.
    // For setting listening address, use client.start_listening.
    Normal,
}

pub struct Client {
    // This channel sends events from Client to EventLoop.
    client_tx: Sender<ClientEvent>,
}

impl Client {
    pub fn new(client_tx: Sender<ClientEvent>) -> Self {
        Client { client_tx }
    }

    // Set listening address for a particular Normal node.
    pub async fn start_listening(&mut self, addr: Multiaddr) {
        let (sender, recv) = oneshot::channel();

        let listen = ClientEvent::Listen { addr, sender };

        self.client_tx.send(listen).await.unwrap();

        // Check if the ListenEvent was processed, properly.
        let _ = recv.await.expect("Failed to start listening.");
    }
}

pub struct ClientConfig {
    // This will be true, if we are running a bootstrap node.
    pub bootstrap_nodes: Vec<(Multiaddr, PeerId)>,
    pub bootstrap_keys: Vec<Vec<u8>>,
    pub client_type: ClientType,
    pub listen_addr: Option<Multiaddr>,
}

// This method will construct a new Swarm and EventLoop object.
pub async fn create_connection(config: ClientConfig) -> (Client, EventLoop) {
    let (client_tx, client_rx) = channel(10);

    let client = Client::new(client_tx);

    let eventloop = match config.client_type {
        ClientType::Bootstrap => EventLoop::new(create_bootstrap(config).await, client_rx),
        ClientType::Normal => EventLoop::new(create_node(config).await, client_rx),
    };

    return (client, eventloop);
}

pub fn handle_client_event(swarm: &mut Swarm<ComposedBehaviour>, event: ClientEvent) {
    match event {
        ClientEvent::Listen { addr, sender } => match swarm.listen_on(addr) {
            Ok(_) => {
                sender.send(Ok(())).unwrap();
            }
            Err(e) => {
                sender.send(Err(Box::new(e))).unwrap();
            }
        },
    }
}
