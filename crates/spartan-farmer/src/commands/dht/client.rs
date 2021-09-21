use super::core::{create_node, ComposedBehaviour};
use super::eventloop::EventLoop;
use super::*;

#[derive(Copy, Clone, Debug)]
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

pub enum ClientEvent {
    // Event for adding a listening address.
    Listen {
        addr: Multiaddr,
        sender: oneshot::Sender<OneshotType>,
    },
    // Bootstrap, look for the closest peers.
    Bootstrap {
        sender: oneshot::Sender<OneshotType>,
    },
}

pub struct ClientConfig {
    pub bootstrap_nodes: Vec<String>, // Vec<(Multiaddr, PeerId)>,
    pub bootstrap_keys: Vec<Vec<u8>>,
    pub client_type: ClientType,
    pub listen_addr: Option<Multiaddr>,
}

pub struct Client {
    pub peerid: PeerId,
    // This channel sends events from Client to EventLoop.
    client_tx: Sender<ClientEvent>,
}

impl Client {
    pub fn new(peerid: PeerId, client_tx: Sender<ClientEvent>) -> Self {
        Client { peerid, client_tx }
    }

    // Set listening address for a particular Normal node.
    pub async fn start_listening(&mut self, addr: Multiaddr) {
        let (sender, recv) = oneshot::channel();

        self.client_tx
            .send(ClientEvent::Listen { addr, sender })
            .await
            .unwrap();

        // Check if the ListenEvent was processed, properly.
        let _ = recv.await.expect("Failed to start listening.");
    }

    // Sync with other peers on the DHT.
    pub async fn bootstrap(&mut self) {
        let (sender, recv) = oneshot::channel();

        self.client_tx
            .send(ClientEvent::Bootstrap { sender })
            .await
            .unwrap();

        // Check if the Bootstrap was processed, properly.
        let _ = recv.await.expect("Failed to bootstrap.");
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
            ClientEvent::Bootstrap { sender } => match swarm.behaviour_mut().kademlia.bootstrap() {
                Ok(_) => {
                    sender.send(Ok(())).unwrap();
                }
                Err(e) => {
                    sender.send(Err(Box::new(e))).unwrap();
                }
            },
        }
    }
}

// This method will construct a new Swarm and EventLoop object.
pub async fn create_connection(config: &ClientConfig) -> (Client, EventLoop) {
    let (client_tx, client_rx) = channel(10);

    let (peerid, swarm) = match config.client_type {
        ClientType::Bootstrap => create_node(config).await,
        ClientType::Normal => create_node(config).await,
    };

    let eventloop = EventLoop::new(swarm, client_rx);
    let client = Client::new(peerid, client_tx);

    (client, eventloop)
}
