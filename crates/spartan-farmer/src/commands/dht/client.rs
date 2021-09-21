use super::*;
use super::{core::create_node, eventloop::EventLoop};

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
    // List all known peers.
    KnownPeers {
        sender: oneshot::Sender<Vec<PeerId>>,
    },
}

pub struct ClientConfig {
    pub bootstrap_nodes: Vec<String>, // Vec<(Multiaddr, PeerId)>,
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

    // Returns the list of all the peers the client has in its Routing table.
    pub async fn known_peers(&mut self) -> Vec<PeerId> {
        let (sender, recv) = oneshot::channel();

        self.client_tx
            .send(ClientEvent::KnownPeers { sender })
            .await;

        let peers = recv
            .await
            .expect("Failed to retrieve the list of all known peers.");

        peers
    }

    // Set listening address for a particular Normal node.
    pub async fn start_listening(&mut self, addr: Multiaddr) {
        // The oneshot channel helps us to pass error messages related to
        // SwarmEvent/KademliaEvent.
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

    pub fn handle_client_event(eventloop: &mut EventLoop, event: ClientEvent) {
        match event {
            ClientEvent::Listen { addr, sender } => match eventloop.swarm.listen_on(addr) {
                Ok(_) => sender.send(Ok(())).unwrap(),
                Err(e) => sender.send(Err(Box::new(e))).unwrap(),
            },
            ClientEvent::Bootstrap { sender } => {
                match eventloop.swarm.behaviour_mut().kademlia.bootstrap() {
                    Ok(_qid) => sender.send(Ok(())).unwrap(),
                    Err(e) => sender.send(Err(Box::new(e))).unwrap(),
                }
            }
            ClientEvent::KnownPeers { sender } => {
                let mut result = Vec::new();

                for bucket in eventloop.swarm.behaviour_mut().kademlia.kbuckets() {
                    if !bucket.is_empty() {
                        for record in bucket.iter() {
                            result.push(*record.node.key.preimage());
                        }
                    }
                }

                sender.send(result);
            }
        }
    }
}

// This method will construct a new Swarm and EventLoop object.
pub fn create_connection(config: &ClientConfig) -> (Client, EventLoop) {
    let (client_tx, client_rx) = channel(10);

    let (peerid, swarm) = match config.client_type {
        ClientType::Bootstrap => create_node(config),
        ClientType::Normal => create_node(config),
    };

    let eventloop = EventLoop::new(swarm, client_rx);
    let client = Client::new(peerid, client_tx);

    (client, eventloop)
}
