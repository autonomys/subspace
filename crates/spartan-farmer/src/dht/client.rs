use super::{
    core::create_node,
    eventloop::{ClientEvent, EventLoop},
};
use futures::channel::{
    mpsc::{channel, Sender},
    oneshot,
};
use futures::prelude::*;
use libp2p::{kad::QueryId, Multiaddr, PeerId};

pub struct ClientConfig {
    pub bootstrap_nodes: Vec<String>, // Vec<(Multiaddr, PeerId)>,
    pub listen_addr: Option<Multiaddr>,
}

pub struct Client {
    pub peerid: PeerId,
    // This channel sends events from Client to EventLoop.
    client_tx: Sender<ClientEvent>,
}

impl Client {
    fn new(peerid: PeerId, client_tx: Sender<ClientEvent>) -> Self {
        Client { peerid, client_tx }
    }

    // Read the Query Result for a specific Kademlia query.
    // This method returns information about pending as well as finsihed queries.
    // TODO: We are using for testing.
    #[allow(dead_code)]
    pub async fn query_result(&mut self, qid: QueryId) -> String {
        let (sender, recv) = oneshot::channel();

        self.client_tx
            .send(ClientEvent::QueryResult { qid, sender })
            .await
            .unwrap();

        let result = recv
            .await
            .expect("Failed to retrieve the list of all known peers.");

        result
    }

    // Get the list of all addresses we are listening on.
    // TODO: We are using for testing.
    #[allow(dead_code)]
    pub async fn listeners(&mut self) -> Vec<Multiaddr> {
        let (sender, recv) = oneshot::channel();

        self.client_tx
            .send(ClientEvent::Listeners { sender })
            .await
            .unwrap();

        let addrs = recv
            .await
            .expect("Failed to retrieve the list of all known peers.");

        addrs
    }

    // Dial another node using Peer Id and Address.
    // TODO: We are using for testing.
    #[allow(dead_code)]
    pub async fn dial(&mut self, peer: PeerId, addr: Multiaddr) {
        let (sender, recv) = oneshot::channel();

        self.client_tx
            .send(ClientEvent::Dial { addr, peer, sender })
            .await
            .unwrap();

        let _ = recv.await;
    }

    // Returns the list of all the peers the client has in its Routing table.
    // TODO: We are using for testing.
    #[allow(dead_code)]
    pub async fn known_peers(&mut self) -> Vec<PeerId> {
        let (sender, recv) = oneshot::channel();

        self.client_tx
            .send(ClientEvent::KnownPeers { sender })
            .await
            .unwrap();

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

    // Bootstrap
    pub async fn bootstrap(&mut self) -> QueryId {
        let (sender, recv) = oneshot::channel();

        self.client_tx
            .send(ClientEvent::Bootstrap { sender })
            .await
            .unwrap();

        // Check if the Bootstrap was processed, properly.
        recv.await.expect("Failed to bootstrap.")
    }
}

// This method will construct a new Swarm and EventLoop object.
pub fn create_connection(config: &ClientConfig) -> (Client, EventLoop) {
    let (client_tx, client_rx) = channel(10);

    let (peerid, swarm) = create_node(config);

    let eventloop = EventLoop::new(swarm, client_rx);
    let client = Client::new(peerid, client_tx);

    (client, eventloop)
}
