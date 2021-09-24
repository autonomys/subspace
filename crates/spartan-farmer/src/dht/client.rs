// Stuff for Kademlia
use libp2p::kad::{QueryId, QueryResult};

// Stuff needed to create the swarm
use libp2p::{Multiaddr, PeerId};

// Stuff needed to set up channels between Client API task and EventLoop task.
use futures::channel::{
    mpsc::{channel, Sender},
    oneshot,
};
use futures::prelude::*;

type OneshotError = Box<dyn std::error::Error + Send>;
type OneshotType = Result<(), OneshotError>;

use super::{
    core::create_node,
    eventloop::{ClientEvent, EventLoop},
};

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

pub(super) enum ClientEvent {
    // Event for adding a listening address.
    Listen {
        addr: Multiaddr,
        sender: oneshot::Sender<OneshotType>,
    },
    // List all known peers.
    // TODO: We are using for testing.
    #[allow(dead_code)]
    KnownPeers {
        sender: oneshot::Sender<Vec<PeerId>>,
    },
    // Dial another peer.
    // TODO: We are using for testing.
    #[allow(dead_code)]
    Dial {
        addr: Multiaddr,
        peer: PeerId,
        sender: oneshot::Sender<OneshotType>,
    },
    // Bootstrap during the initial connection to the DHT.
    // NOTE: All the bootstrap nodes must already be connected to the swarm before we can start the
    // bootstrap process.
    Bootstrap {
        sender: oneshot::Sender<QueryId>,
    },
    // Get all listening addresses.
    // TODO: We are using for testing.
    #[allow(dead_code)]
    Listeners {
        sender: oneshot::Sender<Vec<Multiaddr>>,
    },
    // Read Kademlia Query Result.
    // TODO: We are using for testing.
    #[allow(dead_code)]
    QueryResult {
        qid: QueryId,
        sender: oneshot::Sender<String>,
    },
}

pub(super) fn handle_client_event(eventloop: &mut EventLoop, event: ClientEvent) {
    match event {
        ClientEvent::Listen { addr, sender } => match eventloop.swarm.listen_on(addr) {
            Ok(_) => sender.send(Ok(())).unwrap(),
            Err(e) => sender.send(Err(Box::new(e))).unwrap(),
        },
        ClientEvent::Bootstrap { sender } => {
            if let Ok(qid) = eventloop.swarm.behaviour_mut().kademlia.bootstrap() {
                sender.send(qid).unwrap();
            }
        }
        ClientEvent::KnownPeers { sender } => {
            let mut result = Vec::new();

            for bucket in eventloop.swarm.behaviour_mut().kademlia.kbuckets() {
                for record in bucket.iter() {
                    result.push(*record.node.key.preimage());
                }
            }

            sender.send(result).unwrap();
        }
        ClientEvent::Dial { addr, peer, sender } => {
            eventloop
                .swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer, addr.clone());

            eventloop.swarm.dial_addr(addr).unwrap();

            sender.send(Ok(())).unwrap();
        }
        ClientEvent::Listeners { sender } => {
            sender
                .send(eventloop.swarm.listeners().cloned().collect::<Vec<_>>())
                .unwrap();
        }
        ClientEvent::QueryResult { qid, sender } => {
            if eventloop.query_result.contains_key(&qid) {
                let result = match eventloop.query_result.remove(&qid).unwrap() {
                    QueryResult::Bootstrap(result) => match result {
                        Ok(result) => format!(
                            "[RESULT] This query still has {:?} peers remaining.",
                            result.num_remaining
                        ),
                        Err(e) => format!("{:?}", e),
                    },
                    QueryResult::GetClosestPeers(result) => match result {
                        Ok(result) => {
                            format!("This query produced {:?} peers.", result.peers.len())
                        }
                        Err(e) => format!("{:?}", e),
                    },
                    _ => "Unknown QueryResult Type".to_string(),
                };

                sender.send(result).unwrap();
            } else {
                let query = eventloop
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .query(&qid)
                    .unwrap();

                let stats = format!(
                    "Total Requests: {}\nFailed: {}\nSucceded: {}\nPending: {}\n",
                    query.stats().num_requests(),
                    query.stats().num_failures(),
                    query.stats().num_successes(),
                    query.stats().num_pending()
                );

                let info = match query.info() {
                    QueryInfo::Bootstrap { remaining, .. } => {
                        format!(
                            "[INFO] This query still has {:?} peers remaining.",
                            remaining
                        )
                    }
                    _ => "Unknown QueryInfo Type".to_string(),
                };

                sender.send(stats + &info).unwrap();
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
