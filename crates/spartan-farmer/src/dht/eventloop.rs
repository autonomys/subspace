// Stuff for Kademlia
use libp2p::kad::{KademliaEvent, QueryId, QueryInfo, QueryResult};
use libp2p::{swarm::SwarmEvent, Swarm};
use libp2p::{Multiaddr, PeerId};

// Stuff needed to set up channels between Client API task and EventLoop task.
use futures::channel::mpsc::Receiver;
use futures::channel::oneshot;
use futures::StreamExt;
use log::info;
use std::collections::HashMap;

use super::core::{ComposedBehaviour, ComposedEvent};

type OneshotError = Box<dyn std::error::Error + Send>;
type OneshotType = Result<(), OneshotError>;

pub struct EventLoop {
    pub(super) swarm: Swarm<ComposedBehaviour>,
    // Channel to receive events from Client.
    client_rx: Receiver<ClientEvent>,
    // HashMap to send back QueryResults.
    pub(super) query_result: HashMap<QueryId, QueryResult>,
}

impl EventLoop {
    // Create new event loop
    pub(super) fn new(swarm: Swarm<ComposedBehaviour>, client_rx: Receiver<ClientEvent>) -> Self {
        EventLoop {
            swarm,
            client_rx,
            query_result: HashMap::default(),
        }
    }

    // Run event loop. We will use this method to spawn the event loop in a background task.
    pub async fn run(mut self) {
        loop {
            futures::select! {
                client_event = self.client_rx.next() => if let Some(event) = client_event {
                    handle_client_event(&mut self, event)
                },
                network_event = self.swarm.next() => match network_event {
                    Some(event) => self.handle_network_event(event).await,
                    None => break,
                }
            }
        }
    }

    // Handle network events.
    async fn handle_network_event(&mut self, event: SwarmEvent<ComposedEvent, std::io::Error>) {
        match event {
            SwarmEvent::Behaviour(ComposedEvent::Kademlia(event)) => match event {
                KademliaEvent::RoutingUpdated { peer, .. } => {
                    info!("Added new peer to routing table: {:?}", peer)
                }
                KademliaEvent::OutboundQueryCompleted { id, result, .. } => {
                    match &result {
                        QueryResult::Bootstrap(bootstrap_result) => match bootstrap_result {
                            Ok(_res) => info!("Bootstrapping finished successfully."),
                            Err(e) => info!("{:?}", e),
                        },
                        _ => {}
                    };
                    // Send query results back so that we can use that information.
                    self.query_result.insert(id, result);
                }
                _ => {}
            },
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Farmer is listening to K-DHT on: {:?}", address)
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connected to new peer: {:?}", peer_id)
            }
            _ => {}
        }
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
