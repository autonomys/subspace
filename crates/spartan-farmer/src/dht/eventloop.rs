// Stuff for Kademlia
use libp2p::kad::{KademliaEvent, QueryId, QueryResult};

use libp2p::{swarm::SwarmEvent, Swarm};

// Stuff needed to set up channels between Client API task and EventLoop task.
use futures::channel::mpsc::Receiver;
use futures::StreamExt;

use log::info;

type OneshotError = Box<dyn std::error::Error + Send>;
type OneshotType = Result<(), OneshotError>;

use super::{
    client::{Client, ClientEvent},
    core::{ComposedBehaviour, ComposedEvent},
};
use std::collections::HashMap;

pub struct EventLoop {
    pub swarm: Swarm<ComposedBehaviour>,
    // Channel to receive events from Client.
    client_rx: Receiver<ClientEvent>,
    // HashMap to send back QueryResults.
    pub query_result: HashMap<QueryId, QueryResult>,
}

impl EventLoop {
    // Create new event loop
    pub fn new(swarm: Swarm<ComposedBehaviour>, client_rx: Receiver<ClientEvent>) -> Self {
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
                    Client::handle_client_event(&mut self, event)
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
                        QueryResult::GetClosestPeers(rnd_walk_result) => match rnd_walk_result {
                            Ok(res) => {
                                info!(
                                    "Kademlia Random Walk finished successfully: {:?}",
                                    res.peers
                                );
                            }
                            Err(e) => info!("{:?}", e),
                        },
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
