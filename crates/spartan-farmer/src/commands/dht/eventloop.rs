use super::*;
use super::{
    client::{Client, ClientEvent},
    core::{ComposedBehaviour, ComposedEvent},
};

pub struct EventLoop {
    pub swarm: Swarm<ComposedBehaviour>,
    // Channel to receive events from Client.
    client_rx: Receiver<ClientEvent>,
}

impl EventLoop {
    // Create new event loop
    pub fn new(swarm: Swarm<ComposedBehaviour>, client_rx: Receiver<ClientEvent>) -> Self {
        EventLoop { swarm, client_rx }
    }

    // Run event loop. We will use this method to spawn the event loop in a background task.
    pub async fn run(mut self) {
        loop {
            futures::select! {
                client_event = self.client_rx.next() => match client_event {
                    Some(event) => self.handle_event(event),
                    None => {},
                },
                network_event = self.swarm.next() => match network_event {
                    Some(event) => self.handle_network_event(event).await,
                    None => break,
                }
            }
        }
    }

    // The Client will send events to EventLoop using this method.
    fn handle_event(&mut self, event: ClientEvent) {
        if let Err(e) = Client::handle_client_event(self, event) {
            info!("{:?}", e)
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
                    info!("Query ID: {:?}", id);
                    if let libp2p::kad::QueryResult::Bootstrap(result) = result {
                        match result {
                            Ok(res) => {
                                info!("Bootstrapping finished successfully: {:?}", res.peer)
                            }
                            Err(e) => info!("{:?}", e),
                        }
                    }
                }
                KademliaEvent::RoutablePeer { peer, address } => {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer, address);
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
