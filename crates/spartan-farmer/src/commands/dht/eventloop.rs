use super::client::{Client, ClientEvent};
use super::core::{ComposedBehaviour, ComposedEvent};
use super::*;

pub struct EventLoop {
    swarm: Swarm<ComposedBehaviour>,
    // Channel to receive events from Client.
    client_rx: Receiver<ClientEvent>,
}

impl EventLoop {
    /// Create new event loop
    pub fn new(swarm: Swarm<ComposedBehaviour>, client_rx: Receiver<ClientEvent>) -> Self {
        EventLoop { swarm, client_rx }
    }

    /// Run event loop. We will use this method to spawn the event loop in a background task.
    pub async fn run(mut self) {
        loop {
            futures::select! {
                client_event = self.client_rx.next() => self.handle_event(client_event.unwrap()),
                network_event = self.swarm.next() => match network_event {
                    Some(event) => self.handle_network_event(event).await,
                    None => break,
                }
            }
        }
    }

    // NOTE: We have to put the handle client event method in the EventLoop impl because it
    // needs access to the swarm.
    fn handle_event(&mut self, event: ClientEvent) {
        Client::handle_client_event(&mut self.swarm, event)
    }

    async fn handle_network_event(&mut self, event: SwarmEvent<ComposedEvent, std::io::Error>) {
        match event {
            SwarmEvent::Behaviour(event) => match event {
                ComposedEvent::Kademlia(event) => match event {
                    KademliaEvent::RoutingUpdated { peer, .. } => {
                        info!("Added new peer to routing table: {:?}", peer)
                    }
                    KademliaEvent::OutboundQueryCompleted { id, result, .. } => {
                        info!("Query ID: {:?}", id);
                        match result {
                            libp2p::kad::QueryResult::Bootstrap(result) => match result {
                                Ok(res) => {
                                    info!("Bootstrapping finished successfully: {:?}", res.peer)
                                }
                                Err(e) => info!("{:?}", e),
                            },
                            _ => {}
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
            },
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Farmer is listening to K-DHT on: {:?}", address)
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint: _,
                num_established: _,
            } => info!("Connected to new peer: {:?}", peer_id),
            _ => {}
        }
    }
}
