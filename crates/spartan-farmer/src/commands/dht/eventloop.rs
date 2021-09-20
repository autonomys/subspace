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
                    None => {},
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
                            libp2p::kad::QueryResult::GetClosestPeers(_) => todo!(),
                            libp2p::kad::QueryResult::GetProviders(_) => todo!(),
                            libp2p::kad::QueryResult::StartProviding(_) => todo!(),
                            libp2p::kad::QueryResult::RepublishProvider(_) => todo!(),
                            libp2p::kad::QueryResult::GetRecord(_) => todo!(),
                            libp2p::kad::QueryResult::PutRecord(_) => todo!(),
                            libp2p::kad::QueryResult::RepublishRecord(_) => todo!(),
                        }
                    }
                    KademliaEvent::InboundRequestServed { request: _ } => todo!(),
                    KademliaEvent::UnroutablePeer { peer: _ } => todo!(),
                    KademliaEvent::RoutablePeer {
                        peer: _,
                        address: _,
                    } => todo!(),
                    KademliaEvent::PendingRoutablePeer {
                        peer: _,
                        address: _,
                    } => todo!(),
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
            SwarmEvent::ConnectionClosed {
                peer_id: _,
                endpoint: _,
                num_established: _,
                cause: _,
            } => todo!(),
            SwarmEvent::IncomingConnection {
                local_addr: _,
                send_back_addr: _,
            } => todo!(),
            SwarmEvent::IncomingConnectionError {
                local_addr: _,
                send_back_addr: _,
                error: _,
            } => todo!(),
            SwarmEvent::BannedPeer {
                peer_id: _,
                endpoint: _,
            } => todo!(),
            SwarmEvent::UnreachableAddr {
                peer_id: _,
                address: _,
                error: _,
                attempts_remaining: _,
            } => todo!(),
            SwarmEvent::UnknownPeerUnreachableAddr {
                address: _,
                error: _,
            } => todo!(),
            SwarmEvent::ExpiredListenAddr {
                listener_id: _,
                address: _,
            } => todo!(),
            SwarmEvent::ListenerClosed {
                listener_id: _,
                addresses: _,
                reason: _,
            } => todo!(),
            SwarmEvent::ListenerError {
                listener_id: _,
                error: _,
            } => todo!(),
            SwarmEvent::Dialing(_) => todo!(),
        }
    }
}
