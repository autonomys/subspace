use crate::behavior::{Behaviour, Event};
use crate::shared::{Command, Shared};
use crate::utils;
use futures::channel::mpsc;
use futures::{FutureExt, StreamExt};
use libp2p::identify::IdentifyEvent;
use libp2p::swarm::SwarmEvent;
use libp2p::{futures, Multiaddr, PeerId, Swarm};
use log::{debug, trace};
use std::sync::Arc;
use std::time::Duration;

/// Runner for the Node.
#[must_use = "Node does not function properly unless its runner is driven forward"]
pub struct NodeRunner {
    /// Bootstrap or reserved nodes.
    permanent_addresses: Vec<(PeerId, Multiaddr)>,
    /// Should non-global addresses be added to the DHT?
    allow_non_globals_in_dht: bool,
    command_receiver: mpsc::Receiver<Command>,
    swarm: Swarm<Behaviour>,
    shared: Arc<Shared>,
    /// How frequently should random queries be done using Kademlia DHT to populate routing table.
    next_random_query_interval: Duration,
}

impl NodeRunner {
    pub(crate) fn new(
        permanent_addresses: Vec<(PeerId, Multiaddr)>,
        allow_non_globals_in_dht: bool,
        command_receiver: mpsc::Receiver<Command>,
        swarm: Swarm<Behaviour>,
        shared: Arc<Shared>,
        initial_random_query_interval: Duration,
    ) -> Self {
        Self {
            permanent_addresses,
            allow_non_globals_in_dht,
            command_receiver,
            swarm,
            shared,
            next_random_query_interval: initial_random_query_interval,
        }
    }

    pub async fn run(&mut self) {
        // We'll make the first query right away and continue at the interval.
        let mut random_query_timeout = Box::pin(tokio::time::sleep(Duration::from_secs(0)).fuse());

        loop {
            futures::select! {
                _ = random_query_timeout => {
                    self.handle_random_query_interval();
                    // Increase interval 2x, but to at most 60 seconds.
                    random_query_timeout = Box::pin(tokio::time::sleep(self.next_random_query_interval).fuse());
                    self.next_random_query_interval = (self.next_random_query_interval * 2).min(Duration::from_secs(60));
                },
                swarm_event = self.swarm.next() => {
                    if let Some(swarm_event) = swarm_event {
                        self.handle_swarm_event(swarm_event).await;
                    } else {
                        break;
                    }
                },
                command = self.command_receiver.next() => {
                    if let Some(command) = command {
                        self.handle_command(command).await;
                    } else {
                        break;
                    }
                },
            }
        }
    }

    fn handle_random_query_interval(&mut self) {
        let random_peer_id = PeerId::random();

        debug!("Starting random Kademlia query for {}", random_peer_id);

        self.swarm
            .behaviour_mut()
            .kademlia
            .get_closest_peers(random_peer_id);
    }

    async fn handle_swarm_event<E: std::fmt::Debug>(&mut self, swarm_event: SwarmEvent<Event, E>) {
        match swarm_event {
            SwarmEvent::Behaviour(Event::Identify(IdentifyEvent::Received {
                peer_id,
                mut info,
            })) => {
                if info.listen_addrs.len() > 30 {
                    debug!(
                        "Node {} has reported more than 30 addresses; it is identified by {} and {}",
                        peer_id, info.protocol_version, info.agent_version
                    );
                    info.listen_addrs.truncate(30);
                }

                let kademlia = &mut self.swarm.behaviour_mut().kademlia;

                if info
                    .protocols
                    .iter()
                    .any(|protocol| protocol.as_bytes() == kademlia.protocol_name())
                {
                    for address in info.listen_addrs {
                        if !self.allow_non_globals_in_dht
                            && !utils::is_global_address_or_dns(&address)
                        {
                            trace!(
                                "Ignoring self-reported non-global address {} from {}.",
                                address,
                                peer_id
                            );
                            continue;
                        }

                        trace!(
                            "Adding self-reported address {} from {} to Kademlia DHT {}.",
                            address,
                            peer_id,
                            String::from_utf8_lossy(kademlia.protocol_name()),
                        );
                        kademlia.add_address(&peer_id, address);
                    }
                } else {
                    trace!(
                        "{} doesn't support our Kademlia DHT protocol {}",
                        peer_id,
                        String::from_utf8_lossy(kademlia.protocol_name())
                    );
                }
            }
            SwarmEvent::Behaviour(Event::Kademlia(kademlia_event)) => {
                println!("Kademlia event: {:?}", kademlia_event);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                self.shared.listeners.lock().push(address.clone());
                self.shared.handlers.new_listener.call_simple(&address);
            }
            other => {
                println!("Other swarm event: {:?}", other);
            }
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            // TODO
        }
    }
}
