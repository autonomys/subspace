use crate::behavior::{Behavior, Event};
use crate::shared::{Command, Shared};
use crate::utils;
use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, StreamExt};
use libp2p::identify::IdentifyEvent;
use libp2p::kad::{
    GetClosestPeersError, GetClosestPeersOk, GetRecordError, GetRecordOk, KademliaEvent, QueryId,
    QueryResult, Quorum,
};
use libp2p::swarm::SwarmEvent;
use libp2p::{futures, PeerId, Swarm};
use log::{debug, trace};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

enum QueryResultSender {
    GetValue {
        sender: oneshot::Sender<Option<Vec<u8>>>,
    },
}

/// Runner for the Node.
#[must_use = "Node does not function properly unless its runner is driven forward"]
pub struct NodeRunner {
    /// Should non-global addresses be added to the DHT?
    allow_non_globals_in_dht: bool,
    command_receiver: mpsc::Receiver<Command>,
    swarm: Swarm<Behavior>,
    shared: Arc<Shared>,
    /// How frequently should random queries be done using Kademlia DHT to populate routing table.
    next_random_query_interval: Duration,
    query_id_receivers: HashMap<QueryId, QueryResultSender>,
}

impl NodeRunner {
    pub(crate) fn new(
        allow_non_globals_in_dht: bool,
        command_receiver: mpsc::Receiver<Command>,
        swarm: Swarm<Behavior>,
        shared: Arc<Shared>,
        initial_random_query_interval: Duration,
    ) -> Self {
        Self {
            allow_non_globals_in_dht,
            command_receiver,
            swarm,
            shared,
            next_random_query_interval: initial_random_query_interval,
            query_id_receivers: HashMap::default(),
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
                debug!("Kademlia event: {:?}", kademlia_event);

                match kademlia_event {
                    KademliaEvent::OutboundQueryCompleted {
                        result: QueryResult::GetClosestPeers(results),
                        ..
                    } => match results {
                        Ok(GetClosestPeersOk { key, peers }) => {
                            trace!(
                                "Get closest peers query for {} yielded {} results",
                                hex::encode(&key),
                                peers.len(),
                            );

                            if peers.is_empty()
                                && self.shared.connected_peers_count.load(Ordering::Relaxed) != 0
                            {
                                debug!("Random Kademlia query has yielded empty list of peers");
                            }
                        }
                        Err(GetClosestPeersError::Timeout { key, peers }) => {
                            debug!(
                                "Get closest peers query for {} timed out with {} results",
                                hex::encode(&key),
                                peers.len(),
                            );
                        }
                    },
                    KademliaEvent::OutboundQueryCompleted {
                        id,
                        result: QueryResult::GetRecord(results),
                        ..
                    } => {
                        if let Some(QueryResultSender::GetValue { sender }) =
                            self.query_id_receivers.remove(&id)
                        {
                            match results {
                                Ok(GetRecordOk { records, .. }) => {
                                    let records_len = records.len();
                                    let record = records
                                        .into_iter()
                                        .next()
                                        .expect("Success means we have at least one record")
                                        .record;

                                    trace!(
                                        "Get record query for {} yielded {} results",
                                        hex::encode(&record.key),
                                        records_len,
                                    );

                                    // We don't care if receiver still waits for response.
                                    let _ = sender.send(Some(record.value));
                                }
                                Err(error) => {
                                    // We don't care if receiver still waits for response.
                                    let _ = sender.send(None);

                                    match error {
                                        GetRecordError::NotFound { key, .. } => {
                                            debug!(
                                                "Get record query for {} failed with no results",
                                                hex::encode(&key),
                                            );
                                        }
                                        GetRecordError::QuorumFailed { key, records, .. } => {
                                            debug!(
                                                "Get record query quorum for {} failed with {} results",
                                                hex::encode(&key),
                                                records.len(),
                                            );
                                        }
                                        GetRecordError::Timeout { key, records, .. } => {
                                            debug!(
                                                "Get record query for {} timed out with {} results",
                                                hex::encode(&key),
                                                records.len(),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        // TODO
                    }
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                self.shared.listeners.lock().push(address.clone());
                self.shared.handlers.new_listener.call_simple(&address);
            }
            SwarmEvent::ConnectionEstablished { .. } => {
                self.shared
                    .connected_peers_count
                    .fetch_add(1, Ordering::SeqCst);
            }
            SwarmEvent::ConnectionClosed { .. } => {
                self.shared
                    .connected_peers_count
                    .fetch_sub(1, Ordering::SeqCst);
            }
            other => {
                debug!("Other swarm event: {:?}", other);
            }
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::GetValue { key, result_sender } => {
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    // TODO: Will probably want something different and validate data instead.
                    .get_record(&key, Quorum::One);

                self.query_id_receivers.insert(
                    query_id,
                    QueryResultSender::GetValue {
                        sender: result_sender,
                    },
                );
            }
        }
    }
}
