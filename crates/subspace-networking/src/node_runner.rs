use crate::behavior::{Behavior, Event};
use crate::shared::{Command, CreatedSubscription, Shared};
use crate::utils;
use bytes::Bytes;
use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, StreamExt};
use libp2p::gossipsub::{GossipsubEvent, TopicHash};
use libp2p::identify::IdentifyEvent;
use libp2p::kad::{
    GetClosestPeersError, GetClosestPeersOk, GetRecordError, GetRecordOk, KademliaEvent, QueryId,
    QueryResult, Quorum,
};
use libp2p::swarm::SwarmEvent;
use libp2p::{futures, PeerId, Swarm};
use nohash_hasher::IntMap;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, trace, warn};

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
    /// Global subscription counter, is assigned to every (logical) subscription and is used for
    /// unsubscribing.
    next_subscription_id: usize,
    /// Topic subscription senders for logical subscriptions (multiple logical subscriptions can be
    /// present for the same physical subscription).
    topic_subscription_senders: HashMap<TopicHash, IntMap<usize, mpsc::UnboundedSender<Bytes>>>,
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
            next_subscription_id: 0,
            topic_subscription_senders: HashMap::default(),
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

        trace!("Starting random Kademlia query for {}", random_peer_id);

        self.swarm
            .behaviour_mut()
            .kademlia
            .get_closest_peers(random_peer_id);
    }

    async fn handle_swarm_event<E: std::fmt::Debug>(&mut self, swarm_event: SwarmEvent<Event, E>) {
        match swarm_event {
            SwarmEvent::Behaviour(Event::Identify(event)) => {
                self.handle_identify_event(event).await;
            }
            SwarmEvent::Behaviour(Event::Kademlia(event)) => {
                self.handle_kademlia_event(event).await;
            }
            SwarmEvent::Behaviour(Event::Gossipsub(event)) => {
                self.handle_gossipsub_event(event).await;
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                self.shared.listeners.lock().push(address.clone());
                self.shared.handlers.new_listener.call_simple(&address);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                ..
            } => {
                debug!("Connection established with peer {peer_id} [{num_established} from peer]");
                self.shared
                    .connected_peers_count
                    .fetch_add(1, Ordering::SeqCst);
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                debug!("Connection closed with peer {peer_id} [{num_established} from peer]");

                self.shared
                    .connected_peers_count
                    .fetch_sub(1, Ordering::SeqCst);
            }
            other => {
                trace!("Other swarm event: {:?}", other);
            }
        }
    }

    async fn handle_identify_event(&mut self, event: IdentifyEvent) {
        if let IdentifyEvent::Received { peer_id, mut info } = event {
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
                    if !self.allow_non_globals_in_dht && !utils::is_global_address_or_dns(&address)
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
    }

    async fn handle_kademlia_event(&mut self, event: KademliaEvent) {
        trace!("Kademlia event: {:?}", event);

        match event {
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

                            // Doesn't matter if receiver still waits for response.
                            let _ = sender.send(Some(record.value));
                        }
                        Err(error) => {
                            // Doesn't matter if receiver still waits for response.
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

    async fn handle_gossipsub_event(&mut self, event: GossipsubEvent) {
        if let GossipsubEvent::Message { message, .. } = event {
            if let Some(senders) = self.topic_subscription_senders.get(&message.topic) {
                let bytes = Bytes::from(message.data);

                for sender in senders.values() {
                    // Doesn't matter if receiver is still listening for messages or not.
                    let _ = sender.unbounded_send(bytes.clone());
                }
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
                    .get_record(key.to_bytes().into(), Quorum::One);

                self.query_id_receivers.insert(
                    query_id,
                    QueryResultSender::GetValue {
                        sender: result_sender,
                    },
                );
            }
            Command::Subscribe {
                topic,
                result_sender,
            } => {
                let topic_hash = topic.hash();
                let (sender, receiver) = mpsc::unbounded();

                // Unconditionally create subscription ID, code is simpler this way.
                let subscription_id = self.next_subscription_id;
                self.next_subscription_id += 1;

                let created_subscription = CreatedSubscription {
                    subscription_id,
                    receiver,
                };

                match self.topic_subscription_senders.entry(topic_hash) {
                    Entry::Occupied(mut entry) => {
                        // In case subscription already exists, just add one more sender to it.
                        if result_sender.send(Ok(created_subscription)).is_ok() {
                            entry.get_mut().insert(subscription_id, sender);
                        }
                    }
                    Entry::Vacant(entry) => {
                        // Otherwise subscription needs to be created.

                        match self.swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                            Ok(true) => {
                                if result_sender.send(Ok(created_subscription)).is_ok() {
                                    entry.insert(IntMap::from_iter([(subscription_id, sender)]));
                                }
                            }
                            Ok(false) => {
                                panic!(
                                    "Logic error, topic subscription wasn't created, this must never \
                            happen"
                                );
                            }
                            Err(error) => {
                                let _ = result_sender.send(Err(error));
                            }
                        }
                    }
                }
            }
            Command::Unsubscribe {
                topic,
                subscription_id,
            } => {
                if let Entry::Occupied(mut entry) =
                    self.topic_subscription_senders.entry(topic.hash())
                {
                    entry.get_mut().remove(&subscription_id);

                    // If last sender was removed - unsubscribe.
                    if entry.get().is_empty() {
                        entry.remove_entry();

                        if let Err(error) = self.swarm.behaviour_mut().gossipsub.unsubscribe(&topic)
                        {
                            warn!("Failed to unsubscribe from topic {topic}: {error}");
                        }
                    }
                } else {
                    error!(
                        "Can't unsubscribe from topic {topic} because subscription doesn't exist, \
                        this is a logic error in the library"
                    );
                }
            }
            Command::Publish {
                topic,
                message,
                result_sender,
            } => {
                // Doesn't matter if receiver still waits for response.
                let _ = result_sender.send(
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(topic, message)
                        .map(|_message_id| ()),
                );
            }
        }
    }
}
