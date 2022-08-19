use crate::behavior::persistent_parameters::NetworkingParametersRegistry;
use crate::behavior::{Behavior, Event};
use crate::request_responses::{Event as RequestResponseEvent, IfDisconnected};
use crate::shared::{Command, CreatedSubscription, Shared};
use crate::utils;
use crate::utils::convert_multiaddresses;
use bytes::Bytes;
use futures::channel::{mpsc, oneshot};
use futures::future::Fuse;
use futures::{FutureExt, StreamExt};
use libp2p::core::ConnectedPoint;
use libp2p::gossipsub::{GossipsubEvent, TopicHash};
use libp2p::identify::IdentifyEvent;
use libp2p::kad::{
    GetClosestPeersError, GetClosestPeersOk, GetRecordError, GetRecordOk, KademliaEvent, QueryId,
    QueryResult, Quorum,
};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{AddressScore, DialError, SwarmEvent};
use libp2p::{futures, Multiaddr, PeerId, Swarm};
use nohash_hasher::IntMap;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Weak;
use std::time::Duration;
use tokio::time::Sleep;
use tracing::{debug, error, trace, warn};

// Defines a threshold for starting new connection attempts to known peers.
const CONNECTED_PEERS_THRESHOLD: usize = 10;
// Defines a protocol name specific for the relay server
const RELAY_HOP_PROTOCOL_NAME: &[u8] = b"/libp2p/circuit/relay/0.2.0/hop";

enum QueryResultSender {
    GetValue {
        sender: oneshot::Sender<Option<Vec<u8>>>,
    },
    GetClosestPeers {
        sender: oneshot::Sender<Vec<PeerId>>,
    },
}

/// Runner for the Node.
#[must_use = "Node does not function properly unless its runner is driven forward"]
pub struct NodeRunner {
    /// Should non-global addresses be added to the DHT?
    allow_non_globals_in_dht: bool,
    is_relay_server: bool,
    command_receiver: mpsc::Receiver<Command>,
    swarm: Swarm<Behavior>,
    shared_weak: Weak<Shared>,
    /// How frequently should random queries be done using Kademlia DHT to populate routing table.
    next_random_query_interval: Duration,
    query_id_receivers: HashMap<QueryId, QueryResultSender>,
    /// Global subscription counter, is assigned to every (logical) subscription and is used for
    /// unsubscribing.
    next_subscription_id: usize,
    /// Topic subscription senders for logical subscriptions (multiple logical subscriptions can be
    /// present for the same physical subscription).
    topic_subscription_senders: HashMap<TopicHash, IntMap<usize, mpsc::UnboundedSender<Bytes>>>,
    random_query_timeout: Pin<Box<Fuse<Sleep>>>,
    /// Defines a timeout between swarm attempts to dial known addresses
    peer_dialing_timeout: Pin<Box<Fuse<Sleep>>>,
    /// Manages the networking parameters like known peers and addresses
    networking_parameters_registry: Box<dyn NetworkingParametersRegistry>,
    /// Defines set of peers with a permanent connection (and reconnection if necessary).
    reserved_peers: Vec<Multiaddr>,
}

// Helper struct for NodeRunner configuration (clippy requirement).
pub(crate) struct NodeRunnerConfig {
    pub allow_non_globals_in_dht: bool,
    pub is_relay_server: bool,
    pub command_receiver: mpsc::Receiver<Command>,
    pub swarm: Swarm<Behavior>,
    pub shared_weak: Weak<Shared>,
    pub next_random_query_interval: Duration,
    pub networking_parameters_registry: Box<dyn NetworkingParametersRegistry>,
    pub reserved_peers: Vec<Multiaddr>,
}

impl NodeRunner {
    pub(crate) fn new(
        NodeRunnerConfig {
            allow_non_globals_in_dht,
            is_relay_server,
            command_receiver,
            swarm,
            shared_weak,
            next_random_query_interval,
            networking_parameters_registry,
            reserved_peers,
        }: NodeRunnerConfig,
    ) -> Self {
        Self {
            allow_non_globals_in_dht,
            is_relay_server,
            command_receiver,
            swarm,
            shared_weak,
            next_random_query_interval,
            query_id_receivers: HashMap::default(),
            next_subscription_id: 0,
            topic_subscription_senders: HashMap::default(),
            // We'll make the first query right away and continue at the interval.
            random_query_timeout: Box::pin(tokio::time::sleep(Duration::from_secs(0)).fuse()),
            // We'll make the first dial right away and continue at the interval.
            peer_dialing_timeout: Box::pin(tokio::time::sleep(Duration::from_secs(0)).fuse()),
            networking_parameters_registry,
            reserved_peers,
        }
    }

    pub async fn run(&mut self) {
        loop {
            futures::select! {
                _ = &mut self.random_query_timeout => {
                    self.handle_random_query_interval();
                    // Increase interval 2x, but to at most 60 seconds.
                    self.random_query_timeout =
                        Box::pin(tokio::time::sleep(self.next_random_query_interval).fuse());
                    self.next_random_query_interval =
                        (self.next_random_query_interval * 2).min(Duration::from_secs(60));
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
                _ = self.networking_parameters_registry.run().fuse() => {
                    trace!("Network parameters registry runner exited.")
                },
                //TODO: consider changing this worker to the reactive approach (using the connection
                // closing events to maintain established connections set).
                _ = &mut self.peer_dialing_timeout => {
                    self.handle_peer_dialing().await;

                    self.peer_dialing_timeout =
                        Box::pin(tokio::time::sleep(Duration::from_secs(3)).fuse());
                },
            }
        }
    }

    async fn handle_peer_dialing(&mut self) {
        let local_peer_id = *self.swarm.local_peer_id();
        let connected_peers = self.swarm.connected_peers().cloned().collect::<Vec<_>>();

        // Handle reserved peers first.
        if !self.reserved_peers.is_empty() {
            trace!(%local_peer_id, "Checking reserved peers connection: {:?}", self.reserved_peers);

            let reserved_peers = HashMap::<PeerId, Multiaddr>::from_iter(
                convert_multiaddresses(self.reserved_peers.clone()).into_iter(),
            );
            let connected_peers_id_set = HashSet::from_iter(connected_peers.clone());
            let reserved_peers_id_set = reserved_peers.keys().cloned().collect::<HashSet<_>>();

            let missing_reserved_peer_ids =
                reserved_peers_id_set.difference(&connected_peers_id_set);

            for peer_id in missing_reserved_peer_ids {
                if let Some(addr) = reserved_peers.get(peer_id) {
                    self.dial_peer(*peer_id, addr.clone());
                }
            }
        }

        // Maintain minimum connected peers number.
        if connected_peers.len() < CONNECTED_PEERS_THRESHOLD {
            debug!(
                %local_peer_id,
                connected_peers=connected_peers.len(),
                "Initiate connection to known peers",
            );

            let addresses = self
                .networking_parameters_registry
                .next_known_addresses_batch()
                .await;

            trace!(%local_peer_id, "Processing addresses batch: {:?}", addresses);

            for (peer_id, addr) in addresses {
                if connected_peers.contains(&peer_id) {
                    continue;
                }

                self.dial_peer(peer_id, addr)
            }
        }
    }

    fn dial_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        let local_peer_id = *self.swarm.local_peer_id();
        trace!(%local_peer_id, remote_peer_id=%peer_id, %addr, "Dialing address ...");

        let dial_opts = DialOpts::peer_id(peer_id)
            .addresses(vec![addr.clone()])
            .build();

        if let Err(err) = self.swarm.dial(dial_opts) {
            warn!(
                %err,
                %local_peer_id,
                remote_peer_id = %peer_id,
                %addr,
                "Unexpected error: failed to dial an address."
            );
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
            SwarmEvent::Behaviour(Event::RequestResponse(event)) => {
                self.handle_request_response_event(event).await;
            }
            SwarmEvent::Behaviour(Event::Relay(event)) => {
                trace!("Relay event: {:?}", event);
            }
            SwarmEvent::Behaviour(Event::RelayClient(event)) => {
                trace!("Relay Client event: {:?}", event);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                let shared = match self.shared_weak.upgrade() {
                    Some(shared) => shared,
                    None => {
                        return;
                    }
                };
                shared.listeners.lock().push(address.clone());
                if matches!(address.iter().next(), Some(Protocol::Memory(_))) {
                    // This is necessary for local connections using circuit relay
                    if self.is_relay_server {
                        self.swarm
                            .add_external_address(address.clone(), AddressScore::Infinite);
                    }
                } else {
                    // TODO: Add support for public address for add_external_address, AutoNAT
                }
                shared.handlers.new_listener.call_simple(&address);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                endpoint,
                ..
            } => {
                debug!("Connection established with peer {peer_id} [{num_established} from peer]");

                if let ConnectedPoint::Dialer { address, .. } = endpoint {
                    self.networking_parameters_registry
                        .add_known_peer(peer_id, vec![address])
                        .await;
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                debug!("Connection closed with peer {peer_id} [{num_established} from peer]");
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error } => {
                if let DialError::Transport(ref addresses) = error {
                    for (addr, _) in addresses {
                        debug!(?error, ?peer_id, %addr, "SwarmEvent::OutgoingConnectionError for peer.");
                        if let Some(peer_id) = peer_id {
                            self.networking_parameters_registry
                                .remove_known_peer_addresses(peer_id, vec![addr.clone()])
                                .await;
                        }
                    }
                } else {
                    trace!(?error, ?peer_id, "SwarmEvent::OutgoingConnectionError");
                }
            }
            other => {
                trace!("Other swarm event: {:?}", other);
            }
        }
    }

    async fn handle_identify_event(&mut self, event: IdentifyEvent) {
        if let IdentifyEvent::Received { peer_id, mut info } = event {
            let local_peer_id = *self.swarm.local_peer_id();

            if info.listen_addrs.len() > 30 {
                debug!(
                    %local_peer_id,
                    %peer_id,
                    "Node has reported more than 30 addresses; it is identified by {} and {}",
                    info.protocol_version, info.agent_version
                );
                info.listen_addrs.truncate(30);
            }

            let kademlia = &mut self.swarm.behaviour_mut().kademlia;
            let kademlia_enabled = info
                .protocols
                .iter()
                .any(|protocol| protocol.as_bytes() == kademlia.protocol_name());
            let relay_server_enabled = info
                .protocols
                .iter()
                .any(|protocol| protocol.as_bytes() == RELAY_HOP_PROTOCOL_NAME);

            let proper_protocols_supported = !relay_server_enabled && kademlia_enabled;
            if proper_protocols_supported {
                for address in info.listen_addrs {
                    if !self.allow_non_globals_in_dht && !utils::is_global_address_or_dns(&address)
                    {
                        trace!(
                            %local_peer_id,
                            %peer_id,
                            %address,
                            "Ignoring self-reported non-global address.",
                        );
                        continue;
                    }

                    trace!(
                        %local_peer_id,
                        %peer_id,
                        %address,
                        "Adding self-reported address to Kademlia DHT ({}).",
                        String::from_utf8_lossy(kademlia.protocol_name()),
                    );
                    kademlia.add_address(&peer_id, address);
                }
            } else {
                if !kademlia_enabled {
                    trace!(
                        %local_peer_id,
                        %peer_id,
                        "Peer doesn't support our Kademlia DHT protocol ({}). Adding to the DTH skipped.",
                        String::from_utf8_lossy(kademlia.protocol_name())
                    )
                }

                if relay_server_enabled {
                    trace!(
                        %local_peer_id,
                        %peer_id,
                        "Peer identified as a relay server. Adding to the DHT skipped.",
                    )
                }
            }
        }
    }

    async fn handle_kademlia_event(&mut self, event: KademliaEvent) {
        trace!("Kademlia event: {:?}", event);

        match event {
            KademliaEvent::OutboundQueryCompleted {
                id,
                result: QueryResult::GetClosestPeers(results),
                ..
            } => {
                if let Some(QueryResultSender::GetClosestPeers { sender }) =
                    self.query_id_receivers.remove(&id)
                {
                    match results {
                        Ok(GetClosestPeersOk { key, peers }) => {
                            trace!(
                                "Get closest peers query for {} yielded {} results",
                                hex::encode(&key),
                                peers.len(),
                            );

                            if peers.is_empty()
                                // Connected peers collection is not empty.
                                && self.swarm.connected_peers().next().is_some()
                            {
                                debug!("Random Kademlia query has yielded empty list of peers");
                            }

                            if sender.send(peers).is_err() {
                                debug!("GetClosestPeersOk channel was dropped");
                            }
                        }
                        Err(GetClosestPeersError::Timeout { key, peers }) => {
                            if sender.send(Vec::new()).is_err() {
                                debug!("GetClosestPeersOk channel was dropped");
                            }

                            debug!(
                                "Get closest peers query for {} timed out with {} results",
                                hex::encode(&key),
                                peers.len(),
                            );
                        }
                    }
                }
            }
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
                // Ignore other events.
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

    async fn handle_request_response_event(&mut self, event: RequestResponseEvent) {
        // No actions on statistics events.
        trace!("Request response event: {:?}", event);
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::GetValue { key, result_sender } => {
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
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
            Command::GetClosestPeers { key, result_sender } => {
                let query_id = self.swarm.behaviour_mut().kademlia.get_closest_peers(key);

                self.query_id_receivers.insert(
                    query_id,
                    QueryResultSender::GetClosestPeers {
                        sender: result_sender,
                    },
                );
            }
            Command::GenericRequest {
                peer_id,
                protocol_name,
                request,
                result_sender,
            } => {
                self.swarm.behaviour_mut().request_response.send_request(
                    &peer_id,
                    protocol_name,
                    request,
                    result_sender,
                    IfDisconnected::TryConnect,
                );
            }
            Command::CheckConnectedPeers { result_sender } => {
                let connected_peers_present = self.swarm.connected_peers().next().is_some();

                let kademlia_connection_initiated = if connected_peers_present {
                    self.swarm.behaviour_mut().kademlia.bootstrap().is_ok()
                } else {
                    false
                };

                let _ = result_sender.send(kademlia_connection_initiated);
            }
        }
    }
}
