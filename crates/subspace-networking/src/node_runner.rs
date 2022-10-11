use crate::behavior::custom_record_store::CustomRecordStore;
use crate::behavior::persistent_parameters::NetworkingParametersRegistry;
use crate::behavior::{Behavior, Event};
use crate::request_responses::{Event as RequestResponseEvent, IfDisconnected};
use crate::shared::{Command, CreatedSubscription, Shared};
use crate::utils;
use bytes::Bytes;
use futures::channel::{mpsc, oneshot};
use futures::future::Fuse;
use futures::{FutureExt, StreamExt};
use libp2p::core::ConnectedPoint;
use libp2p::gossipsub::{GossipsubEvent, TopicHash};
use libp2p::identify::IdentifyEvent;
use libp2p::kad::{
    AddProviderError, AddProviderOk, GetClosestPeersError, GetClosestPeersOk, GetProvidersError,
    GetProvidersOk, GetRecordError, GetRecordOk, InboundRequest, KademliaEvent, QueryId,
    QueryResult, Quorum,
};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{DialError, SwarmEvent};
use libp2p::{futures, Multiaddr, PeerId, Swarm};
use nohash_hasher::IntMap;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Weak;
use std::time::Duration;
use tokio::time::Sleep;
use tracing::{debug, error, trace, warn};

enum QueryResultSender {
    Value {
        sender: oneshot::Sender<Option<Vec<u8>>>,
    },
    ClosestPeers {
        sender: oneshot::Sender<Vec<PeerId>>,
    },
    Providers {
        sender: oneshot::Sender<Option<Vec<PeerId>>>,
    },
    Announce {
        sender: oneshot::Sender<bool>,
    },
}

/// Runner for the Node.
#[must_use = "Node does not function properly unless its runner is driven forward"]
pub struct NodeRunner<RecordStore = CustomRecordStore>
where
    RecordStore: Send + Sync + for<'a> libp2p::kad::store::RecordStore<'a> + 'static,
{
    /// Should non-global addresses be added to the DHT?
    allow_non_globals_in_dht: bool,
    command_receiver: mpsc::Receiver<Command>,
    swarm: Swarm<Behavior<RecordStore>>,
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
    reserved_peers: HashMap<PeerId, Multiaddr>,
    /// Incoming swarm connection limit.
    max_established_incoming_connections: u32,
    /// Outgoing swarm connection limit.
    max_established_outgoing_connections: u32,
}

// Helper struct for NodeRunner configuration (clippy requirement).
pub(crate) struct NodeRunnerConfig<RecordStore = CustomRecordStore>
where
    RecordStore: Send + Sync + for<'a> libp2p::kad::store::RecordStore<'a> + 'static,
{
    pub allow_non_globals_in_dht: bool,
    pub command_receiver: mpsc::Receiver<Command>,
    pub swarm: Swarm<Behavior<RecordStore>>,
    pub shared_weak: Weak<Shared>,
    pub next_random_query_interval: Duration,
    pub networking_parameters_registry: Box<dyn NetworkingParametersRegistry>,
    pub reserved_peers: HashMap<PeerId, Multiaddr>,
    pub max_established_incoming_connections: u32,
    pub max_established_outgoing_connections: u32,
}

impl<RecordStore> NodeRunner<RecordStore>
where
    RecordStore: Send + Sync + for<'a> libp2p::kad::store::RecordStore<'a> + 'static,
{
    pub(crate) fn new(
        NodeRunnerConfig::<RecordStore> {
            allow_non_globals_in_dht,
            command_receiver,
            swarm,
            shared_weak,
            next_random_query_interval,
            networking_parameters_registry,
            reserved_peers,
            max_established_incoming_connections,
            max_established_outgoing_connections,
        }: NodeRunnerConfig<RecordStore>,
    ) -> Self {
        Self {
            allow_non_globals_in_dht,
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
            max_established_incoming_connections,
            max_established_outgoing_connections,
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

            let connected_peers_id_set = connected_peers.iter().cloned().collect();
            let reserved_peers_id_set = self.reserved_peers.keys().cloned().collect::<HashSet<_>>();

            let missing_reserved_peer_ids =
                reserved_peers_id_set.difference(&connected_peers_id_set);

            // Establish missing connections to reserved peers.
            for peer_id in missing_reserved_peer_ids {
                if let Some(addr) = self.reserved_peers.get(peer_id) {
                    self.dial_peer(*peer_id, addr.clone());
                }
            }
        }

        // Maintain minimum connected out-peers number.
        let outgoing_connections_number = {
            let network_info = self.swarm.network_info();
            let connections = network_info.connection_counters();

            connections.num_pending_outgoing() + connections.num_established_outgoing()
        };
        if outgoing_connections_number < self.max_established_outgoing_connections {
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
            SwarmEvent::NewListenAddr { address, .. } => {
                let shared = match self.shared_weak.upgrade() {
                    Some(shared) => shared,
                    None => {
                        return;
                    }
                };
                shared.listeners.lock().push(address.clone());
                shared.handlers.new_listener.call_simple(&address);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                endpoint,
                ..
            } => {
                let is_reserved_peer = self.reserved_peers.contains_key(&peer_id);
                debug!(%peer_id, %is_reserved_peer, "Connection established [{num_established} from peer]");

                let (in_connections_number, out_connections_number) = {
                    let network_info = self.swarm.network_info();
                    let connections = network_info.connection_counters();

                    (
                        connections.num_established_incoming(),
                        connections.num_established_outgoing(),
                    )
                };

                match endpoint {
                    // In connections
                    ConnectedPoint::Listener { .. } => {
                        // check connections limit for non-reserved peers
                        if !is_reserved_peer
                            && in_connections_number > self.max_established_incoming_connections
                        {
                            debug!(
                                %peer_id,
                                "Incoming connections limit exceeded. Disconnecting in-peer ..."
                            );
                            // Error here means: "peer was already disconnected"
                            let _ = self.swarm.disconnect_peer_id(peer_id);
                        }
                    }
                    // Out connections
                    ConnectedPoint::Dialer { address, .. } => {
                        self.networking_parameters_registry
                            .add_known_peer(peer_id, vec![address])
                            .await;

                        // check connections limit for non-reserved peers
                        if !is_reserved_peer
                            && out_connections_number > self.max_established_outgoing_connections
                        {
                            debug!(
                                %peer_id,
                                "Outgoing connections limit exceeded. Disconnecting out-peer ..."
                            );
                            // Error here means: "peer was already disconnected"
                            let _ = self.swarm.disconnect_peer_id(peer_id);
                        }
                    }
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

            if kademlia_enabled {
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
                trace!(
                    %local_peer_id,
                    %peer_id,
                    "Peer doesn't support our Kademlia DHT protocol ({}). Adding to the DTH skipped.",
                    String::from_utf8_lossy(kademlia.protocol_name())
                )
            }
        }
    }

    async fn handle_kademlia_event(&mut self, event: KademliaEvent) {
        trace!("Kademlia event: {:?}", event);

        match event {
            KademliaEvent::InboundRequest {
                request: InboundRequest::AddProvider { record },
            } => {
                trace!("Add provider request received: {:?}", record);
                if let Some(record) = record {
                    if let Err(err) = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .store_mut()
                        .add_provider(record.clone())
                    {
                        error!(?err, "Failed to add provider record: {:?}", record);
                    }
                }
            }
            KademliaEvent::OutboundQueryCompleted {
                id,
                result: QueryResult::GetClosestPeers(results),
                ..
            } => {
                if let Some(QueryResultSender::ClosestPeers { sender }) =
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
                if let Some(QueryResultSender::Value { sender }) =
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
            KademliaEvent::OutboundQueryCompleted {
                id,
                result: QueryResult::GetProviders(results),
                ..
            } => {
                if let Some(QueryResultSender::Providers { sender }) =
                    self.query_id_receivers.remove(&id)
                {
                    match results {
                        Ok(GetProvidersOk { key, providers, .. }) => {
                            trace!(
                                "Get providers query for {} yielded {} results",
                                hex::encode(&key),
                                providers.len(),
                            );

                            // Doesn't matter if receiver still waits for response.
                            let _ = sender.send(Some(providers.into_iter().collect()));
                        }
                        Err(error) => {
                            let GetProvidersError::Timeout { key, .. } = error;

                            // Doesn't matter if receiver still waits for response.
                            let _ = sender.send(None);

                            debug!(
                                "Get providers query for {} failed with no results",
                                hex::encode(&key),
                            );
                        }
                    }
                }
            }
            KademliaEvent::OutboundQueryCompleted {
                id,
                result: QueryResult::StartProviding(results),
                ..
            } => {
                if let Some(QueryResultSender::Announce { sender }) =
                    self.query_id_receivers.remove(&id)
                {
                    match results {
                        Ok(AddProviderOk { key }) => {
                            trace!("Start providing query for {} succeeded", hex::encode(&key),);

                            // Doesn't matter if receiver still waits for response.
                            let _ = sender.send(true);
                        }
                        Err(error) => {
                            let AddProviderError::Timeout { key } = error;

                            // Doesn't matter if receiver still waits for response.
                            let _ = sender.send(false);

                            debug!("Start providing query for {} failed.", hex::encode(&key),);
                        }
                    }
                }
            }
            _ => {}
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
                    QueryResultSender::Value {
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
                    QueryResultSender::ClosestPeers {
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
            Command::StartAnnouncing { key, result_sender } => {
                let res = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .start_providing(key.into());

                match res {
                    Ok(query_id) => {
                        self.query_id_receivers.insert(
                            query_id,
                            QueryResultSender::Announce {
                                sender: result_sender,
                            },
                        );
                    }
                    Err(error) => {
                        error!(?key, ?error, "Failed to announce a piece.");

                        let _ = result_sender.send(false);
                    }
                }
            }
            Command::StopAnnouncing { key, result_sender } => {
                self.swarm
                    .behaviour_mut()
                    .kademlia
                    .stop_providing(&key.into());

                let _ = result_sender.send(true);
            }
            Command::GetProviders { key, result_sender } => {
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_providers(key.into());

                self.query_id_receivers.insert(
                    query_id,
                    QueryResultSender::Providers {
                        sender: result_sender,
                    },
                );
            }
        }
    }
}
