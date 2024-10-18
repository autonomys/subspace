use crate::behavior::persistent_parameters::{
    append_p2p_suffix, remove_p2p_suffix, KnownPeersRegistry, PeerAddressRemovedEvent,
};
use crate::behavior::{Behavior, Event};
use crate::constructor;
use crate::constructor::temporary_bans::TemporaryBans;
use crate::constructor::LocalOnlyRecordStore;
use crate::protocols::request_response::request_response_factory::{
    Event as RequestResponseEvent, IfDisconnected,
};
use crate::shared::{Command, CreatedSubscription, PeerDiscovered, Shared};
use crate::utils::{is_global_address_or_dns, strip_peer_id, SubspaceMetrics};
use async_mutex::Mutex as AsyncMutex;
use bytes::Bytes;
use event_listener_primitives::HandlerId;
use futures::channel::mpsc;
use futures::future::Fuse;
use futures::{FutureExt, StreamExt};
use libp2p::autonat::{Event as AutonatEvent, NatStatus, OutboundProbeEvent};
use libp2p::core::ConnectedPoint;
use libp2p::gossipsub::{Event as GossipsubEvent, TopicHash};
use libp2p::identify::Event as IdentifyEvent;
use libp2p::kad::{
    Behaviour as Kademlia, BootstrapOk, Event as KademliaEvent, GetClosestPeersError,
    GetClosestPeersOk, GetProvidersError, GetProvidersOk, GetRecordError, GetRecordOk,
    InboundRequest, KBucketKey, PeerRecord, ProgressStep, PutRecordOk, QueryId, QueryResult,
    Quorum, Record, RecordKey,
};
use libp2p::metrics::{Metrics, Recorder};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{DialError, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Swarm, TransportError};
use nohash_hasher::IntMap;
use parking_lot::Mutex;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::yield_now;
use tokio::time::Sleep;
use tracing::{debug, error, trace, warn};

enum QueryResultSender {
    Value {
        sender: mpsc::UnboundedSender<PeerRecord>,
        // Just holding onto permit while data structure is not dropped
        _permit: OwnedSemaphorePermit,
    },
    ClosestPeers {
        sender: mpsc::UnboundedSender<PeerId>,
        // Just holding onto permit while data structure is not dropped
        _permit: Option<OwnedSemaphorePermit>,
    },
    Providers {
        key: RecordKey,
        sender: mpsc::UnboundedSender<PeerId>,
        // Just holding onto permit while data structure is not dropped
        _permit: Option<OwnedSemaphorePermit>,
    },
    PutValue {
        sender: mpsc::UnboundedSender<()>,
        // Just holding onto permit while data structure is not dropped
        _permit: OwnedSemaphorePermit,
    },
    Bootstrap {
        sender: mpsc::UnboundedSender<()>,
    },
}

#[derive(Debug, Default)]
enum BootstrapCommandState {
    #[default]
    NotStarted,
    InProgress(mpsc::UnboundedReceiver<()>),
    Finished,
}

/// Runner for the Node.
#[must_use = "Node does not function properly unless its runner is driven forward"]
pub struct NodeRunner<LocalRecordProvider>
where
    LocalRecordProvider: constructor::LocalRecordProvider + Send + Sync + 'static,
{
    /// Should non-global addresses be added to the DHT?
    allow_non_global_addresses_in_dht: bool,
    /// Whether node is listening on some addresses
    is_listening: bool,
    command_receiver: mpsc::Receiver<Command>,
    swarm: Swarm<Behavior<LocalOnlyRecordStore<LocalRecordProvider>>>,
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
    /// Defines an interval between periodical tasks.
    periodical_tasks_interval: Pin<Box<Fuse<Sleep>>>,
    /// Manages the networking parameters like known peers and addresses
    known_peers_registry: Box<dyn KnownPeersRegistry>,
    /// Defines set of peers with a permanent connection (and reconnection if necessary).
    reserved_peers: HashMap<PeerId, Multiaddr>,
    /// Temporarily banned peers.
    temporary_bans: Arc<Mutex<TemporaryBans>>,
    /// Libp2p Prometheus metrics.
    libp2p_metrics: Option<Metrics>,
    /// Subspace Prometheus metrics.
    metrics: Option<SubspaceMetrics>,
    /// Mapping from specific peer to ip addresses
    peer_ip_addresses: HashMap<PeerId, HashSet<IpAddr>>,
    /// Defines protocol version for the network peers. Affects network partition.
    protocol_version: String,
    /// Addresses to bootstrap Kademlia network
    bootstrap_addresses: Vec<Multiaddr>,
    /// Ensures a single bootstrap on run() invocation.
    bootstrap_command_state: Arc<AsyncMutex<BootstrapCommandState>>,
    /// Receives an event on peer address removal from the persistent storage.
    removed_addresses_rx: mpsc::UnboundedReceiver<PeerAddressRemovedEvent>,
    /// Optional storage for the [`HandlerId`] of the address removal task.
    /// We keep to stop the task along with the rest of the networking.
    _address_removal_task_handler_id: Option<HandlerId>,
}

impl<LocalRecordProvider> fmt::Debug for NodeRunner<LocalRecordProvider>
where
    LocalRecordProvider: constructor::LocalRecordProvider + Send + Sync + 'static,
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeRunner").finish_non_exhaustive()
    }
}

// Helper struct for NodeRunner configuration (clippy requirement).
pub(crate) struct NodeRunnerConfig<LocalRecordProvider>
where
    LocalRecordProvider: constructor::LocalRecordProvider + Send + Sync + 'static,
{
    pub(crate) allow_non_global_addresses_in_dht: bool,
    /// Whether node is listening on some addresses
    pub(crate) is_listening: bool,
    pub(crate) command_receiver: mpsc::Receiver<Command>,
    pub(crate) swarm: Swarm<Behavior<LocalOnlyRecordStore<LocalRecordProvider>>>,
    pub(crate) shared_weak: Weak<Shared>,
    pub(crate) next_random_query_interval: Duration,
    pub(crate) known_peers_registry: Box<dyn KnownPeersRegistry>,
    pub(crate) reserved_peers: HashMap<PeerId, Multiaddr>,
    pub(crate) temporary_bans: Arc<Mutex<TemporaryBans>>,
    pub(crate) libp2p_metrics: Option<Metrics>,
    pub(crate) metrics: Option<SubspaceMetrics>,
    pub(crate) protocol_version: String,
    pub(crate) bootstrap_addresses: Vec<Multiaddr>,
}

impl<LocalRecordProvider> NodeRunner<LocalRecordProvider>
where
    LocalRecordProvider: constructor::LocalRecordProvider + Send + Sync + 'static,
{
    pub(crate) fn new(
        NodeRunnerConfig {
            allow_non_global_addresses_in_dht,
            is_listening,
            command_receiver,
            swarm,
            shared_weak,
            next_random_query_interval,
            mut known_peers_registry,
            reserved_peers,
            temporary_bans,
            libp2p_metrics,
            metrics,
            protocol_version,
            bootstrap_addresses,
        }: NodeRunnerConfig<LocalRecordProvider>,
    ) -> Self {
        // Setup the address removal events exchange between persistent params storage and Kademlia.
        let (removed_addresses_tx, removed_addresses_rx) = mpsc::unbounded();
        let mut address_removal_task_handler_id = None;
        if let Some(handler_id) = known_peers_registry.on_unreachable_address({
            Arc::new(move |event| {
                if let Err(error) = removed_addresses_tx.unbounded_send(event.clone()) {
                    debug!(?error, ?event, "Cannot send PeerAddressRemovedEvent")
                };
            })
        }) {
            address_removal_task_handler_id.replace(handler_id);
        }

        Self {
            allow_non_global_addresses_in_dht,
            is_listening,
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
            periodical_tasks_interval: Box::pin(tokio::time::sleep(Duration::from_secs(0)).fuse()),
            known_peers_registry,
            reserved_peers,
            temporary_bans,
            libp2p_metrics,
            metrics,
            peer_ip_addresses: HashMap::new(),
            protocol_version,
            bootstrap_addresses,
            bootstrap_command_state: Arc::new(AsyncMutex::new(BootstrapCommandState::default())),
            removed_addresses_rx,
            _address_removal_task_handler_id: address_removal_task_handler_id,
        }
    }

    /// Drives the main networking future forward.
    pub async fn run(&mut self) {
        if self.is_listening {
            // Wait for listen addresses, otherwise we will get ephemeral addresses in external address candidates that
            // we do not want
            loop {
                if self.swarm.listeners().next().is_some() {
                    break;
                }

                if let Some(swarm_event) = self.swarm.next().await {
                    self.register_event_metrics(&swarm_event);
                    self.handle_swarm_event(swarm_event).await;
                } else {
                    break;
                }
            }
        }

        self.bootstrap().await;

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
                        self.register_event_metrics(&swarm_event);
                        self.handle_swarm_event(swarm_event).await;
                    } else {
                        break;
                    }
                },
                command = self.command_receiver.next() => {
                    if let Some(command) = command {
                        self.handle_command(command);
                    } else {
                        break;
                    }
                },
                _ = self.known_peers_registry.run().fuse() => {
                    trace!("Network parameters registry runner exited.")
                },
                _ = &mut self.periodical_tasks_interval => {
                    self.handle_periodical_tasks().await;

                    self.periodical_tasks_interval =
                        Box::pin(tokio::time::sleep(Duration::from_secs(5)).fuse());
                },
                event = self.removed_addresses_rx.select_next_some() => {
                    self.handle_removed_address_event(event);
                },
            }

            // Allow to exit from busy loop during graceful shutdown
            yield_now().await;
        }
    }

    /// Bootstraps Kademlia network
    async fn bootstrap(&mut self) {
        // Add bootstrap nodes first to make sure there is space for them in k-buckets
        for (peer_id, address) in strip_peer_id(self.bootstrap_addresses.clone()) {
            self.swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer_id, address);
        }

        let known_peers = self.known_peers_registry.all_known_peers().await;

        if !known_peers.is_empty() {
            for (peer_id, addresses) in known_peers {
                for address in addresses.clone() {
                    let address = match address.with_p2p(peer_id) {
                        Ok(address) => address,
                        Err(address) => {
                            warn!(%peer_id, %address, "Failed to add peer ID to known peer address");
                            break;
                        }
                    };
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, address);
                }

                if let Err(error) = self
                    .swarm
                    .dial(DialOpts::peer_id(peer_id).addresses(addresses).build())
                {
                    warn!(%peer_id, %error, "Failed to dial peer during bootstrapping");
                }
            }

            // Do bootstrap asynchronously
            self.handle_command(Command::Bootstrap {
                result_sender: None,
            });
            return;
        }

        let bootstrap_command_state = self.bootstrap_command_state.clone();
        let mut bootstrap_command_state = bootstrap_command_state.lock().await;
        let bootstrap_command_receiver = match &mut *bootstrap_command_state {
            BootstrapCommandState::NotStarted => {
                debug!("Bootstrap started.");

                let (bootstrap_command_sender, bootstrap_command_receiver) = mpsc::unbounded();

                self.handle_command(Command::Bootstrap {
                    result_sender: Some(bootstrap_command_sender),
                });

                *bootstrap_command_state =
                    BootstrapCommandState::InProgress(bootstrap_command_receiver);
                match &mut *bootstrap_command_state {
                    BootstrapCommandState::InProgress(bootstrap_command_receiver) => {
                        bootstrap_command_receiver
                    }
                    _ => {
                        unreachable!("Was just set to that exact value");
                    }
                }
            }
            BootstrapCommandState::InProgress(bootstrap_command_receiver) => {
                bootstrap_command_receiver
            }
            BootstrapCommandState::Finished => {
                return;
            }
        };

        let mut bootstrap_step = 0;
        loop {
            futures::select! {
                swarm_event = self.swarm.next() => {
                    if let Some(swarm_event) = swarm_event {
                        self.register_event_metrics(&swarm_event);
                        self.handle_swarm_event(swarm_event).await;
                    } else {
                        break;
                    }
                },
                result = bootstrap_command_receiver.next() => {
                    if result.is_some() {
                        debug!(%bootstrap_step, "Kademlia bootstrapping...");
                        bootstrap_step += 1;
                    } else {
                        break;
                    }
                }
            }
        }

        debug!("Bootstrap finished.");
        *bootstrap_command_state = BootstrapCommandState::Finished;
    }

    /// Handles periodical tasks.
    async fn handle_periodical_tasks(&mut self) {
        // Log current connections.
        let network_info = self.swarm.network_info();
        let connections = network_info.connection_counters();

        debug!(?connections, "Current connections and limits.");

        // Renew known external addresses.
        let mut external_addresses = self.swarm.external_addresses().cloned().collect::<Vec<_>>();

        if let Some(shared) = self.shared_weak.upgrade() {
            debug!(?external_addresses, "Renew external addresses.",);
            let mut addresses = shared.external_addresses.lock();
            addresses.clear();
            addresses.append(&mut external_addresses);
        }

        self.log_kademlia_stats();
    }

    fn handle_random_query_interval(&mut self) {
        let random_peer_id = PeerId::random();

        trace!("Starting random Kademlia query for {}", random_peer_id);

        self.swarm
            .behaviour_mut()
            .kademlia
            .get_closest_peers(random_peer_id);
    }

    fn handle_removed_address_event(&mut self, event: PeerAddressRemovedEvent) {
        trace!(?event, "Peer addressed removed event.",);

        let bootstrap_node_ids = strip_peer_id(self.bootstrap_addresses.clone())
            .into_iter()
            .map(|(peer_id, _)| peer_id)
            .collect::<Vec<_>>();

        if bootstrap_node_ids.contains(&event.peer_id) {
            debug!(
                ?event,
                ?bootstrap_node_ids,
                "Skipped removing bootstrap node from Kademlia buckets."
            );

            return;
        }

        // Remove both versions of the address
        self.swarm.behaviour_mut().kademlia.remove_address(
            &event.peer_id,
            &append_p2p_suffix(event.peer_id, event.address.clone()),
        );

        self.swarm
            .behaviour_mut()
            .kademlia
            .remove_address(&event.peer_id, &remove_p2p_suffix(event.address));
    }

    async fn handle_swarm_event(&mut self, swarm_event: SwarmEvent<Event>) {
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
            SwarmEvent::Behaviour(Event::Autonat(event)) => {
                self.handle_autonat_event(event).await;
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
                endpoint,
                num_established,
                ..
            } => {
                // Save known addresses that were successfully dialed.
                if let ConnectedPoint::Dialer { address, .. } = &endpoint {
                    // filter non-global addresses when non-globals addresses are disabled
                    if self.allow_non_global_addresses_in_dht || is_global_address_or_dns(address) {
                        self.known_peers_registry
                            .add_known_peer(peer_id, vec![address.clone()])
                            .await;
                    }
                };

                let shared = match self.shared_weak.upgrade() {
                    Some(shared) => shared,
                    None => {
                        return;
                    }
                };

                let is_reserved_peer = self.reserved_peers.contains_key(&peer_id);
                debug!(
                    %peer_id,
                    %is_reserved_peer,
                    ?endpoint,
                    %num_established,
                    "Connection established"
                );

                let maybe_remote_ip =
                    endpoint
                        .get_remote_address()
                        .iter()
                        .find_map(|protocol| match protocol {
                            Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
                            Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
                            _ => None,
                        });
                if let Some(ip) = maybe_remote_ip {
                    self.peer_ip_addresses
                        .entry(peer_id)
                        .and_modify(|ips| {
                            ips.insert(ip);
                        })
                        .or_insert(HashSet::from([ip]));
                }

                let num_established_peer_connections = shared
                    .num_established_peer_connections
                    .fetch_add(1, Ordering::SeqCst)
                    + 1;

                shared
                    .handlers
                    .num_established_peer_connections_change
                    .call_simple(&num_established_peer_connections);

                // A new connection
                if num_established.get() == 1 {
                    shared.handlers.connected_peer.call_simple(&peer_id);
                }

                if let Some(metrics) = self.metrics.as_mut() {
                    metrics.inc_established_connections()
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                cause,
                ..
            } => {
                let shared = match self.shared_weak.upgrade() {
                    Some(shared) => shared,
                    None => {
                        return;
                    }
                };

                debug!(
                    %peer_id,
                    ?cause,
                    %num_established,
                    "Connection closed with peer"
                );

                if num_established == 0 {
                    self.peer_ip_addresses.remove(&peer_id);
                }
                let num_established_peer_connections = shared
                    .num_established_peer_connections
                    .fetch_sub(1, Ordering::SeqCst)
                    - 1;

                shared
                    .handlers
                    .num_established_peer_connections_change
                    .call_simple(&num_established_peer_connections);

                // No more connections
                if num_established == 0 {
                    shared.handlers.disconnected_peer.call_simple(&peer_id);
                }

                if let Some(metrics) = self.metrics.as_mut() {
                    metrics.dec_established_connections()
                };
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer_id) = &peer_id {
                    let should_ban_temporarily =
                        self.should_temporary_ban_on_dial_error(peer_id, &error);

                    trace!(%should_ban_temporarily, "Temporary bans conditions.");

                    if should_ban_temporarily {
                        self.temporary_bans.lock().create_or_extend(peer_id);
                        debug!(%peer_id, ?error, "Peer was temporarily banned.");
                    }
                }

                debug!(
                    ?peer_id,
                    ?error,
                    "SwarmEvent::OutgoingConnectionError for peer."
                );

                match error {
                    DialError::Transport(ref addresses) => {
                        for (addr, _) in addresses {
                            trace!(?error, ?peer_id, %addr, "SwarmEvent::OutgoingConnectionError (DialError::Transport) for peer.");
                            if let Some(peer_id) = peer_id {
                                self.known_peers_registry
                                    .remove_known_peer_addresses(peer_id, vec![addr.clone()])
                                    .await;
                            }
                        }
                    }
                    DialError::WrongPeerId { obtained, .. } => {
                        trace!(?error, ?peer_id, obtained_peer_id=?obtained, "SwarmEvent::WrongPeerId (DialError::WrongPeerId) for peer.");

                        if let Some(ref peer_id) = peer_id {
                            let kademlia = &mut self.swarm.behaviour_mut().kademlia;
                            let _ = kademlia.remove_peer(peer_id);
                        }
                    }
                    _ => {
                        trace!(?error, ?peer_id, "SwarmEvent::OutgoingConnectionError");
                    }
                }
            }
            SwarmEvent::NewExternalAddrCandidate { address } => {
                trace!(%address, "External address candidate");
            }
            SwarmEvent::ExternalAddrConfirmed { address } => {
                debug!(%address, "Confirmed external address");

                let connected_peers = self.swarm.connected_peers().copied().collect::<Vec<_>>();
                self.swarm.behaviour_mut().identify.push(connected_peers);
            }
            SwarmEvent::ExternalAddrExpired { address } => {
                debug!(%address, "External address expired");

                let connected_peers = self.swarm.connected_peers().copied().collect::<Vec<_>>();
                self.swarm.behaviour_mut().identify.push(connected_peers);
            }
            other => {
                trace!("Other swarm event: {:?}", other);
            }
        }
    }

    fn should_temporary_ban_on_dial_error(&self, peer_id: &PeerId, error: &DialError) -> bool {
        // TODO: Replace with banning of addresses rather peer IDs if this helps
        if true {
            return false;
        }

        // Ban temporarily only peers without active connections.
        if self.swarm.is_connected(peer_id) {
            return false;
        }

        match &error {
            DialError::Transport(addresses) => {
                for (_, error) in addresses {
                    match error {
                        TransportError::MultiaddrNotSupported(_) => {
                            return true;
                        }
                        TransportError::Other(_) => {
                            // Ignore "temporary ban" errors
                            if self.temporary_bans.lock().is_banned(peer_id) {
                                return false;
                            }
                        }
                    }
                }
                // Other errors that are not related to temporary bans
                true
            }
            DialError::LocalPeerId { .. } => {
                // We don't ban ourselves
                debug!("Local peer dial attempt detected.");

                false
            }
            DialError::NoAddresses => {
                // Let's wait until we get addresses
                true
            }
            DialError::DialPeerConditionFalse(_) => {
                // These are local conditions, we don't need to ban remote peers
                false
            }
            DialError::Aborted => {
                // Seems like a transient event
                false
            }
            DialError::WrongPeerId { .. } => {
                // It's likely that peer was restarted with different identity
                false
            }
            DialError::Denied { .. } => {
                // We exceeded the connection limits or we hit a black listed peer
                false
            }
        }
    }

    async fn handle_identify_event(&mut self, event: IdentifyEvent) {
        let local_peer_id = *self.swarm.local_peer_id();

        if let IdentifyEvent::Received {
            peer_id, mut info, ..
        } = event
        {
            debug!(?peer_id, protocols = ?info.protocols, "IdentifyEvent::Received");

            // Check for network partition
            if info.protocol_version != self.protocol_version {
                debug!(
                    %local_peer_id,
                    %peer_id,
                    local_protocol_version = %self.protocol_version,
                    peer_protocol_version = %info.protocol_version,
                    "Peer has different protocol version, banning temporarily",
                );

                self.temporary_bans.lock().create_or_extend(&peer_id);
                // Forget about this peer until they upgrade
                let _ = self.swarm.disconnect_peer_id(peer_id);
                self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
                self.known_peers_registry
                    .remove_all_known_peer_addresses(peer_id);

                return;
            }

            // Remove temporary ban if there was any
            self.temporary_bans.lock().remove(&peer_id);

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
            let full_kademlia_support = kademlia.protocol_names().iter().all(|local_protocol| {
                info.protocols
                    .iter()
                    .any(|remote_protocol| *remote_protocol == *local_protocol)
            });

            if full_kademlia_support {
                let received_addresses = info
                    .listen_addrs
                    .into_iter()
                    .filter(|address| {
                        if self.allow_non_global_addresses_in_dht
                            || is_global_address_or_dns(address)
                        {
                            true
                        } else {
                            trace!(
                                %local_peer_id,
                                %peer_id,
                                %address,
                                "Ignoring self-reported non-global address",
                            );

                            false
                        }
                    })
                    .collect::<Vec<_>>();
                let received_address_strings = received_addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                let old_addresses = kademlia
                    .kbucket(peer_id)
                    .and_then(|peers| {
                        let key = peer_id.into();
                        peers.iter().find_map(|peer| {
                            (peer.node.key == &key).then_some(
                                peer.node
                                    .value
                                    .iter()
                                    .filter(|existing_address| {
                                        let existing_address = existing_address.to_string();

                                        !received_address_strings.iter().any(|received_address| {
                                            received_address.starts_with(&existing_address)
                                                || existing_address.starts_with(received_address)
                                        })
                                    })
                                    .cloned()
                                    .collect::<Vec<_>>(),
                            )
                        })
                    })
                    .unwrap_or_default();

                for address in received_addresses {
                    debug!(
                        %local_peer_id,
                        %peer_id,
                        %address,
                        protocol_names = ?kademlia.protocol_names(),
                        "Adding self-reported address to Kademlia DHT",
                    );

                    kademlia.add_address(&peer_id, address);
                }

                for old_address in old_addresses {
                    trace!(
                        %local_peer_id,
                        %peer_id,
                        %old_address,
                        "Removing old self-reported address from Kademlia DHT",
                    );

                    kademlia.remove_address(&peer_id, &old_address);
                }
            } else {
                debug!(
                    %local_peer_id,
                    %peer_id,
                    peer_protocols = ?info.protocols,
                    protocol_names = ?kademlia.protocol_names(),
                    "Peer doesn't support our Kademlia DHT protocol",
                );

                kademlia.remove_peer(&peer_id);
            }
        }
    }

    async fn handle_kademlia_event(&mut self, event: KademliaEvent) {
        trace!("Kademlia event: {:?}", event);

        match event {
            KademliaEvent::InboundRequest {
                request: InboundRequest::AddProvider { record, .. },
            } => {
                debug!("Unexpected AddProvider request received: {:?}", record);
            }
            KademliaEvent::UnroutablePeer { peer } => {
                debug!(%peer, "Unroutable peer detected");

                self.swarm.behaviour_mut().kademlia.remove_peer(&peer);

                if let Some(shared) = self.shared_weak.upgrade() {
                    shared
                        .handlers
                        .peer_discovered
                        .call_simple(&PeerDiscovered::UnroutablePeer { peer_id: peer });
                }
            }
            KademliaEvent::RoutablePeer { peer, address } => {
                debug!(?address, "Routable peer detected: {:?}", peer);

                if let Some(shared) = self.shared_weak.upgrade() {
                    shared
                        .handlers
                        .peer_discovered
                        .call_simple(&PeerDiscovered::RoutablePeer {
                            peer_id: peer,
                            address,
                        });
                }
            }
            KademliaEvent::PendingRoutablePeer { peer, address } => {
                debug!(?address, "Pending routable peer detected: {:?}", peer);

                if let Some(shared) = self.shared_weak.upgrade() {
                    shared
                        .handlers
                        .peer_discovered
                        .call_simple(&PeerDiscovered::RoutablePeer {
                            peer_id: peer,
                            address,
                        });
                }
            }
            KademliaEvent::OutboundQueryProgressed {
                step: ProgressStep { last, .. },
                id,
                result: QueryResult::GetClosestPeers(result),
                ..
            } => {
                let mut cancelled = false;
                if let Some(QueryResultSender::ClosestPeers { sender, .. }) =
                    self.query_id_receivers.get(&id)
                {
                    match result {
                        Ok(GetClosestPeersOk { key, peers }) => {
                            trace!(
                                "Get closest peers query for {} yielded {} results",
                                hex::encode(key),
                                peers.len(),
                            );

                            if peers.is_empty()
                                // Connected peers collection is not empty.
                                && self.swarm.connected_peers().next().is_some()
                            {
                                debug!("Random Kademlia query has yielded empty list of peers");
                            }

                            for peer in peers {
                                cancelled = Self::unbounded_send_and_cancel_on_error(
                                    &mut self.swarm.behaviour_mut().kademlia,
                                    sender,
                                    peer.peer_id,
                                    "GetClosestPeersOk",
                                    &id,
                                ) || cancelled;
                            }
                        }
                        Err(GetClosestPeersError::Timeout { key, peers }) => {
                            debug!(
                                "Get closest peers query for {} timed out with {} results",
                                hex::encode(key),
                                peers.len(),
                            );

                            for peer in peers {
                                cancelled = Self::unbounded_send_and_cancel_on_error(
                                    &mut self.swarm.behaviour_mut().kademlia,
                                    sender,
                                    peer.peer_id,
                                    "GetClosestPeersError::Timeout",
                                    &id,
                                ) || cancelled;
                            }
                        }
                    }
                }

                if last || cancelled {
                    // There will be no more progress
                    self.query_id_receivers.remove(&id);
                }
            }
            KademliaEvent::OutboundQueryProgressed {
                step: ProgressStep { last, .. },
                id,
                result: QueryResult::GetRecord(result),
                ..
            } => {
                let mut cancelled = false;
                if let Some(QueryResultSender::Value { sender, .. }) =
                    self.query_id_receivers.get(&id)
                {
                    match result {
                        Ok(GetRecordOk::FoundRecord(rec)) => {
                            trace!(
                                key = hex::encode(&rec.record.key),
                                "Get record query succeeded",
                            );

                            cancelled = Self::unbounded_send_and_cancel_on_error(
                                &mut self.swarm.behaviour_mut().kademlia,
                                sender,
                                rec,
                                "GetRecordOk",
                                &id,
                            ) || cancelled;
                        }
                        Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => {
                            trace!("Get record query yielded no results");
                        }
                        Err(error) => match error {
                            GetRecordError::NotFound { key, .. } => {
                                debug!(
                                    key = hex::encode(&key),
                                    "Get record query failed with no results",
                                );
                            }
                            GetRecordError::QuorumFailed { key, records, .. } => {
                                debug!(
                                    key = hex::encode(&key),
                                    "Get record query quorum failed with {} results",
                                    records.len(),
                                );
                            }
                            GetRecordError::Timeout { key } => {
                                debug!(key = hex::encode(&key), "Get record query timed out");
                            }
                        },
                    }
                }

                if last || cancelled {
                    // There will be no more progress
                    self.query_id_receivers.remove(&id);
                }
            }
            KademliaEvent::OutboundQueryProgressed {
                step: ProgressStep { last, .. },
                id,
                result: QueryResult::GetProviders(result),
                ..
            } => {
                let mut cancelled = false;
                if let Some(QueryResultSender::Providers { key, sender, .. }) =
                    self.query_id_receivers.get(&id)
                {
                    match result {
                        Ok(GetProvidersOk::FoundProviders { key, providers }) => {
                            trace!(
                                key = hex::encode(&key),
                                "Get providers query yielded {} results",
                                providers.len(),
                            );

                            for provider in providers {
                                cancelled = Self::unbounded_send_and_cancel_on_error(
                                    &mut self.swarm.behaviour_mut().kademlia,
                                    sender,
                                    provider,
                                    "GetProvidersOk",
                                    &id,
                                ) || cancelled;
                            }
                        }
                        Ok(GetProvidersOk::FinishedWithNoAdditionalRecord { closest_peers }) => {
                            trace!(
                                key = hex::encode(key),
                                closest_peers = %closest_peers.len(),
                                "Get providers query yielded no results"
                            );
                        }
                        Err(error) => {
                            let GetProvidersError::Timeout { key, .. } = error;

                            debug!(
                                key = hex::encode(&key),
                                "Get providers query failed with no results",
                            );
                        }
                    }
                }

                if last || cancelled {
                    // There will be no more progress
                    self.query_id_receivers.remove(&id);
                }
            }
            KademliaEvent::OutboundQueryProgressed {
                step: ProgressStep { last, .. },
                id,
                result: QueryResult::PutRecord(result),
                ..
            } => {
                let mut cancelled = false;
                if let Some(QueryResultSender::PutValue { sender, .. }) =
                    self.query_id_receivers.get(&id)
                {
                    match result {
                        Ok(PutRecordOk { key, .. }) => {
                            trace!("Put record query for {} succeeded", hex::encode(&key));

                            cancelled = Self::unbounded_send_and_cancel_on_error(
                                &mut self.swarm.behaviour_mut().kademlia,
                                sender,
                                (),
                                "PutRecordOk",
                                &id,
                            ) || cancelled;
                        }
                        Err(error) => {
                            debug!(?error, "Put record query failed.",);
                        }
                    }
                }

                if last || cancelled {
                    // There will be no more progress
                    self.query_id_receivers.remove(&id);
                }
            }
            KademliaEvent::OutboundQueryProgressed {
                step: ProgressStep { last, count },
                id,
                result: QueryResult::Bootstrap(result),
                stats,
            } => {
                debug!(?stats, %last, %count, ?id, ?result, "Bootstrap OutboundQueryProgressed step.");

                let mut cancelled = false;
                if let Some(QueryResultSender::Bootstrap { sender }) =
                    self.query_id_receivers.get_mut(&id)
                {
                    match result {
                        Ok(BootstrapOk {
                            peer,
                            num_remaining,
                        }) => {
                            trace!(%peer, %num_remaining, %last, "Bootstrap query step succeeded");

                            cancelled = Self::unbounded_send_and_cancel_on_error(
                                &mut self.swarm.behaviour_mut().kademlia,
                                sender,
                                (),
                                "Bootstrap",
                                &id,
                            ) || cancelled;
                        }
                        Err(error) => {
                            debug!(?error, "Bootstrap query failed.");
                        }
                    }
                }

                if last || cancelled {
                    // There will be no more progress
                    self.query_id_receivers.remove(&id);
                }
            }
            _ => {}
        }
    }

    // Returns `true` if query was cancelled
    fn unbounded_send_and_cancel_on_error<T>(
        kademlia: &mut Kademlia<LocalOnlyRecordStore<LocalRecordProvider>>,
        sender: &mpsc::UnboundedSender<T>,
        value: T,
        channel: &'static str,
        id: &QueryId,
    ) -> bool {
        if sender.unbounded_send(value).is_err() {
            debug!("{} channel was dropped", channel);

            // Cancel query
            if let Some(mut query) = kademlia.query_mut(id) {
                query.finish();
            }
            true
        } else {
            false
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

    async fn handle_autonat_event(&mut self, event: AutonatEvent) {
        trace!(?event, "Autonat event received.");
        let autonat = &self.swarm.behaviour().autonat;
        debug!(
            public_address=?autonat.public_address(),
            confidence=%autonat.confidence(),
            "Current public address confidence."
        );

        match event {
            AutonatEvent::InboundProbe(_inbound_probe_event) => {
                // We do not care about this event
            }
            AutonatEvent::OutboundProbe(outbound_probe_event) => {
                match outbound_probe_event {
                    OutboundProbeEvent::Request { peer, .. } => {
                        // For outbound probe request add peer to allow list to ensure they can dial us back and not hit
                        // global incoming connection limit
                        self.swarm
                            .behaviour_mut()
                            .connection_limits
                            // We expect a single successful dial from this peer
                            .add_to_incoming_allow_list(
                                peer,
                                self.peer_ip_addresses
                                    .get(&peer)
                                    .iter()
                                    .flat_map(|ip_addresses| ip_addresses.iter())
                                    .copied(),
                                1,
                            );
                    }
                    OutboundProbeEvent::Response { peer, .. } => {
                        self.swarm
                            .behaviour_mut()
                            .connection_limits
                            .remove_from_incoming_allow_list(&peer, Some(1));
                    }
                    OutboundProbeEvent::Error { peer, .. } => {
                        if let Some(peer) = peer {
                            self.swarm
                                .behaviour_mut()
                                .connection_limits
                                .remove_from_incoming_allow_list(&peer, Some(1));
                        }
                    }
                }
            }
            AutonatEvent::StatusChanged { old, new } => {
                debug!(?old, ?new, "Public address status changed.");

                // TODO: Remove block once https://github.com/libp2p/rust-libp2p/issues/4863 is resolved
                if let (NatStatus::Public(old_address), NatStatus::Private) = (old, new.clone()) {
                    self.swarm.remove_external_address(&old_address);
                    debug!(
                        ?old_address,
                        new_status = ?new,
                        "Removing old external address...",
                    );

                    // Trigger potential mode change manually
                    self.swarm.behaviour_mut().kademlia.set_mode(None);
                }

                let connected_peers = self.swarm.connected_peers().copied().collect::<Vec<_>>();
                self.swarm.behaviour_mut().identify.push(connected_peers);
            }
        }
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::GetValue {
                key,
                result_sender,
                permit,
            } => {
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_record(key.to_bytes().into());

                self.query_id_receivers.insert(
                    query_id,
                    QueryResultSender::Value {
                        sender: result_sender,
                        _permit: permit,
                    },
                );
            }
            Command::PutValue {
                key,
                value,
                result_sender,
                permit,
            } => {
                let local_peer_id = *self.swarm.local_peer_id();

                let record = Record {
                    key: key.into(),
                    value,
                    publisher: Some(local_peer_id),
                    expires: None, // No time expiration.
                };
                let query_result = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .put_record(record, Quorum::One);

                match query_result {
                    Ok(query_id) => {
                        self.query_id_receivers.insert(
                            query_id,
                            QueryResultSender::PutValue {
                                sender: result_sender,
                                _permit: permit,
                            },
                        );
                    }
                    Err(err) => {
                        warn!(?err, "Failed to put value.");
                    }
                }
            }
            Command::Subscribe {
                topic,
                result_sender,
            } => {
                if !self.swarm.behaviour().gossipsub.is_enabled() {
                    panic!("Gossibsub protocol is disabled.");
                }

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

                        if let Some(gossipsub) = self.swarm.behaviour_mut().gossipsub.as_mut() {
                            match gossipsub.subscribe(&topic) {
                                Ok(true) => {
                                    if result_sender.send(Ok(created_subscription)).is_ok() {
                                        entry
                                            .insert(IntMap::from_iter([(subscription_id, sender)]));
                                    }
                                }
                                Ok(false) => {
                                    panic!(
                                        "Logic error, topic subscription wasn't created, this \
                                        must never happen"
                                    );
                                }
                                Err(error) => {
                                    let _ = result_sender.send(Err(error));
                                }
                            }
                        }
                    }
                }
            }
            Command::Unsubscribe {
                topic,
                subscription_id,
            } => {
                if !self.swarm.behaviour().gossipsub.is_enabled() {
                    panic!("Gossibsub protocol is disabled.");
                }

                if let Entry::Occupied(mut entry) =
                    self.topic_subscription_senders.entry(topic.hash())
                {
                    entry.get_mut().remove(&subscription_id);

                    // If last sender was removed - unsubscribe.
                    if entry.get().is_empty() {
                        entry.remove_entry();

                        if let Some(gossipsub) = self.swarm.behaviour_mut().gossipsub.as_mut() {
                            if let Err(error) = gossipsub.unsubscribe(&topic) {
                                warn!("Failed to unsubscribe from topic {topic}: {error}");
                            }
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
                if !self.swarm.behaviour().gossipsub.is_enabled() {
                    panic!("Gossibsub protocol is disabled.");
                }

                if let Some(gossipsub) = self.swarm.behaviour_mut().gossipsub.as_mut() {
                    // Doesn't matter if receiver still waits for response.
                    let _ =
                        result_sender.send(gossipsub.publish(topic, message).map(|_message_id| ()));
                }
            }
            Command::GetClosestPeers {
                key,
                result_sender,
                permit,
            } => {
                let query_id = self.swarm.behaviour_mut().kademlia.get_closest_peers(key);

                self.query_id_receivers.insert(
                    query_id,
                    QueryResultSender::ClosestPeers {
                        sender: result_sender,
                        _permit: permit,
                    },
                );
            }
            Command::GetClosestLocalPeers {
                key,
                source,
                result_sender,
            } => {
                let source = source.unwrap_or_else(|| *self.swarm.local_peer_id());
                let result = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .find_closest(&KBucketKey::from(key), &source)
                    .into_iter()
                    .filter(|peer| !peer.multiaddrs.is_empty())
                    .map(|peer| (peer.node_id, peer.multiaddrs))
                    .collect();

                // Doesn't matter if receiver still waits for response.
                let _ = result_sender.send(result);
            }
            Command::GenericRequest {
                peer_id,
                addresses,
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
                    addresses,
                );
            }
            Command::GetProviders {
                key,
                result_sender,
                permit,
            } => {
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_providers(key.clone());

                self.query_id_receivers.insert(
                    query_id,
                    QueryResultSender::Providers {
                        key,
                        sender: result_sender,
                        _permit: permit,
                    },
                );
            }
            Command::BanPeer { peer_id } => {
                self.ban_peer(peer_id);
            }
            Command::Dial { address } => {
                let _ = self.swarm.dial(address);
            }
            Command::ConnectedPeers { result_sender } => {
                let connected_peers = self.swarm.connected_peers().cloned().collect();

                let _ = result_sender.send(connected_peers);
            }
            Command::Bootstrap { result_sender } => {
                let kademlia = &mut self.swarm.behaviour_mut().kademlia;

                match kademlia.bootstrap() {
                    Ok(query_id) => {
                        if let Some(result_sender) = result_sender {
                            self.query_id_receivers.insert(
                                query_id,
                                QueryResultSender::Bootstrap {
                                    sender: result_sender,
                                },
                            );
                        }
                    }
                    Err(err) => {
                        debug!(?err, "Bootstrap error.");
                    }
                }
            }
        }
    }

    fn ban_peer(&mut self, peer_id: PeerId) {
        // Remove temporary ban if there is any before creating a permanent one
        self.temporary_bans.lock().remove(&peer_id);

        debug!(?peer_id, "Banning peer on network level");

        self.swarm.behaviour_mut().block_list.block_peer(peer_id);
        self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
        self.known_peers_registry
            .remove_all_known_peer_addresses(peer_id);
    }

    fn register_event_metrics(&mut self, swarm_event: &SwarmEvent<Event>) {
        if let Some(ref mut metrics) = self.libp2p_metrics {
            match swarm_event {
                SwarmEvent::Behaviour(Event::Ping(ping_event)) => {
                    metrics.record(ping_event);
                }
                SwarmEvent::Behaviour(Event::Identify(identify_event)) => {
                    metrics.record(identify_event);
                }
                SwarmEvent::Behaviour(Event::Kademlia(kademlia_event)) => {
                    metrics.record(kademlia_event);
                }
                SwarmEvent::Behaviour(Event::Gossipsub(gossipsub_event)) => {
                    metrics.record(gossipsub_event);
                }
                // TODO: implement in the upstream repository
                // SwarmEvent::Behaviour(Event::RequestResponse(request_response_event)) => {
                //     self.metrics.record(request_response_event);
                // }
                swarm_event => {
                    metrics.record(swarm_event);
                }
            }
        }
    }

    fn log_kademlia_stats(&mut self) {
        let mut peer_counter = 0;
        let mut peer_with_no_address_counter = 0;
        for kbucket in self.swarm.behaviour_mut().kademlia.kbuckets() {
            for entry in kbucket.iter() {
                peer_counter += 1;
                if entry.node.value.len() == 0 {
                    peer_with_no_address_counter += 1;
                }
            }
        }

        debug!(
            peers = %peer_counter,
            peers_with_no_address = %peer_with_no_address_counter,
            "Kademlia stats"
        );
    }
}
