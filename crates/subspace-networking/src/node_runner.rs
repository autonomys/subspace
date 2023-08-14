use crate::behavior::persistent_parameters::{
    append_p2p_suffix, remove_p2p_suffix, NetworkingParametersRegistry, PeerAddressRemovedEvent,
    PEERS_ADDRESSES_BATCH_SIZE,
};
use crate::behavior::{
    Behavior, Event, GeneralConnectedPeersInstance, SpecialConnectedPeersInstance,
};
use crate::connected_peers::Event as ConnectedPeersEvent;
use crate::create;
use crate::create::temporary_bans::TemporaryBans;
use crate::create::{
    ConnectedPeersHandler, LocalOnlyRecordStore, KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER,
    REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER,
};
use crate::peer_info::{Event as PeerInfoEvent, PeerInfoSuccess};
use crate::request_responses::{Event as RequestResponseEvent, IfDisconnected};
use crate::shared::{Command, CreatedSubscription, NewPeerInfo, Shared};
use crate::utils::{
    is_global_address_or_dns, strip_peer_id, PeerAddress, ResizableSemaphorePermit,
};
use async_mutex::Mutex as AsyncMutex;
use bytes::Bytes;
use event_listener_primitives::HandlerId;
use futures::channel::mpsc;
use futures::future::Fuse;
use futures::{FutureExt, StreamExt};
use libp2p::autonat::Event as AutonatEvent;
use libp2p::core::{address_translation, ConnectedPoint};
use libp2p::gossipsub::{Event as GossipsubEvent, TopicHash};
use libp2p::identify::Event as IdentifyEvent;
use libp2p::kad::{
    BootstrapOk, GetClosestPeersError, GetClosestPeersOk, GetProvidersError, GetProvidersOk,
    GetRecordError, GetRecordOk, InboundRequest, Kademlia, KademliaEvent, Mode, PeerRecord,
    ProgressStep, PutRecordOk, QueryId, QueryResult, Quorum, Record,
};
use libp2p::metrics::{Metrics, Recorder};
use libp2p::swarm::{DialError, SwarmEvent};
use libp2p::{futures, Multiaddr, PeerId, Swarm, TransportError};
use nohash_hasher::IntMap;
use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::time::Sleep;
use tracing::{debug, error, info, trace, warn};

// Defines a batch size for peer addresses from Kademlia buckets.
const KADEMLIA_PEERS_ADDRESSES_BATCH_SIZE: usize = 20;

/// How many peers should node be connected to before boosting turns on.
///
/// 1 means boosting starts with second peer.
const CONCURRENT_TASKS_BOOST_PEERS_THRESHOLD: NonZeroUsize =
    NonZeroUsize::new(5).expect("Not zero; qed");

enum QueryResultSender {
    Value {
        sender: mpsc::UnboundedSender<PeerRecord>,
        // Just holding onto permit while data structure is not dropped
        _permit: ResizableSemaphorePermit,
    },
    ClosestPeers {
        sender: mpsc::UnboundedSender<PeerId>,
        // Just holding onto permit while data structure is not dropped
        _permit: ResizableSemaphorePermit,
    },
    Providers {
        sender: mpsc::UnboundedSender<PeerId>,
        // Just holding onto permit while data structure is not dropped
        _permit: ResizableSemaphorePermit,
    },
    PutValue {
        sender: mpsc::UnboundedSender<()>,
        // Just holding onto permit while data structure is not dropped
        _permit: ResizableSemaphorePermit,
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
    LocalRecordProvider: create::LocalRecordProvider + Send + Sync + 'static,
{
    /// Should non-global addresses be added to the DHT?
    allow_non_global_addresses_in_dht: bool,
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
    networking_parameters_registry: Box<dyn NetworkingParametersRegistry>,
    /// Defines set of peers with a permanent connection (and reconnection if necessary).
    reserved_peers: HashMap<PeerId, Multiaddr>,
    /// Temporarily banned peers.
    temporary_bans: Arc<Mutex<TemporaryBans>>,
    /// Prometheus metrics.
    metrics: Option<Metrics>,
    /// Mapping from specific peer to number of established connections
    established_connections: HashMap<(PeerId, ConnectedPoint), usize>,
    /// Defines protocol version for the network peers. Affects network partition.
    protocol_version: String,
    /// Defines whether we maintain a persistent connection for common peers.
    general_connection_decision_handler: Option<ConnectedPeersHandler>,
    /// Defines whether we maintain a persistent connection for special peers.
    special_connection_decision_handler: Option<ConnectedPeersHandler>,
    /// Randomness generator used for choosing Kademlia addresses.
    rng: StdRng,
    /// Addresses to bootstrap Kademlia network
    bootstrap_addresses: Vec<Multiaddr>,
    /// Ensures a single bootstrap on run() invocation.
    bootstrap_command_state: Arc<AsyncMutex<BootstrapCommandState>>,
    /// Kademlia mode. None means "automatic mode".
    kademlia_mode: Option<Mode>,
    /// Known external addresses to the local peer. The addresses are added on the swarm start
    /// and enable peer to notify others about its reachable address.
    external_addresses: Vec<Multiaddr>,
    /// Receives an event on peer address removal from the persistent storage.
    removed_addresses_rx: mpsc::UnboundedReceiver<PeerAddressRemovedEvent>,
    /// Optional storage for the [`HandlerId`] of the address removal task.
    /// We keep to stop the task along with the rest of the networking.
    _address_removal_task_handler_id: Option<HandlerId>,
}

// Helper struct for NodeRunner configuration (clippy requirement).
pub(crate) struct NodeRunnerConfig<LocalRecordProvider>
where
    LocalRecordProvider: create::LocalRecordProvider + Send + Sync + 'static,
{
    pub(crate) allow_non_global_addresses_in_dht: bool,
    pub(crate) command_receiver: mpsc::Receiver<Command>,
    pub(crate) swarm: Swarm<Behavior<LocalOnlyRecordStore<LocalRecordProvider>>>,
    pub(crate) shared_weak: Weak<Shared>,
    pub(crate) next_random_query_interval: Duration,
    pub(crate) networking_parameters_registry: Box<dyn NetworkingParametersRegistry>,
    pub(crate) reserved_peers: HashMap<PeerId, Multiaddr>,
    pub(crate) temporary_bans: Arc<Mutex<TemporaryBans>>,
    pub(crate) metrics: Option<Metrics>,
    pub(crate) protocol_version: String,
    pub(crate) general_connection_decision_handler: Option<ConnectedPeersHandler>,
    pub(crate) special_connection_decision_handler: Option<ConnectedPeersHandler>,
    pub(crate) bootstrap_addresses: Vec<Multiaddr>,
    pub(crate) kademlia_mode: Option<Mode>,
    pub(crate) external_addresses: Vec<Multiaddr>,
}

impl<LocalRecordProvider> NodeRunner<LocalRecordProvider>
where
    LocalRecordProvider: create::LocalRecordProvider + Send + Sync + 'static,
{
    pub(crate) fn new(
        NodeRunnerConfig {
            allow_non_global_addresses_in_dht,
            command_receiver,
            swarm,
            shared_weak,
            next_random_query_interval,
            mut networking_parameters_registry,
            reserved_peers,
            temporary_bans,
            metrics,
            protocol_version,
            general_connection_decision_handler,
            special_connection_decision_handler,
            bootstrap_addresses,
            kademlia_mode,
            external_addresses,
        }: NodeRunnerConfig<LocalRecordProvider>,
    ) -> Self {
        // Setup the address removal events exchange between persistent params storage and Kademlia.
        let (removed_addresses_tx, removed_addresses_rx) = mpsc::unbounded();
        let mut address_removal_task_handler_id = None;
        if let Some(handler_id) = networking_parameters_registry.on_unreachable_address({
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
            networking_parameters_registry,
            reserved_peers,
            temporary_bans,
            metrics,
            established_connections: HashMap::new(),
            protocol_version,
            general_connection_decision_handler,
            special_connection_decision_handler,
            rng: StdRng::seed_from_u64(KADEMLIA_PEERS_ADDRESSES_BATCH_SIZE as u64), // any seed
            bootstrap_addresses,
            bootstrap_command_state: Arc::new(AsyncMutex::new(BootstrapCommandState::default())),
            kademlia_mode,
            external_addresses,
            removed_addresses_rx,
            _address_removal_task_handler_id: address_removal_task_handler_id,
        }
    }

    /// Drives the main networking future forward.
    pub async fn run(&mut self) {
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
                _ = self.networking_parameters_registry.run().fuse() => {
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
        }
    }

    /// Bootstraps Kademlia network
    async fn bootstrap(&mut self) {
        let bootstrap_command_state = self.bootstrap_command_state.clone();
        let mut bootstrap_command_state = bootstrap_command_state.lock().await;
        let bootstrap_command_receiver = match &mut *bootstrap_command_state {
            BootstrapCommandState::NotStarted => {
                debug!("Bootstrap started.");

                let (bootstrap_command_sender, bootstrap_command_receiver) = mpsc::unbounded();

                self.handle_command(Command::Bootstrap {
                    result_sender: bootstrap_command_sender,
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

        debug!("Bootstrap started.");

        self.swarm
            .behaviour_mut()
            .kademlia
            .set_mode(self.kademlia_mode);
        debug!("Kademlia mode set: {:?}.", self.kademlia_mode);

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

    async fn handle_swarm_event<E: Debug>(&mut self, swarm_event: SwarmEvent<Event, E>) {
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
            SwarmEvent::Behaviour(Event::PeerInfo(event)) => {
                self.handle_peer_info_event(event).await;
            }
            SwarmEvent::Behaviour(Event::GeneralConnectedPeers(event)) => {
                self.handle_general_connected_peers_event(event).await;
            }
            SwarmEvent::Behaviour(Event::SpecialConnectedPeers(event)) => {
                self.handle_special_connected_peers_event(event).await;
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
                        self.networking_parameters_registry
                            .add_known_peer(peer_id, vec![address.clone()])
                            .await;
                    }
                };

                // Remove temporary ban if there was any
                self.temporary_bans.lock().remove(&peer_id);

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
                    "Connection established [{num_established} from peer]"
                );

                // TODO: Workaround for https://github.com/libp2p/rust-libp2p/discussions/3418
                self.established_connections
                    .entry((peer_id, endpoint))
                    .and_modify(|entry| {
                        *entry += 1;
                    })
                    .or_insert(1);
                let num_established_peer_connections = shared
                    .num_established_peer_connections
                    .fetch_add(1, Ordering::SeqCst)
                    + 1;
                if num_established_peer_connections > CONCURRENT_TASKS_BOOST_PEERS_THRESHOLD.get() {
                    // The peer count exceeded the threshold, bump up the quota.
                    if let Err(error) = shared
                        .kademlia_tasks_semaphore
                        .expand(KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER)
                    {
                        warn!(%error, "Failed to expand Kademlia concurrent tasks");
                    }
                    if let Err(error) = shared
                        .regular_tasks_semaphore
                        .expand(REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER)
                    {
                        warn!(%error, "Failed to expand regular concurrent tasks");
                    }
                }
                shared
                    .handlers
                    .num_established_peer_connections_change
                    .call_simple(&num_established_peer_connections);

                // A new connection
                if num_established.get() == 1 {
                    shared.handlers.connected_peer.call_simple(&peer_id);
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                let shared = match self.shared_weak.upgrade() {
                    Some(shared) => shared,
                    None => {
                        return;
                    }
                };
                debug!("Connection closed with peer {peer_id} [{num_established} from peer]");

                // TODO: Workaround for https://github.com/libp2p/rust-libp2p/discussions/3418
                {
                    match self.established_connections.entry((peer_id, endpoint)) {
                        Entry::Vacant(_) => {
                            // Nothing to do here, we are not aware of the connection being closed
                            warn!(
                                ?peer_id,
                                "Connection closed, but it is not known as open connection, \
                                this is likely a bug in libp2p: \
                                https://github.com/libp2p/rust-libp2p/discussions/3418"
                            );
                            return;
                        }
                        Entry::Occupied(mut entry) => {
                            let value = entry.get_mut();
                            if *value == 1 {
                                entry.remove_entry();
                            } else {
                                *value -= 1;
                            }
                        }
                    };
                }
                let num_established_peer_connections = shared
                    .num_established_peer_connections
                    .fetch_sub(1, Ordering::SeqCst)
                    - 1;
                if num_established_peer_connections == CONCURRENT_TASKS_BOOST_PEERS_THRESHOLD.get()
                {
                    // The previous peer count was over the threshold, reclaim the quota.
                    if let Err(error) = shared
                        .kademlia_tasks_semaphore
                        .shrink(KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER)
                    {
                        warn!(%error, "Failed to shrink Kademlia concurrent tasks");
                    }
                    if let Err(error) = shared
                        .regular_tasks_semaphore
                        .shrink(REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER)
                    {
                        warn!(%error, "Failed to shrink regular concurrent tasks");
                    }
                }
                shared
                    .handlers
                    .num_established_peer_connections_change
                    .call_simple(&num_established_peer_connections);

                // No more connections
                if num_established == 0 {
                    shared.handlers.disconnected_peer.call_simple(&peer_id);
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer_id) = &peer_id {
                    // Create or extend temporary ban, but only if we are not offline
                    if let Some(shared) = self.shared_weak.upgrade() {
                        // One peer is possibly a node peer is connected to, hence expecting more
                        // than one for online status
                        if shared
                            .num_established_peer_connections
                            .load(Ordering::Relaxed)
                            > 1
                        {
                            // Ban temporarily only peers without active connections.
                            if !self.swarm.is_connected(peer_id) {
                                let should_temporary_ban = match &error {
                                    DialError::Transport(addresses) => {
                                        // Ignoring other errors, those are likely temporary ban errors
                                        !matches!(
                                            addresses.first(),
                                            Some((_multiaddr, TransportError::Other(_error)))
                                        )
                                    }
                                    _ => true,
                                };

                                if should_temporary_ban {
                                    self.temporary_bans.lock().create_or_extend(peer_id);
                                    debug!(%peer_id, ?error, "Peer was temporarily banned.");
                                }
                            }
                        }
                    };
                }

                debug!(?peer_id, "SwarmEvent::OutgoingConnectionError for peer.");

                match error {
                    DialError::Transport(ref addresses) => {
                        for (addr, _) in addresses {
                            trace!(?error, ?peer_id, %addr, "SwarmEvent::OutgoingConnectionError (DialError::Transport) for peer.");
                            if let Some(peer_id) = peer_id {
                                self.networking_parameters_registry
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
            other => {
                trace!("Other swarm event: {:?}", other);
            }
        }
    }

    async fn handle_identify_event(&mut self, event: IdentifyEvent) {
        let local_peer_id = *self.swarm.local_peer_id();

        if let IdentifyEvent::Received { peer_id, mut info } = event {
            debug!(?peer_id, protocols=?info.protocols, "IdentifyEvent::Received");

            // Check for network partition
            if info.protocol_version != self.protocol_version {
                debug!(
                    %local_peer_id,
                    %peer_id,
                    local_protocol_version=%self.protocol_version,
                    peer_protocol_version=%info.protocol_version,
                    "Peer has different protocol version. Peer was banned.",
                );

                self.ban_peer(peer_id);
            }

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
                for address in info.listen_addrs {
                    if !self.allow_non_global_addresses_in_dht
                        && !is_global_address_or_dns(&address)
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
                        "Adding self-reported address to Kademlia DHT ({:?}).",
                        kademlia
                            .protocol_names()
                            .iter()
                            .collect::<Vec<_>>(),
                    );
                    kademlia.add_address(&peer_id, address);
                }
            } else {
                debug!(
                    %local_peer_id,
                    %peer_id,
                    peer_protocols=?info.protocols,
                    "Peer doesn't support our Kademlia DHT protocol ({:?}).",
                    kademlia
                        .protocol_names()
                        .iter()
                        .collect::<Vec<_>>(),
                );

                kademlia.remove_peer(&peer_id);
            }

            self.add_observed_external_address(info.observed_addr);
        }
    }

    fn add_observed_external_address(&mut self, observed_addr: Multiaddr) {
        if !self.external_addresses.is_empty() {
            debug!(
                "Observed address wasn't added as external (manual external addresses set): {}",
                observed_addr
            );
            return;
        }

        let Some(listen_addr) = self.swarm.listeners().next() else {
            warn!("Listener addresses are not specified!");
            return;
        };

        let Some(observed_addr) = address_translation(listen_addr, &observed_addr) else {
            warn!(
                ?listen_addr,
                ?observed_addr,
                "Can't translate observed address!"
            );
            return;
        };

        if !self
            .swarm
            .external_addresses()
            .cloned()
            .collect::<Vec<_>>()
            .contains(&observed_addr)
        {
            info!("Added observed address as external: {}", observed_addr);
            self.swarm.add_external_address(observed_addr);
        } else {
            trace!("Skipping known external address: {}", observed_addr);
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
                debug!("Unroutable peer detected: {:?}", peer);

                self.swarm.behaviour_mut().kademlia.remove_peer(&peer);
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
                                    peer,
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
                                    peer,
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
                if let Some(QueryResultSender::Providers { sender, .. }) =
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
                        Ok(GetProvidersOk::FinishedWithNoAdditionalRecord { .. }) => {
                            trace!("Get providers query yielded no results");
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
                step: ProgressStep { last, .. },
                id,
                result: QueryResult::Bootstrap(result),
                ..
            } => {
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

    async fn handle_peer_info_event(&mut self, event: PeerInfoEvent) {
        trace!(?event, "Peer info event.");

        if let Ok(PeerInfoSuccess::Received(peer_info)) = event.result {
            if let Some(shared) = self.shared_weak.upgrade() {
                let connected_peers = self.swarm.connected_peers().cloned().collect::<Vec<_>>();

                shared.handlers.new_peer_info.call_simple(&NewPeerInfo {
                    peer_id: event.peer_id,
                    peer_info: peer_info.clone(),
                    connected_peers,
                });
            }

            if let Some(general_connected_peers) =
                self.swarm.behaviour_mut().general_connected_peers.as_mut()
            {
                let keep_alive = self
                    .general_connection_decision_handler
                    .as_ref()
                    .map(|handler| handler(&peer_info))
                    .unwrap_or(false);

                general_connected_peers.update_keep_alive_status(event.peer_id, keep_alive);
            }

            if let Some(special_connected_peers) =
                self.swarm.behaviour_mut().special_connected_peers.as_mut()
            {
                let special_keep_alive = self
                    .special_connection_decision_handler
                    .as_ref()
                    .map(|handler| handler(&peer_info))
                    .unwrap_or(false);

                special_connected_peers.update_keep_alive_status(event.peer_id, special_keep_alive);
            }
        }
    }

    async fn handle_general_connected_peers_event(
        &mut self,
        event: ConnectedPeersEvent<GeneralConnectedPeersInstance>,
    ) {
        trace!(?event, "General connected peers event.");

        let peers = self.get_peers_to_dial().await;

        if let Some(general_connected_peers) =
            self.swarm.behaviour_mut().general_connected_peers.as_mut()
        {
            general_connected_peers.add_peers_to_dial(&peers);
        }
    }

    async fn handle_special_connected_peers_event(
        &mut self,
        event: ConnectedPeersEvent<SpecialConnectedPeersInstance>,
    ) {
        trace!(?event, "Special connected peers event.");

        let peers = self.get_peers_to_dial().await;

        if let Some(special_connected_peers) =
            self.swarm.behaviour_mut().special_connected_peers.as_mut()
        {
            special_connected_peers.add_peers_to_dial(&peers);
        }
    }

    async fn handle_autonat_event(&mut self, event: AutonatEvent) {
        trace!(?event, "Autonat event received.");
        if let Some(autonat) = self.swarm.behaviour().autonat.as_ref() {
            debug!(
                public_address=?autonat.public_address(),
                confidence=%autonat.confidence(),
                "Current public address confidence."
            );
        }

        if let AutonatEvent::StatusChanged { old, new } = event {
            info!(?old, ?new, "Public address status changed.")
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
            Command::GetProviders {
                key,
                result_sender,
                permit,
            } => {
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_providers(key.into());

                self.query_id_receivers.insert(
                    query_id,
                    QueryResultSender::Providers {
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

                for (peer_id, address) in strip_peer_id(self.bootstrap_addresses.clone()) {
                    kademlia.add_address(&peer_id, address);
                }

                match kademlia.bootstrap() {
                    Ok(query_id) => {
                        self.query_id_receivers.insert(
                            query_id,
                            QueryResultSender::Bootstrap {
                                sender: result_sender,
                            },
                        );
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
        self.networking_parameters_registry
            .remove_all_known_peer_addresses(peer_id);
    }

    fn register_event_metrics<E: Debug>(&mut self, swarm_event: &SwarmEvent<Event, E>) {
        if let Some(ref mut metrics) = self.metrics {
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

    async fn get_peers_to_dial(&mut self) -> Vec<PeerAddress> {
        let mut result_peers =
            Vec::with_capacity(KADEMLIA_PEERS_ADDRESSES_BATCH_SIZE + PEERS_ADDRESSES_BATCH_SIZE);

        // Get addresses from Kademlia buckets
        let mut kademlia_addresses = Vec::new();
        let mut kademlia_peers = HashSet::new();
        for kbucket in self.swarm.behaviour_mut().kademlia.kbuckets() {
            for entry in kbucket.iter() {
                let peer_id = *entry.node.key.preimage();
                let addresses = entry.node.value.clone().into_vec();

                for address in addresses {
                    kademlia_addresses.push((peer_id, address));
                }
            }
        }

        // Take random batch from kademlia addresses.
        for _ in 0..KADEMLIA_PEERS_ADDRESSES_BATCH_SIZE {
            if kademlia_addresses.is_empty() {
                break;
            }
            let random_index = self.rng.gen_range(0..kademlia_addresses.len());

            let (peer_id, peer_address) = kademlia_addresses.swap_remove(random_index);
            result_peers.push((peer_id, peer_address));
            kademlia_peers.insert(peer_id);
        }

        // Get peer batch from the known peers registry
        let connected_peers = self.swarm.connected_peers().cloned().collect::<Vec<_>>();
        let local_peer_id = *self.swarm.local_peer_id();
        let allow_non_global_addresses_in_dht = self.allow_non_global_addresses_in_dht;

        let addresses = self
            .networking_parameters_registry
            .next_known_addresses_batch()
            .await
            .into_iter()
            .filter(|(peer_id, address)| {
                if !allow_non_global_addresses_in_dht && !is_global_address_or_dns(address) {
                    trace!(
                        %local_peer_id,
                        %peer_id,
                        %address,
                        "Ignoring non-global address read from parameters registry.",
                    );
                    false
                } else {
                    true
                }
            });

        trace!(%local_peer_id, "Processing addresses batch: {:?}", addresses);

        for (peer_id, addr) in addresses {
            if connected_peers.contains(&peer_id) || kademlia_peers.contains(&peer_id) {
                continue;
            }

            result_peers.push((peer_id, addr))
        }

        let bootstrap_nodes = strip_peer_id(self.bootstrap_addresses.clone())
            .into_iter()
            .map(|(peer_id, _)| peer_id)
            .collect::<HashSet<_>>();

        result_peers.retain(|(peer_id, _)| !bootstrap_nodes.contains(peer_id));
        result_peers
    }
}
