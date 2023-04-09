use crate::behavior::persistent_parameters::NetworkingParametersRegistry;
use crate::behavior::{provider_storage, Behavior, Event};
use crate::create::temporary_bans::TemporaryBans;
use crate::create::{
    ProviderOnlyRecordStore, KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER,
    REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER,
};
use crate::request_responses::{Event as RequestResponseEvent, IfDisconnected};
use crate::shared::{Command, CreatedSubscription, Shared};
use crate::utils::{is_global_address_or_dns, ResizableSemaphorePermit};
use bytes::Bytes;
use futures::channel::mpsc;
use futures::future::Fuse;
use futures::{FutureExt, StreamExt};
use libp2p::core::ConnectedPoint;
use libp2p::gossipsub::{Event as GossipsubEvent, TopicHash};
use libp2p::identify::Event as IdentifyEvent;
use libp2p::kad::store::RecordStore;
use libp2p::kad::{
    AddProviderError, AddProviderOk, GetClosestPeersError, GetClosestPeersOk, GetProvidersError,
    GetProvidersOk, GetRecordError, GetRecordOk, InboundRequest, Kademlia, KademliaEvent,
    PeerRecord, ProgressStep, PutRecordOk, QueryId, QueryResult, Quorum, Record,
};
use libp2p::metrics::{Metrics, Recorder};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{DialError, SwarmEvent};
use libp2p::{futures, Multiaddr, PeerId, Swarm, TransportError};
use nohash_hasher::IntMap;
use parking_lot::Mutex;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Sleep;
use tracing::{debug, error, info, trace, warn};

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
    Announce {
        sender: mpsc::UnboundedSender<()>,
        // Just holding onto permit while data structure is not dropped
        _permit: ResizableSemaphorePermit,
    },
    PutValue {
        sender: mpsc::UnboundedSender<()>,
        // Just holding onto permit while data structure is not dropped
        _permit: ResizableSemaphorePermit,
    },
}

/// Runner for the Node.
#[must_use = "Node does not function properly unless its runner is driven forward"]
pub struct NodeRunner<ProviderStorage>
where
    ProviderStorage: provider_storage::ProviderStorage + Send + Sync + 'static,
{
    /// Should non-global addresses be added to the DHT?
    allow_non_global_addresses_in_dht: bool,
    command_receiver: mpsc::Receiver<Command>,
    swarm: Swarm<Behavior<ProviderOnlyRecordStore<ProviderStorage>>>,
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
    /// Defines target total (in and out) connection number that should be maintained.
    target_connections: u32,
    /// Temporarily banned peers.
    temporary_bans: Arc<Mutex<TemporaryBans>>,
    /// Prometheus metrics.
    metrics: Option<Metrics>,
    /// Mapping from specific peer to number of established connections
    established_connections: HashMap<(PeerId, ConnectedPoint), usize>,
    /// DSN connection observer. Turns on/off DSN operations like piece retrieval.
    online_status_observer_tx: watch::Sender<bool>,
}

// Helper struct for NodeRunner configuration (clippy requirement).
pub(crate) struct NodeRunnerConfig<ProviderStorage>
where
    ProviderStorage: provider_storage::ProviderStorage + Send + Sync + 'static,
{
    pub(crate) allow_non_global_addresses_in_dht: bool,
    pub(crate) command_receiver: mpsc::Receiver<Command>,
    pub(crate) swarm: Swarm<Behavior<ProviderOnlyRecordStore<ProviderStorage>>>,
    pub(crate) shared_weak: Weak<Shared>,
    pub(crate) next_random_query_interval: Duration,
    pub(crate) networking_parameters_registry: Box<dyn NetworkingParametersRegistry>,
    pub(crate) reserved_peers: HashMap<PeerId, Multiaddr>,
    pub(crate) target_connections: u32,
    pub(crate) temporary_bans: Arc<Mutex<TemporaryBans>>,
    pub(crate) metrics: Option<Metrics>,
    pub(crate) online_status_observer_tx: watch::Sender<bool>,
}

impl<ProviderStorage> NodeRunner<ProviderStorage>
where
    ProviderStorage: provider_storage::ProviderStorage + Send + Sync + 'static,
{
    pub(crate) fn new(
        NodeRunnerConfig {
            allow_non_global_addresses_in_dht,
            command_receiver,
            swarm,
            shared_weak,
            next_random_query_interval,
            networking_parameters_registry,
            reserved_peers,
            target_connections,
            temporary_bans,
            metrics,
            online_status_observer_tx,
        }: NodeRunnerConfig<ProviderStorage>,
    ) -> Self {
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
            peer_dialing_timeout: Box::pin(tokio::time::sleep(Duration::from_secs(0)).fuse()),
            networking_parameters_registry,
            reserved_peers,
            target_connections,
            temporary_bans,
            metrics,
            established_connections: HashMap::new(),
            online_status_observer_tx,
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
                        self.register_event_metrics(&swarm_event);
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
                        Box::pin(tokio::time::sleep(Duration::from_secs(5)).fuse());
                },
            }
        }
    }

    // Handle DSN online status signaling
    fn signal_online_status(&mut self) {
        let current_online_status = self.swarm.connected_peers().next().is_some();
        let previous_online_status = *self.online_status_observer_tx.borrow();

        if previous_online_status != current_online_status {
            if let Err(err) = self.online_status_observer_tx.send(current_online_status) {
                error!("DSN connection observer channel failed: {err}")
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

        // Maintain target connection number.
        let (total_current_connections, established_connections) = {
            let network_info = self.swarm.network_info();
            let connections = network_info.connection_counters();

            debug!(?connections, "Current connections and limits.");

            (
                connections.num_pending_outgoing()
                    + connections.num_established_outgoing()
                    + connections.num_pending_incoming()
                    + connections.num_established_incoming(),
                connections.num_established_outgoing() + connections.num_established_incoming(),
            )
        };

        if total_current_connections < self.target_connections {
            debug!(
                %local_peer_id,
                total_current_connections,
                target_connections=self.target_connections,
                connected_peers=connected_peers.len(),
                "Initiate connection to known peers",
            );

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
                if connected_peers.contains(&peer_id) {
                    continue;
                }

                self.dial_peer(peer_id, addr)
            }
        } else if established_connections < self.target_connections {
            self.networking_parameters_registry
                .start_over_address_batching()
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
                self.signal_online_status();

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
                if shared.connected_peers_count.fetch_add(1, Ordering::SeqCst)
                    >= CONCURRENT_TASKS_BOOST_PEERS_THRESHOLD.get()
                {
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
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                self.signal_online_status();

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
                if shared.connected_peers_count.fetch_sub(1, Ordering::SeqCst)
                    > CONCURRENT_TASKS_BOOST_PEERS_THRESHOLD.get()
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
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error } => {
                if let Some(peer_id) = &peer_id {
                    // Create or extend temporary ban, but only if we are not offline
                    if let Some(shared) = self.shared_weak.upgrade() {
                        // One peer is possibly a node peer is connected to, hence expecting more
                        // than one for online status
                        if shared.connected_peers_count.load(Ordering::Relaxed) > 1 {
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
                            }
                        }
                    };
                }

                match error {
                    DialError::Transport(ref addresses) => {
                        for (addr, _) in addresses {
                            debug!(?error, ?peer_id, %addr, "SwarmEvent::OutgoingConnectionError (DialError::Transport) for peer.");
                            if let Some(peer_id) = peer_id {
                                self.networking_parameters_registry
                                    .remove_known_peer_addresses(peer_id, vec![addr.clone()])
                                    .await;
                            }
                        }
                    }
                    DialError::WrongPeerId { obtained, .. } => {
                        debug!(?error, ?peer_id, obtained_peer_id=?obtained, "SwarmEvent::WrongPeerId (DialError::WrongPeerId) for peer.");

                        if let Some(ref peer_id) = peer_id {
                            let kademlia = &mut self.swarm.behaviour_mut().kademlia;
                            let _ = kademlia.remove_peer(peer_id);
                        }
                    }
                    _ => {
                        debug!(?error, ?peer_id, "SwarmEvent::OutgoingConnectionError");
                    }
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
            let kademlia_enabled = info.protocols.iter().any(|protocol_a| {
                kademlia
                    .protocol_names()
                    .iter()
                    .any(|protocol_b| protocol_a.as_bytes() == protocol_b.as_ref())
            });

            if kademlia_enabled {
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
                            .map(|p| String::from_utf8_lossy(p.as_ref()))
                            .collect::<Vec<_>>(),
                    );
                    kademlia.add_address(&peer_id, address);
                }
            } else {
                trace!(
                    %local_peer_id,
                    %peer_id,
                    "Peer doesn't support our Kademlia DHT protocol ({:?}). Adding to the DHT skipped.",
                    kademlia
                        .protocol_names()
                        .iter()
                        .map(|p| String::from_utf8_lossy(p.as_ref()))
                        .collect::<Vec<_>>(),
                )
            }
        }
    }

    async fn handle_kademlia_event(&mut self, event: KademliaEvent) {
        trace!("Kademlia event: {:?}", event);

        match event {
            KademliaEvent::InboundRequest {
                request: InboundRequest::AddProvider { record, guard },
            } => {
                trace!("Add provider request received: {:?}", record);
                if let (Some(record), Some(guard)) = (record, guard) {
                    if let Err(err) = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .store_mut()
                        .add_provider(record.clone())
                    {
                        error!(?err, "Failed to add provider record: {:?}", record);
                    }

                    let shared = match self.shared_weak.upgrade() {
                        Some(shared) => shared,
                        None => {
                            return;
                        }
                    };

                    shared.handlers.announcement.call_simple(&record, &guard);
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
                    self.query_id_receivers.get_mut(&id)
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
                    self.query_id_receivers.get_mut(&id)
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
                    self.query_id_receivers.get_mut(&id)
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
                result: QueryResult::StartProviding(result),
                stats,
            } => {
                let mut cancelled = false;
                trace!("Start providing stats: {:?}", stats);

                if let Some(QueryResultSender::Announce { sender, .. }) =
                    self.query_id_receivers.get_mut(&id)
                {
                    match result {
                        Ok(AddProviderOk { key }) => {
                            trace!("Start providing query for {} succeeded", hex::encode(&key));

                            cancelled = Self::unbounded_send_and_cancel_on_error(
                                &mut self.swarm.behaviour_mut().kademlia,
                                sender,
                                (),
                                "AddProviderOk",
                                &id,
                            ) || cancelled;
                        }
                        Err(error) => {
                            let AddProviderError::Timeout { key } = error;

                            debug!("Start providing query for {} failed.", hex::encode(&key));
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
                    self.query_id_receivers.get_mut(&id)
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
            _ => {}
        }
    }

    // Returns `true` if query was cancelled
    fn unbounded_send_and_cancel_on_error<T>(
        kademlia: &mut Kademlia<ProviderOnlyRecordStore<ProviderStorage>>,
        sender: &mut mpsc::UnboundedSender<T>,
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

    async fn handle_command(&mut self, command: Command) {
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
            Command::CheckConnectedPeers { result_sender } => {
                let connected_peers_present = self.swarm.connected_peers().next().is_some();

                let kademlia_connection_initiated = if connected_peers_present {
                    self.swarm.behaviour_mut().kademlia.bootstrap().is_ok()
                } else {
                    false
                };

                let _ = result_sender.send(kademlia_connection_initiated);
            }
            Command::StartAnnouncing {
                key,
                result_sender,
                permit,
            } => {
                let res = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .start_providing(key.clone());

                match res {
                    Ok(query_id) => {
                        self.query_id_receivers.insert(
                            query_id,
                            QueryResultSender::Announce {
                                sender: result_sender,
                                _permit: permit,
                            },
                        );
                    }
                    Err(error) => {
                        error!(?key, ?error, "Failed to announce a piece.");
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
                // Remove temporary ban if there is any before creating a permanent one
                self.temporary_bans.lock().remove(&peer_id);

                info!(?peer_id, "Banning peer on network level");
                self.swarm.ban_peer_id(peer_id);
                self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
                self.networking_parameters_registry
                    .remove_all_known_peer_addresses(peer_id)
                    .await;
            }
            Command::Dial { address } => {
                let _ = self.swarm.dial(address);
            }
        }
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
}
