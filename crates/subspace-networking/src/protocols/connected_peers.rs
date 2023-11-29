//! # 'Connected peers' protocol
//!
//! This module contains a `connected peers` protocol. The main
//! purpose of the protocol is to manage and maintain connections with peers in a
//! distributed network, with a focus on managing permanent connections.
//!
//! The heart of the module is the [`PeerDecision`] enum, which represents different states
//! of a peer's permanent connection decision. These states include:
//!
//! * `PendingConnection` - Indicates that a connection attempt to a peer is in progress.
//! * `PendingDecision` - A state when we're waiting for a decision for a certain period of time.
//!   If no decision is made within this period, we consider the decision to be `NotInterested`.
//! * `PermanentConnection` - Indicates that the decision has been made to maintain a permanent
//!   connection with the peer. No further decision-making is required for this state.
//! * `NotInterested` - Shows that the system has decided not to connect with the peer.
//!   No further decision-making is required for this state.
//!
//! The module includes configuration, event handling, and connection management. It provides
//! capabilities for dialing peers, sending signals about changes in connection states.
//!
//! The protocol strives to maintain a certain target number of peers, handles delay between dialing
//! attempts, and manages a cache for candidates for permanent connections. It maintains
//! a single connection for each peer. Multiple protocol instances could be instantiated.

mod handler;

#[cfg(test)]
mod tests;

use crate::utils::PeerAddress;
use futures::FutureExt;
use futures_timer::Delay;
use handler::Handler;
use libp2p::core::{ConnectedPoint, Endpoint, Multiaddr};
use libp2p::swarm::behaviour::{ConnectionEstablished, FromSwarm};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{
    ConnectionClosed, ConnectionDenied, ConnectionId, DialFailure, NetworkBehaviour, NotifyHandler,
    THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::PeerId;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tracing::{debug, trace};

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub(super) enum ConnectionType {
    Outgoing,
    Incoming,
}

impl From<&ConnectedPoint> for ConnectionType {
    fn from(value: &ConnectedPoint) -> Self {
        match value {
            ConnectedPoint::Dialer { .. } => ConnectionType::Outgoing,
            ConnectedPoint::Listener { .. } => ConnectionType::Incoming,
        }
    }
}

impl ConnectionType {
    fn stringify(&self) -> String {
        match self {
            Self::Outgoing => "Outgoing".to_string(),
            Self::Incoming => "Incoming".to_string(),
        }
    }
}

/// Represents different states of a peer permanent connection.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectionState {
    /// Indicates that a connection is expected to be established to this peer.
    Preparing { peer_address: Multiaddr },

    /// Indicates that a connection attempt to a peer is in progress.
    Connecting { peer_address: Multiaddr },

    /// We're waiting for a decision for some time. The decision time is limited by the
    /// connection timeout.
    Deciding {
        connection_id: ConnectionId,
        connection_type: ConnectionType,
    },

    /// Indicates that the decision has been made to maintain a permanent
    /// connection with the peer. No further decision-making is required for this state.
    Permanent {
        connection_id: ConnectionId,
        connection_type: ConnectionType,
    },

    /// Shows that the system has decided not to connect with the peer.
    /// No further decision-making is required for this state.
    NotInterested,
}

impl ConnectionState {
    /// Checks whether we have an active connection.
    fn connected(&self) -> bool {
        self.connection_id().is_some()
    }

    /// Returns active connection ID if any.
    fn connection_id(&self) -> Option<ConnectionId> {
        match self {
            ConnectionState::Preparing { .. } | ConnectionState::Connecting { .. } => None,
            ConnectionState::Deciding { connection_id, .. } => Some(*connection_id),
            ConnectionState::Permanent { connection_id, .. } => Some(*connection_id),
            ConnectionState::NotInterested => None,
        }
    }

    /// Returns active connection type if any.
    fn connection_type(&self) -> Option<ConnectionType> {
        match self {
            ConnectionState::Preparing { .. } | ConnectionState::Connecting { .. } => None,
            ConnectionState::Deciding {
                connection_type, ..
            } => Some(*connection_type),
            ConnectionState::Permanent {
                connection_type, ..
            } => Some(*connection_type),
            ConnectionState::NotInterested => None,
        }
    }

    /// Converts [`ConnectionState`] to a string with information loss.
    fn stringify(&self) -> String {
        let type_part = self
            .connection_type()
            .map(|conn_type| conn_type.stringify())
            .unwrap_or("None".to_string());

        let state_part = match self {
            ConnectionState::Preparing { .. } => "ToConnect".to_string(),
            ConnectionState::Connecting { .. } => "Connecting".to_string(),
            ConnectionState::Deciding { .. } => "Deciding".to_string(),
            ConnectionState::Permanent { .. } => "Permanent".to_string(),
            ConnectionState::NotInterested => "NotInterested".to_string(),
        };

        format!("{0}:{1}", type_part, state_part)
    }
}

/// Connected peers protocol configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Defines a target for logging.
    pub log_target: &'static str,
    /// Interval between new dialing attempts.
    pub dialing_interval: Duration,
    /// Interval between logging of the internal state.
    pub logging_interval: Duration,
    /// Number of connected peers that protocol will maintain proactively.
    pub target_connected_peers: u32,
    /// Number of connected peers that protocol will allow to be connected to permanently.
    pub max_connected_peers: u32,
    /// We dial peers using this batch size.
    pub dialing_peer_batch_size: u32,
    /// Time interval reserved for a decision about connections.
    /// It also affects keep-alive interval.
    pub decision_timeout: Duration,
}

const DEFAULT_CONNECTED_PEERS_LOG_TARGET: &str = "connected-peers";
impl Default for Config {
    fn default() -> Self {
        Self {
            log_target: DEFAULT_CONNECTED_PEERS_LOG_TARGET,
            dialing_interval: Duration::from_secs(15),
            logging_interval: Duration::from_secs(5),
            target_connected_peers: 15,
            max_connected_peers: 30,
            dialing_peer_batch_size: 5,
            decision_timeout: Duration::from_secs(10),
        }
    }
}

/// Connected-peers protocol event.
#[derive(Debug, Clone)]
pub enum Event<Instance> {
    /// We need a new batch of peer addresses from the swarm.
    NewDialingCandidatesRequested(PhantomData<Instance>),
}

/// Defines a possible change for the connection status.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerConnectionDecisionUpdate {
    peer_id: PeerId,
    keep_alive: handler::KeepAlive,
    connection_id: ConnectionId,
}

#[derive(Debug, Default)]
#[allow(dead_code)] // actually, we use the fields implicitly using the `Debug` on logging.
struct ConnectedPeerStats {
    status_count: HashMap<String, usize>,
    peer_status: HashMap<String, Vec<PeerId>>,
}

/// `Behaviour` for `connected peers` protocol.
#[derive(Debug)]
pub struct Behaviour<Instance> {
    /// Protocol configuration.
    config: Config,

    /// Represents current permanent connection decisions for known peers.
    known_peers: HashMap<PeerId, ConnectionState>,

    /// Pending 'signals' to connection handlers about recent changes.
    peer_decision_changes: Vec<PeerConnectionDecisionUpdate>,

    /// Delay between dialing attempts.
    dialing_delay: Delay,

    /// Cache for candidates for permanent connections.
    peer_cache: Vec<PeerAddress>,

    /// Future waker.
    waker: Option<Waker>,

    /// Instance type marker.
    phantom_data: PhantomData<Instance>,

    /// Delay between logging of the internal state.
    logging_delay: Delay,
}

impl<Instance> Behaviour<Instance> {
    /// Creates a new `Behaviour`.
    pub fn new(config: Config) -> Self {
        let dialing_delay = Delay::new(config.dialing_interval);
        let logging_delay = Delay::new(config.logging_interval);
        Self {
            config,
            known_peers: HashMap::new(),
            peer_decision_changes: Vec::new(),
            dialing_delay,
            peer_cache: Vec::new(),
            waker: None,
            phantom_data: PhantomData,
            logging_delay,
        }
    }

    /// Create a connection handler for the protocol.
    fn new_connection_handler(
        &mut self,
        peer_id: &PeerId,
        connection_id: ConnectionId,
        connection_type: ConnectionType,
    ) -> Handler {
        let default_keep_alive_until = Instant::now() + self.config.decision_timeout;
        let (keep_alive, keep_alive_until) =
            if let Some(connection_state) = self.known_peers.get_mut(peer_id) {
                match connection_state {
                    ConnectionState::Preparing { .. } | ConnectionState::Connecting { .. } => {
                        // Connection attempt was successful.
                        *connection_state = ConnectionState::Deciding {
                            connection_id,
                            connection_type,
                        };

                        (true, Some(default_keep_alive_until))
                    }
                    ConnectionState::Deciding { .. } => (false, None), // We're already have a connection
                    ConnectionState::Permanent { .. } => (false, None), // We're already have a connection
                    ConnectionState::NotInterested => (false, None),
                }
            } else {
                // Connection from other protocols.
                self.known_peers.insert(
                    *peer_id,
                    ConnectionState::Deciding {
                        connection_id,
                        connection_type,
                    },
                );

                (true, Some(default_keep_alive_until))
            };

        self.wake();
        Handler::new(keep_alive, keep_alive_until)
    }

    /// Specifies the whether we should keep connections to the peer alive. The decision could
    /// depend on another protocol (e.g.: PeerInfo protocol event handling).
    pub fn update_keep_alive_status(&mut self, peer_id: PeerId, keep_alive: bool) {
        let allow_new_incoming_connected_peer = self
            .permanently_connected_peers(ConnectionType::Incoming)
            < self.config.max_connected_peers;
        let allow_new_outgoing_connected_peer = self
            .permanently_connected_peers(ConnectionType::Outgoing)
            < self.config.target_connected_peers;

        // It's a known peer.
        if let Some(connection_state) = self.known_peers.get_mut(&peer_id) {
            // We're connected
            if let Some(connection_id) = connection_state.connection_id() {
                let Some(connection_type) = connection_state.connection_type() else {
                    debug!(
                            ?peer_id,
                            ?keep_alive,
                            "Detected an attempt to update status of peer with unknown connection type."
                        );
                    return;
                };

                let not_enough_connected_peers = {
                    match connection_type {
                        ConnectionType::Outgoing => allow_new_outgoing_connected_peer,
                        ConnectionType::Incoming => allow_new_incoming_connected_peer,
                    }
                };

                if not_enough_connected_peers {
                    trace!(%peer_id, %keep_alive, "Insufficient number of connected peers detected.");
                } else {
                    trace!(%peer_id, %keep_alive, "Target number of connected peers reached.");
                }

                // Check whether we have enough connected peers already and a positive decision
                let (new_connection_state, keep_alive_handler) =
                    if not_enough_connected_peers && keep_alive {
                        (
                            ConnectionState::Permanent {
                                connection_id,
                                connection_type,
                            },
                            true,
                        )
                    } else {
                        (ConnectionState::NotInterested, false)
                    };

                *connection_state = new_connection_state;

                self.peer_decision_changes
                    .push(PeerConnectionDecisionUpdate {
                        peer_id,
                        keep_alive: keep_alive_handler,
                        connection_id,
                    });
                self.wake();
            } else {
                debug!(
                    ?peer_id,
                    ?keep_alive,
                    "Detected an attempt to update status of non-existing connection."
                );
            }
        } else {
            debug!(
                ?peer_id,
                ?keep_alive,
                "Detected an attempt to update status of unknown peer."
            );
        }
    }

    /// Calculates the current number of permanently connected peers.
    fn permanently_connected_peers(&self, filter_connection_type: ConnectionType) -> u32 {
        self.known_peers
            .iter()
            .filter(|(_, connection_state)| {
                if let ConnectionState::Permanent {
                    connection_type, ..
                } = connection_state
                {
                    *connection_type == filter_connection_type
                } else {
                    false
                }
            })
            .count() as u32
    }

    /// Calculates the current number of peers with all connections except connections with
    /// decision PeerDecision::NotInterested.
    fn active_peers(&self) -> u32 {
        self.known_peers
            .iter()
            .filter(|(_, connection_state)| {
                !matches!(connection_state, ConnectionState::NotInterested)
            })
            .count() as u32
    }

    /// Adds peer addresses for internal cache. We use these addresses to dial peers for maintaining
    /// target connection number.
    pub fn add_peers_to_dial(&mut self, peers: &[PeerAddress]) {
        self.peer_cache.extend_from_slice(peers);
        self.wake();
    }

    fn wake(&self) {
        if let Some(waker) = &self.waker {
            waker.wake_by_ref()
        }
    }

    fn gather_stats(&self) -> ConnectedPeerStats {
        let status_count =
            self.known_peers
                .iter()
                .fold(HashMap::new(), |mut result, (_, connection_info)| {
                    result
                        .entry(connection_info.stringify())
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                    result
                });

        let peer_status = self.known_peers.iter().fold(
            HashMap::<String, Vec<PeerId>>::new(),
            |mut result, (peer_id, connection_info)| {
                result
                    .entry(connection_info.stringify())
                    .and_modify(|peers| peers.push(*peer_id))
                    .or_insert(vec![*peer_id]);
                result
            },
        );

        ConnectedPeerStats {
            status_count,
            peer_status,
        }
    }
}

impl<Instance: 'static + Send> NetworkBehaviour for Behaviour<Instance> {
    type ConnectionHandler = Handler;
    type ToSwarm = Event<Instance>;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.new_connection_handler(&peer_id, connection_id, ConnectionType::Incoming))
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        _: &Multiaddr,
        _: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.new_connection_handler(&peer_id, connection_id, ConnectionType::Outgoing))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            }) => {
                match self.known_peers.entry(peer_id) {
                    // Connection was established without dialing from this protocol
                    Entry::Vacant(entry) => {
                        entry.insert(ConnectionState::Deciding {
                            connection_id,
                            connection_type: endpoint.into(),
                        });

                        trace!(%peer_id, "Pending peer decision...");
                        self.wake();
                    }
                    Entry::Occupied(_) => {
                        // We're already have either a connection or a decision
                    }
                }
            }
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id,
                remaining_established,
                connection_id,
                ..
            }) => {
                // Handle connection with known ConnectionId.
                let known_connection_closed = self
                    .known_peers
                    .get(&peer_id)
                    .and_then(|connection_state| connection_state.connection_id())
                    .map(|exiting_connection_id| exiting_connection_id == connection_id)
                    .unwrap_or(false);

                if known_connection_closed {
                    trace!(%peer_id, ?connection_id, "Known connection closed");
                    self.known_peers.remove(&peer_id);
                    self.wake();
                }

                // Handle connection with `NotInterested` status.
                if remaining_established == 0 {
                    let old_peer_decision = self.known_peers.remove(&peer_id);

                    if old_peer_decision.is_some() {
                        trace!(
                            %peer_id,
                            ?old_peer_decision,
                            ?connection_id,
                            "Known peer disconnected"
                        );
                        self.wake();
                    }
                };
            }
            FromSwarm::DialFailure(DialFailure {
                peer_id: Some(peer_id),
                error,
                ..
            }) => {
                let other_connections = self
                    .known_peers
                    .get(&peer_id)
                    .map(|connection_state| connection_state.connected())
                    .unwrap_or(false);
                if !other_connections {
                    let old_peer_decision = self.known_peers.remove(&peer_id);

                    if old_peer_decision.is_some() {
                        debug!(
                            %peer_id,
                            ?old_peer_decision,
                            ?error,
                            "Dialing error to known peer"
                        );
                    }
                }

                self.wake();
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        _: THandlerOutEvent<Self>,
    ) {
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // Notify handlers about received connection decision.
        if let Some(change) = self.peer_decision_changes.pop() {
            return Poll::Ready(ToSwarm::NotifyHandler {
                peer_id: change.peer_id,
                handler: NotifyHandler::One(change.connection_id),
                event: change.keep_alive,
            });
        }

        // Check decision statuses.
        for (peer_id, connection_state) in self.known_peers.iter_mut() {
            match connection_state {
                ConnectionState::Preparing {
                    peer_address: address,
                } => {
                    debug!(%peer_id, "Dialing a new peer");

                    let dial_opts = DialOpts::peer_id(*peer_id).addresses(vec![address.clone()]);

                    *connection_state = ConnectionState::Connecting {
                        peer_address: address.clone(),
                    };

                    return Poll::Ready(ToSwarm::Dial {
                        opts: dial_opts.build(),
                    });
                }
                ConnectionState::Connecting { .. } => {
                    // Waiting for connection to be established.
                }
                ConnectionState::Deciding { .. } => {
                    // The decision time is limited by the connection timeout.
                }
                ConnectionState::Permanent { .. } | ConnectionState::NotInterested { .. } => {
                    // Decision is made - no action necessary.
                }
            }
        }

        // Schedule new peer dialing.
        match self.dialing_delay.poll_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(()) => {
                self.dialing_delay.reset(self.config.dialing_interval);

                // Request new peer addresses.
                if self.peer_cache.is_empty() && self.config.target_connected_peers > 0 {
                    trace!("Requesting new peers for connected-peers protocol...");

                    return Poll::Ready(ToSwarm::GenerateEvent(
                        Event::NewDialingCandidatesRequested(PhantomData),
                    ));
                }

                // New dial candidates.
                if self.active_peers() < self.config.target_connected_peers {
                    let range = 0..(self.config.dialing_peer_batch_size as usize)
                        .min(self.peer_cache.len());

                    let peer_addresses = self.peer_cache.drain(range);

                    for (peer_id, address) in peer_addresses {
                        self.known_peers.entry(peer_id).or_insert_with(|| {
                            cx.waker().wake_by_ref();

                            ConnectionState::Preparing {
                                peer_address: address,
                            }
                        });
                    }
                }
            }
        }

        // Log the internal state.
        match self.logging_delay.poll_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(()) => {
                self.logging_delay.reset(self.config.logging_interval);

                let stats = self.gather_stats();

                debug!(
                    instance = %self.config.log_target,
                    ?stats,
                    "Connected peers protocol statistics",
                );
            }
        }

        self.waker.replace(cx.waker().clone());
        Poll::Pending
    }
}
