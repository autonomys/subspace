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
//! attempts, and manages a cache for candidates for permanent connections.
//! Multiple protocol instances could be instantiated.

mod handler;

use crate::utils::PeerAddress;
use futures::FutureExt;
use futures_timer::Delay;
use handler::Handler;
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::swarm::behaviour::{ConnectionEstablished, FromSwarm};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{
    ConnectionClosed, ConnectionDenied, ConnectionId, DialFailure, KeepAlive, NetworkBehaviour,
    NotifyHandler, PollParameters, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::PeerId;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::Add;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// Peer connections number and statuses.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerState {
    connection_state: ConnectionState,
    connection_counter: usize,
}

impl PeerState {
    fn new(connection_state: ConnectionState) -> Self {
        Self {
            connection_state,
            connection_counter: 0,
        }
    }
}

/// Represents different states of a peer permanent connection.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectionState {
    /// Indicates that a connection attempt to a peer is in progress.
    Connecting { peer_address: Multiaddr },

    /// We're waiting for a decision for some time. The decision time is limited by the
    /// connection timeout.
    Deciding,

    /// Indicates that the decision has been made to maintain a permanent
    /// connection with the peer. No further decision-making is required for this state.
    Permanent,

    /// Shows that the system has decided not to connect with the peer.
    /// No further decision-making is required for this state.
    NotInterested,
}

/// Connected peers protocol configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Defines a target for logging.
    pub log_target: &'static str,
    /// Interval between new dialing attempts.
    pub dialing_interval: Duration,
    /// Number of connected peers that protocol will maintain.
    pub target_connected_peers: u32,
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
            dialing_interval: Duration::from_secs(3),
            target_connected_peers: 30,
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
    keep_alive: KeepAlive,
}

/// `Behaviour` for `connected peers` protocol.
#[derive(Debug)]
pub struct Behaviour<Instance> {
    /// Protocol configuration.
    config: Config,

    /// Represents current permanent connection decisions for known peers.
    known_peers: HashMap<PeerId, PeerState>,

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
}

impl<Instance> Behaviour<Instance> {
    /// Creates a new `Behaviour`.
    pub fn new(config: Config) -> Self {
        let dialing_delay = Delay::new(config.dialing_interval);
        Self {
            config,
            known_peers: HashMap::new(),
            peer_decision_changes: Vec::new(),
            dialing_delay,
            peer_cache: Vec::new(),
            waker: None,
            phantom_data: PhantomData,
        }
    }

    /// Create a connection handler for the protocol.
    fn new_connection_handler(&mut self, peer_id: &PeerId) -> Handler {
        let default_until = Instant::now().add(self.config.decision_timeout);
        let default_keep_alive_until = KeepAlive::Until(default_until);
        let keep_alive = if let Some(state) = self.known_peers.get_mut(peer_id) {
            match state.connection_state {
                ConnectionState::Connecting { .. } => {
                    // Connection attempt was successful.
                    state.connection_state = ConnectionState::Deciding;

                    default_keep_alive_until
                }
                ConnectionState::Deciding => KeepAlive::Until(default_until),
                ConnectionState::Permanent => KeepAlive::Yes,
                ConnectionState::NotInterested => KeepAlive::No,
            }
        } else {
            // Connection from other protocols.
            self.known_peers
                .insert(*peer_id, PeerState::new(ConnectionState::Deciding));

            default_keep_alive_until
        };

        self.wake();
        Handler::new(keep_alive)
    }

    /// Specifies the whether we should keep connections to the peer alive. The decision could
    /// depend on another protocol (e.g.: PeerInfo protocol event handling).
    /// In case when we had decision timeout it sets up proper keep connection alive anyway.
    pub fn update_keep_alive_status(&mut self, peer_id: PeerId, keep_alive: bool) {
        let (connection_state, keep_alive) = if keep_alive {
            if self.permanently_connected_peers() < self.config.target_connected_peers {
                trace!(%peer_id, %keep_alive, "Insufficient number of connected peers.");

                (ConnectionState::Permanent, KeepAlive::Yes)
            } else {
                trace!(%peer_id, %keep_alive, "Target number of connected peers reached.");

                (ConnectionState::NotInterested, KeepAlive::No)
            }
        } else {
            (ConnectionState::NotInterested, KeepAlive::No)
        };

        self.known_peers
            .entry(peer_id)
            .and_modify(|state| {
                state.connection_state = connection_state.clone();
            })
            .or_insert(PeerState::new(connection_state));
        self.peer_decision_changes
            .push(PeerConnectionDecisionUpdate {
                peer_id,
                keep_alive,
            });
        self.wake();
    }

    /// Calculates the current number of permanently connected peers.
    fn permanently_connected_peers(&self) -> u32 {
        self.known_peers
            .iter()
            .filter(|(_, state)| state.connection_state == ConnectionState::Permanent)
            .count() as u32
    }

    /// Calculates the current number of peers with all connections except connections with
    /// decision PeerDecision::NotInterested.
    fn active_peers(&self) -> u32 {
        self.known_peers
            .iter()
            .filter(|(_, state)| state.connection_state != ConnectionState::NotInterested)
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
}

impl<Instance: 'static + Send> NetworkBehaviour for Behaviour<Instance> {
    type ConnectionHandler = Handler;
    type ToSwarm = Event<Instance>;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        peer_id: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.new_connection_handler(&peer_id))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer_id: PeerId,
        _: &Multiaddr,
        _: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.new_connection_handler(&peer_id))
    }

    fn on_swarm_event(&mut self, event: FromSwarm<Self::ConnectionHandler>) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished { peer_id, .. }) => {
                match self.known_peers.entry(peer_id) {
                    // Connection was established without dialing from this protocol
                    Entry::Vacant(entry) => {
                        entry.insert(PeerState {
                            connection_state: ConnectionState::Deciding,
                            connection_counter: 1,
                        });

                        trace!(%peer_id, "Pending peer decision...");
                        self.wake();
                    }
                    Entry::Occupied(mut entry) => {
                        entry.get_mut().connection_counter += 1;
                    }
                }
            }
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id,
                remaining_established,
                ..
            }) => {
                // No established connections left, one of the reasons - the other side chose to not
                // keep the connection alive. We remove information from the local state and
                // possibly will try to reconnect later.
                if remaining_established == 0 {
                    let old_peer_decision = self.known_peers.remove(&peer_id);

                    if old_peer_decision.is_some() {
                        trace!(%peer_id, ?old_peer_decision, "Known peer disconnected.");
                        self.wake();
                    }
                } else {
                    self.known_peers
                        .entry(peer_id)
                        .and_modify(|state| state.connection_counter -= 1);
                };
            }
            FromSwarm::DialFailure(DialFailure { peer_id, .. }) => {
                if let Some(peer_id) = peer_id {
                    let other_connections = self
                        .known_peers
                        .get(&peer_id)
                        .map(|state| state.connection_counter > 0)
                        .unwrap_or(false);
                    if !other_connections {
                        let old_peer_decision = self.known_peers.remove(&peer_id);

                        if old_peer_decision.is_some() {
                            debug!(%peer_id, ?old_peer_decision, "Dialing error to known peer.");
                        }
                    }

                    self.wake();
                }
            }
            FromSwarm::AddressChange(_)
            | FromSwarm::ListenFailure(_)
            | FromSwarm::NewListener(_)
            | FromSwarm::NewListenAddr(_)
            | FromSwarm::ExpiredListenAddr(_)
            | FromSwarm::ListenerError(_)
            | FromSwarm::ListenerClosed(_)
            | FromSwarm::NewExternalAddrCandidate(_)
            | FromSwarm::ExternalAddrConfirmed(_)
            | FromSwarm::ExternalAddrExpired(_) => {}
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
        _: &mut impl PollParameters,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // Notify handlers about received connection decision.
        if let Some(change) = self.peer_decision_changes.pop() {
            return Poll::Ready(ToSwarm::NotifyHandler {
                peer_id: change.peer_id,
                handler: NotifyHandler::Any,
                event: change.keep_alive,
            });
        }

        // Check decision statuses.
        for (peer_id, state) in self.known_peers.iter_mut() {
            trace!(
                %peer_id,
                ?state,
                target=%self.config.log_target,
                "Peer decisions for connected peers protocol."
            );
            match state.connection_state.clone() {
                ConnectionState::Connecting {
                    peer_address: address,
                    ..
                } => {
                    state.connection_state = ConnectionState::Deciding;

                    debug!(%peer_id, "Dialing a new peer.");

                    let dial_opts = DialOpts::peer_id(*peer_id).addresses(vec![address]);

                    return Poll::Ready(ToSwarm::Dial {
                        opts: dial_opts.build(),
                    });
                }
                ConnectionState::Deciding => {
                    // The decision time is limited by the connection timeout.
                }
                ConnectionState::Permanent | ConnectionState::NotInterested => {
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
                if self.peer_cache.is_empty() {
                    trace!("Requesting new peers for connected-peers protocol....");

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
                            PeerState::new(ConnectionState::Connecting {
                                peer_address: address,
                            })
                        });
                    }
                }
            }
        }

        self.waker.replace(cx.waker().clone());
        Poll::Pending
    }
}
