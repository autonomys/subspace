//! # 'Connected peers' protocol
//!
//! This module contains a `connected peers` protocol. The main
//! purpose of the protocol is to manage and maintain connections with peers in a
//! distributed network, with a focus on managing permanent connections.
//!
//! The heart of the module is the `PeerDecision` enum, which represents different states
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
use std::ops::Add;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// Represents different states of a peer permanent connection.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PeerDecision {
    /// Indicates that a connection attempt to a peer is in progress.
    PendingConnection { peer_address: PeerAddress },

    /// We're waiting for a decision for `until` period of time. After that we consider the decision
    /// to be NotInterested.
    PendingDecision { until: Instant },

    /// Indicates that the decision has been made to maintain a permanent
    /// connection with the peer. No further decision-making is required for this state.
    PermanentConnection,

    /// Shows that the system has decided not to connect with the peer.
    /// No further decision-making is required for this state.
    NotInterested,
}

/// Connected peers protocol configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Protocol name.
    pub protocol_name: &'static [u8],
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

const DEFAULT_CONNECTED_PEERS_PROTOCOL_NAME: &[u8] = b"/connected-peers/1.0.0";
impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_name: DEFAULT_CONNECTED_PEERS_PROTOCOL_NAME,
            dialing_interval: Duration::from_secs(3),
            target_connected_peers: 30,
            dialing_peer_batch_size: 5,
            decision_timeout: Duration::from_secs(10),
        }
    }
}

/// Connected-peers protocol event.
#[derive(Debug, Clone)]
pub enum Event {
    /// We need a new batch of peer addresses from the swarm.
    NewDialingCandidatesRequested,
}

/// Defines a possible change for the connection status.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerConnectionDecisionUpdate {
    peer_id: PeerId,
    keep_alive: KeepAlive,
}

/// `Behaviour` for `connected peers` protocol.
#[derive(Debug)]
pub struct Behaviour {
    /// Protocol configuration.
    config: Config,

    /// Represents current permanent connection decisions for known peers.
    known_peers: HashMap<PeerId, PeerDecision>,

    /// Pending 'signals' to connection handlers about recent changes.
    peer_decision_changes: Vec<PeerConnectionDecisionUpdate>,

    /// Delay between dialing attempts.
    dialing_delay: Delay,

    /// Cache for candidates for permanent connections.
    peer_cache: Vec<PeerAddress>,

    /// Future waker.
    waker: Option<Waker>,
}

impl Behaviour {
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
        }
    }

    /// Create a connection handler for the protocol.
    #[inline]
    fn new_connection_handler(&mut self, peer_id: &PeerId) -> Handler {
        let default_until = Instant::now().add(self.config.decision_timeout);
        let default_keep_alive_until = KeepAlive::Until(default_until);
        let keep_alive = if let Some(decision) = self.known_peers.get_mut(peer_id) {
            match decision {
                PeerDecision::PendingConnection { .. } => {
                    // Connection attempt was successful.
                    *decision = PeerDecision::PendingDecision {
                        until: default_until,
                    };

                    default_keep_alive_until
                }
                PeerDecision::PendingDecision { until } => KeepAlive::Until(*until),
                PeerDecision::PermanentConnection => KeepAlive::Yes,
                PeerDecision::NotInterested => KeepAlive::No,
            }
        } else {
            default_keep_alive_until
        };

        // Connection from other protocols.
        if !self.known_peers.contains_key(peer_id) {
            self.known_peers.insert(
                *peer_id,
                PeerDecision::PendingDecision {
                    until: default_until,
                },
            );
        }

        self.wake();
        Handler::new(self.config.protocol_name, keep_alive)
    }

    /// Specifies the whether we should keep connections to the peer alive.
    /// Note: in rare cases, it could override decision timeout and keep connection alive.
    pub fn update_keep_alive_status(&mut self, peer_id: PeerId, keep_alive: bool) {
        let (decision, keep_alive) = if keep_alive {
            if self.permanently_connected_peers() < self.config.target_connected_peers {
                trace!(%peer_id, %keep_alive, "Insufficient number of connected peers.");

                (PeerDecision::PermanentConnection, KeepAlive::Yes)
            } else {
                trace!(%peer_id, %keep_alive, "Target number of connected peers reached.");

                (PeerDecision::NotInterested, KeepAlive::No)
            }
        } else {
            (PeerDecision::NotInterested, KeepAlive::No)
        };

        self.known_peers.insert(peer_id, decision);
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
            .filter_map(|(_, decision)| {
                if *decision == PeerDecision::PermanentConnection {
                    Some(1u32)
                } else {
                    None
                }
            })
            .sum()
    }

    /// Calculates the current number of peers with all connections except connections with
    /// decision PeerDecision::NotInterested.
    fn active_peers(&self) -> u32 {
        self.known_peers
            .iter()
            .filter_map(|(_, decision)| {
                if !matches!(*decision, PeerDecision::NotInterested) {
                    Some(1u32)
                } else {
                    None
                }
            })
            .sum()
    }

    /// Adds peer addresses for internal cache. We use these addresses to dial peers for maintaining
    /// target connection number.
    pub fn add_peers_to_dial(&mut self, peers: Vec<PeerAddress>) {
        self.peer_cache.extend_from_slice(&peers);
        self.wake();
    }

    fn wake(&self) {
        if let Some(waker) = &self.waker {
            waker.wake_by_ref()
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type OutEvent = Event;

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
                // Connection was established without dialing from this protocol
                if let Entry::Vacant(entry) = self.known_peers.entry(peer_id) {
                    entry.insert(PeerDecision::PendingDecision {
                        until: Instant::now().add(self.config.decision_timeout),
                    });

                    trace!(%peer_id, "Pending peer decision...");
                    self.wake();
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
                }
            }
            FromSwarm::DialFailure(DialFailure { peer_id, .. }) => {
                if let Some(peer_id) = peer_id {
                    let old_peer_decision = self.known_peers.remove(&peer_id);

                    // For those rare cases when we have a dialing error and existing connection -
                    // we notify the existing handler about connection closing to avoid connection
                    // leakages. If we're interested in this peer we'll reconnect at some point later.
                    self.peer_decision_changes
                        .push(PeerConnectionDecisionUpdate {
                            peer_id,
                            keep_alive: KeepAlive::No,
                        });

                    if old_peer_decision.is_some() {
                        debug!(%peer_id, ?old_peer_decision, "Dialing error to known peer.");
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
            | FromSwarm::NewExternalAddr(_)
            | FromSwarm::ExpiredExternalAddr(_) => {}
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
    ) -> Poll<ToSwarm<Self::OutEvent, THandlerInEvent<Self>>> {
        // Notify handlers about received connection decision.
        if let Some(change) = self.peer_decision_changes.pop() {
            return Poll::Ready(ToSwarm::NotifyHandler {
                peer_id: change.peer_id,
                handler: NotifyHandler::Any,
                event: change.keep_alive,
            });
        }

        // Check decision statuses.
        for (peer_id, decision) in self.known_peers.iter_mut() {
            trace!(%peer_id, ?decision, "Peer decisions for connected peers protocol.");

            match decision.clone() {
                PeerDecision::PendingConnection {
                    peer_address: (peer_id, address),
                    ..
                } => {
                    *decision = PeerDecision::PendingDecision {
                        until: Instant::now().add(self.config.decision_timeout),
                    };

                    debug!(%peer_id, "Dialing a new peer.");

                    let dial_opts = DialOpts::peer_id(peer_id).addresses(vec![address]);

                    return Poll::Ready(ToSwarm::Dial {
                        opts: dial_opts.build(),
                    });
                }
                PeerDecision::PendingDecision { until } => {
                    if until < Instant::now() {
                        *decision = PeerDecision::NotInterested; // timeout
                    }
                }
                PeerDecision::PermanentConnection | PeerDecision::NotInterested => {
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
                        Event::NewDialingCandidatesRequested,
                    ));
                }

                // New dial candidates.
                if self.active_peers() < self.config.target_connected_peers {
                    let range = 0..(self.config.dialing_peer_batch_size as usize)
                        .min(self.peer_cache.len());

                    let peer_addresses = self.peer_cache.drain(range).collect::<Vec<_>>();

                    for peer_address in peer_addresses {
                        self.known_peers.entry(peer_address.0).or_insert_with(|| {
                            PeerDecision::PendingConnection {
                                peer_address: peer_address.clone(),
                            }
                        });
                    }
                }
            }
        }

        self.waker.replace(cx.waker().clone());
        Poll::Pending
    }
}
