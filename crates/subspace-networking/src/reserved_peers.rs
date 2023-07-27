mod handler;

use handler::Handler;
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::swarm::behaviour::{ConnectionEstablished, FromSwarm};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{
    ConnectionClosed, ConnectionDenied, ConnectionId, DialFailure, NetworkBehaviour,
    PollParameters, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::PeerId;
use std::collections::HashMap;
use std::ops::Add;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tracing::{debug, trace};

use crate::utils::convert_multiaddresses;

/// `Behaviour` controls and maintains the state of connections to a predefined set of peers.
///
/// The `Behaviour` struct is part of our custom protocol that aims to maintain persistent
/// connections to a predefined set of peers. It encapsulates the logic of managing the connections,
/// dialing, and handling various states of these connections.
///
/// ## How it works
///
/// Each `ReservedPeerState` can be in one of the following states, represented by the
/// `ConnectionStatus` enum:
/// 1. `NotConnected`: This state indicates that the peer is currently not connected.
/// The time for the next connection attempt is scheduled and can be queried.
/// 2. `PendingConnection`: This state means that a connection attempt to the peer is currently
/// in progress.
/// 3. `Connected`: This state signals that the peer is currently connected.
///
/// The protocol will attempt to establish a connection to a `NotConnected` peer after a set delay,
/// specified by `DIALING_INTERVAL_IN_SECS`, to prevent multiple simultaneous connection attempts
/// to offline peers. This delay not only conserves resources, but also reduces the amount of
/// log output.
///
/// ## Comments
///
/// The protocol will establish one or two connections between each pair of reserved peers.
///
/// IMPORTANT NOTE: For the maintenance of a persistent connection, both peers should have each
/// other in their `reserved peers set`. This is necessary because if only one peer has the other
/// in its `reserved peers set`, regular connection attempts will occur, but these connections will
/// be dismissed on the other side due to the `KeepAlive` policy.
///
#[derive(Debug)]
pub struct Behaviour {
    /// Protocol name.
    protocol_name: &'static str,
    /// A mapping from `PeerId` to `ReservedPeerState`, where each `ReservedPeerState`
    /// represents the current state of the connection to a reserved peer.
    reserved_peers_state: HashMap<PeerId, ReservedPeerState>,
}

/// Reserved peers protocol configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Protocol name.
    pub protocol_name: &'static str,
    /// Predefined set of reserved peers with addresses.
    pub reserved_peers: Vec<Multiaddr>,
}

/// Reserved peer connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Reserved peer is not connected. The next connection attempt is scheduled.
    NotConnected { scheduled_at: Instant },
    /// Reserved peer dialing is in progress.
    PendingConnection,
    /// Reserved peer is connected.
    Connected,
}

/// We pause between reserved peers dialing otherwise we could do multiple dials to offline peers
/// wasting resources and producing a ton of log records.
const DIALING_INTERVAL_IN_SECS: Duration = Duration::from_secs(1);

/// Helper-function to schedule a connection attempt.
#[inline]
fn schedule_connection() -> Instant {
    Instant::now().add(DIALING_INTERVAL_IN_SECS)
}

/// Defines the state of a reserved peer connection state.
#[derive(Debug, Clone)]
struct ReservedPeerState {
    connection_status: ConnectionStatus,
    peer_id: PeerId,
    address: Multiaddr,
}

/// Reserved peer connection events.
/// Initially the "reserved peers behaviour" doesn't produce events. However, we could pass
/// reserved peer state changes to the swarm using this struct in the future.
#[derive(Debug, Clone)]
pub struct Event;

impl Behaviour {
    /// Creates a new `Behaviour` with a predefined set of reserved peers.
    pub fn new(config: Config) -> Self {
        debug!(
            reserved_peers=?config.reserved_peers,
            "Reserved peers protocol initialization...."
        );

        let peer_addresses = convert_multiaddresses(config.reserved_peers);

        let reserved_peers_state = peer_addresses
            .into_iter()
            .map(|(peer_id, address)| {
                (
                    peer_id,
                    ReservedPeerState {
                        peer_id,
                        address,
                        connection_status: ConnectionStatus::NotConnected {
                            scheduled_at: schedule_connection(),
                        },
                    },
                )
            })
            .collect();

        Self {
            protocol_name: config.protocol_name,
            reserved_peers_state,
        }
    }

    /// Create a connection handler for the reserved peers protocol.
    #[inline]
    fn new_reserved_peers_handler(&self, peer_id: &PeerId) -> Handler {
        Handler::new(
            self.protocol_name,
            self.reserved_peers_state.contains_key(peer_id),
        )
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        peer_id: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.new_reserved_peers_handler(&peer_id))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer_id: PeerId,
        _: &Multiaddr,
        _: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.new_reserved_peers_handler(&peer_id))
    }

    fn on_swarm_event(&mut self, event: FromSwarm<Self::ConnectionHandler>) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished { peer_id, .. }) => {
                if let Some(state) = self.reserved_peers_state.get_mut(&peer_id) {
                    state.connection_status = ConnectionStatus::Connected;

                    debug!(peer_id=%state.peer_id, "Reserved peer connected.");
                }
            }
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id,
                remaining_established,
                ..
            }) => {
                if let Some(state) = self.reserved_peers_state.get_mut(&peer_id) {
                    if remaining_established == 0 {
                        state.connection_status = ConnectionStatus::NotConnected {
                            scheduled_at: schedule_connection(),
                        };

                        debug!(%state.peer_id, "Reserved peer disconnected.");
                    }
                }
            }
            FromSwarm::DialFailure(DialFailure { peer_id, .. }) => {
                if let Some(peer_id) = peer_id {
                    if let Some(state) = self.reserved_peers_state.get_mut(&peer_id) {
                        if state.connection_status == ConnectionStatus::PendingConnection {
                            state.connection_status = ConnectionStatus::NotConnected {
                                scheduled_at: schedule_connection(),
                            };
                        };

                        debug!(peer_id=%state.peer_id, "Reserved peer dialing failed.");
                    }
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
        _: &mut Context<'_>,
        _: &mut impl PollParameters,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        for (_, state) in self.reserved_peers_state.iter_mut() {
            trace!(?state, "Reserved peer state.");

            if let ConnectionStatus::NotConnected { scheduled_at } = state.connection_status {
                if Instant::now() > scheduled_at {
                    state.connection_status = ConnectionStatus::PendingConnection;

                    debug!(peer_id=%state.peer_id, "Dialing the reserved peer....");

                    let dial_opts =
                        DialOpts::peer_id(state.peer_id).addresses(vec![state.address.clone()]);

                    return Poll::Ready(ToSwarm::Dial {
                        opts: dial_opts.build(),
                    });
                }
            }
        }

        Poll::Pending
    }
}
