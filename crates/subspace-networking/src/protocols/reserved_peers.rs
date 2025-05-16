mod handler;
#[cfg(test)]
mod tests;

use futures::FutureExt;
use futures_timer::Delay;
use handler::Handler;
use libp2p::core::transport::PortUse;
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::swarm::behaviour::{ConnectionEstablished, FromSwarm};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{
    ConnectionClosed, ConnectionDenied, ConnectionId, DialFailure, NetworkBehaviour, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::PeerId;
use std::collections::HashMap;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tracing::{debug, trace};

use crate::utils::strip_peer_id;

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
///    The time for the next connection attempt is scheduled and can be queried.
/// 2. `PendingConnection`: This state means that a connection attempt to the peer is currently
///    in progress.
/// 3. `Connected`: This state signals that the peer is currently connected.
///
/// The protocol will attempt to establish a connection to a `NotConnected` peer after a set delay,
/// specified by configurable dialing interval, to prevent multiple simultaneous connection attempts
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
    /// Protocol configuration.
    config: Config,
    /// A mapping from `PeerId` to `ReservedPeerState`, where each `ReservedPeerState`
    /// represents the current state of the connection to a reserved peer.
    reserved_peers_state: HashMap<PeerId, ReservedPeerState>,
    /// Delay between dialing attempts.
    dialing_delay: Delay,
    /// Future waker.
    waker: Option<Waker>,
}

/// Reserved peers protocol configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Predefined set of reserved peers with addresses.
    pub reserved_peers: Vec<Multiaddr>,
    /// Interval between new dialing attempts.
    pub dialing_interval: Duration,
}

/// Reserved peer connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Reserved peer is not connected.
    NotConnected,
    /// Reserved peer dialing is in progress.
    PendingConnection,
    /// Reserved peer is connected.
    Connected,
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

        let peer_addresses = strip_peer_id(config.reserved_peers.clone());
        let dialing_delay = Delay::new(config.dialing_interval);

        let reserved_peers_state = peer_addresses
            .into_iter()
            .map(|(peer_id, address)| {
                (
                    peer_id,
                    ReservedPeerState {
                        peer_id,
                        address,
                        connection_status: ConnectionStatus::NotConnected,
                    },
                )
            })
            .collect();

        Self {
            config,
            reserved_peers_state,
            waker: None,
            dialing_delay,
        }
    }

    /// Create a connection handler for the reserved peers protocol.
    fn new_reserved_peers_handler(&self, peer_id: &PeerId) -> Handler {
        Handler::new(self.reserved_peers_state.contains_key(peer_id))
    }

    fn wake(&self) {
        if let Some(waker) = &self.waker {
            waker.wake_by_ref()
        }
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
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(self.new_reserved_peers_handler(&peer_id))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished { peer_id, .. }) => {
                if let Some(state) = self.reserved_peers_state.get_mut(&peer_id) {
                    state.connection_status = ConnectionStatus::Connected;

                    debug!(peer_id=%state.peer_id, "Reserved peer connected.");
                    self.wake();
                }
            }
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id,
                remaining_established,
                ..
            }) => {
                if let Some(state) = self.reserved_peers_state.get_mut(&peer_id)
                    && remaining_established == 0 {
                        state.connection_status = ConnectionStatus::NotConnected;

                        debug!(%state.peer_id, "Reserved peer disconnected.");
                        self.wake();
                    }
            }
            FromSwarm::DialFailure(DialFailure {
                peer_id: Some(peer_id),
                ..
            }) => {
                if let Some(state) = self.reserved_peers_state.get_mut(&peer_id) {
                    if state.connection_status == ConnectionStatus::PendingConnection {
                        state.connection_status = ConnectionStatus::NotConnected;
                    };

                    debug!(peer_id=%state.peer_id, "Reserved peer dialing failed.");
                    self.wake();
                }
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
        // Schedule new peer dialing.
        match self.dialing_delay.poll_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(()) => {
                self.dialing_delay.reset(self.config.dialing_interval);

                for (_, state) in self.reserved_peers_state.iter_mut() {
                    trace!(?state, "Reserved peer state.");

                    if let ConnectionStatus::NotConnected = state.connection_status {
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
        }

        self.waker.replace(cx.waker().clone());
        Poll::Pending
    }
}
