use libp2p::core::upgrade::DeniedUpgrade;
use libp2p::swarm::handler::ConnectionEvent;
use libp2p::swarm::{ConnectionHandler, ConnectionHandlerEvent, KeepAlive, SubstreamProtocol};
use std::error::Error;
use std::fmt;
use std::task::{Context, Poll};
use tracing::trace;

/// Connection handler for managing connections within our `connected peers` protocol.
///
/// This `Handler` is part of our custom protocol designed to maintain a target number of persistent
/// connections. The decision about the connection is specified by handler events from the
/// protocol [`Behaviour`]
///
/// ## Connection Handling
///
/// The `Handler` manages the lifecycle of a connection to each peer. If it's connected to a
/// peer with positive keep-alive decision (we are interested in this connection), it maintains the
/// connection alive (`KeepAlive::Yes`). If not, it allows the connection to close (`KeepAlive::No`).
pub struct Handler {
    /// Specifies whether we should keep the connection alive.
    keep_alive: KeepAlive,
}

impl Handler {
    /// Builds a new [`Handler`].
    pub fn new(keep_alive: KeepAlive) -> Self {
        Handler { keep_alive }
    }
}

#[derive(Debug)]
pub struct ConnectedPeersError;

impl fmt::Display for ConnectedPeersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Connected peers protocol error.")
    }
}

impl Error for ConnectedPeersError {}

impl ConnectionHandler for Handler {
    type FromBehaviour = KeepAlive;
    type ToBehaviour = ();
    type Error = ConnectedPeersError;
    type InboundProtocol = DeniedUpgrade;
    type OutboundProtocol = DeniedUpgrade;
    type OutboundOpenInfo = ();
    type InboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<DeniedUpgrade, ()> {
        SubstreamProtocol::new(DeniedUpgrade, ())
    }

    fn on_behaviour_event(&mut self, keep_alive: KeepAlive) {
        trace!(?keep_alive, "Behaviour event arrived.");

        self.keep_alive = keep_alive;
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        self.keep_alive
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<DeniedUpgrade, (), (), Self::Error>> {
        Poll::Pending
    }

    fn on_connection_event(
        &mut self,
        _: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
    }
}
