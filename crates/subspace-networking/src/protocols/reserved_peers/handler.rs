use libp2p::core::upgrade::DeniedUpgrade;
use libp2p::swarm::handler::ConnectionEvent;
use libp2p::swarm::{ConnectionHandler, ConnectionHandlerEvent, SubstreamProtocol};
use std::task::{Context, Poll};
use void::Void;

/// Connection handler for managing connections within our `reserved peers` protocol.
///
/// This `Handler` is part of our custom protocol designed to maintain persistent connections
/// with a set of predefined peers.
///
/// ## Connection Handling
///
/// The `Handler` manages the lifecycle of a connection to each peer. If it's connected to a
/// reserved peer, it maintains the connection alive (`KeepAlive::Yes`). If not, it allows the
/// connection to close (`KeepAlive::No`).
///
/// This behavior ensures that connections to reserved peers are maintained persistently,
/// while connections to non-reserved peers are allowed to close.
pub struct Handler {
    /// A boolean flag indicating whether the handler is currently connected to a reserved peer.
    connected_to_reserved_peer: bool,
}

impl Handler {
    /// Builds a new [`Handler`].
    pub fn new(connected_to_reserved_peer: bool) -> Self {
        Handler {
            connected_to_reserved_peer,
        }
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = Void;
    type ToBehaviour = ();
    type InboundProtocol = DeniedUpgrade;
    type OutboundProtocol = DeniedUpgrade;
    type OutboundOpenInfo = ();
    type InboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<DeniedUpgrade, ()> {
        SubstreamProtocol::new(DeniedUpgrade, ())
    }

    fn on_behaviour_event(&mut self, _: Void) {}

    fn connection_keep_alive(&self) -> bool {
        self.connected_to_reserved_peer
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ConnectionHandlerEvent<DeniedUpgrade, (), ()>> {
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
