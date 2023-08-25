use libp2p::core::upgrade::ReadyUpgrade;
use libp2p::swarm::handler::ConnectionEvent;
use libp2p::swarm::{ConnectionHandler, ConnectionHandlerEvent, KeepAlive, SubstreamProtocol};
use libp2p::StreamProtocol;
use std::error::Error;
use std::fmt;
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
    /// Protocol name.
    protocol_name: &'static str,
    /// A boolean flag indicating whether the handler is currently connected to a reserved peer.
    connected_to_reserved_peer: bool,
}

impl Handler {
    /// Builds a new [`Handler`].
    pub fn new(protocol_name: &'static str, connected_to_reserved_peer: bool) -> Self {
        Handler {
            protocol_name,
            connected_to_reserved_peer,
        }
    }
}

#[derive(Debug)]
pub struct ReservedPeersError;

impl fmt::Display for ReservedPeersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Reserved peers error.")
    }
}

impl Error for ReservedPeersError {}

impl ConnectionHandler for Handler {
    type FromBehaviour = Void;
    type ToBehaviour = ();
    type Error = ReservedPeersError;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundOpenInfo = ();
    type InboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<ReadyUpgrade<StreamProtocol>, ()> {
        SubstreamProtocol::new(
            ReadyUpgrade::new(StreamProtocol::new(self.protocol_name)),
            (),
        )
    }

    fn on_behaviour_event(&mut self, _: Void) {}

    fn connection_keep_alive(&self) -> KeepAlive {
        if self.connected_to_reserved_peer {
            KeepAlive::Yes
        } else {
            KeepAlive::No
        }
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<ReadyUpgrade<StreamProtocol>, (), (), Self::Error>> {
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
