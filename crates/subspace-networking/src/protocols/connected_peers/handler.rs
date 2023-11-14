use futures::pin_mut;
use libp2p::core::upgrade::DeniedUpgrade;
use libp2p::swarm::handler::ConnectionEvent;
use libp2p::swarm::{ConnectionHandler, ConnectionHandlerEvent, SubstreamProtocol};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use tracing::trace;

pub type KeepAlive = bool;

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
    /// Optional future that keeps connection alive for a certain amount of time.
    keep_alive_timeout_future: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
}

impl Handler {
    /// Builds a new [`Handler`].
    pub fn new(keep_alive: KeepAlive, keep_alive_until: Option<Instant>) -> Self {
        let keep_alive_timeout_future = keep_alive_until.map(|keep_alive_until| {
            Box::pin(async move { tokio::time::sleep_until(keep_alive_until.into()).await }) as _
        });

        Handler {
            keep_alive,
            keep_alive_timeout_future,
        }
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = KeepAlive;
    type ToBehaviour = ();
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
        // Drop timeout future
        self.keep_alive_timeout_future.take();
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        self.keep_alive
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<DeniedUpgrade, (), ()>> {
        {
            let maybe_keep_alive_timeout_future = &mut self.keep_alive_timeout_future;
            if let Some(keep_alive_timeout_future) = maybe_keep_alive_timeout_future {
                pin_mut!(keep_alive_timeout_future);

                if matches!(keep_alive_timeout_future.poll(cx), Poll::Ready(())) {
                    maybe_keep_alive_timeout_future.take();
                    self.keep_alive = false;
                }
            }
        }

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
