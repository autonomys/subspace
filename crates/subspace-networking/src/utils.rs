//! Miscellaneous utilities for networking.

pub(crate) mod key_with_distance;
pub mod multihash;
pub mod piece_provider;
pub(crate) mod rate_limiter;

use event_listener_primitives::Bag;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::Arc;
use tracing::warn;

const NETWORKING_REGISTRY_PREFIX: &str = "subspace";

/// Metrics for Subspace networking
pub struct SubspaceMetrics {
    established_connections: Gauge,
}

impl SubspaceMetrics {
    /// Constructor
    pub fn new(registry: &mut Registry) -> Self {
        let sub_registry = registry.sub_registry_with_prefix(NETWORKING_REGISTRY_PREFIX);

        let gauge = Gauge::default();
        sub_registry.register(
            "established_connections",
            "The current number of established connections",
            gauge.clone(),
        );

        Self {
            established_connections: gauge,
        }
    }

    pub(crate) fn inc_established_connections(&self) {
        self.established_connections.inc();
    }

    pub(crate) fn dec_established_connections(&self) {
        self.established_connections.dec();
    }
}

/// This test is successful only for global IP addresses and DNS names.
pub(crate) fn is_global_address_or_dns(addr: &Multiaddr) -> bool {
    match addr.iter().next() {
        Some(Protocol::Ip4(ip)) => ip.is_global(),
        Some(Protocol::Ip6(ip)) => ip.is_global(),
        Some(Protocol::Dns(_)) | Some(Protocol::Dns4(_)) | Some(Protocol::Dns6(_)) => true,
        _ => false,
    }
}

/// Convenience alias for peer ID and its multiaddresses.
pub type PeerAddress = (PeerId, Multiaddr);

/// Helper function. Converts multiaddresses to a tuple with peer ID removing the peer Id suffix.
/// It logs incorrect multiaddresses.
pub fn strip_peer_id(addresses: Vec<Multiaddr>) -> Vec<PeerAddress> {
    addresses
        .into_iter()
        .filter_map(|multiaddr| {
            let mut modified_multiaddr = multiaddr.clone();

            let peer_id: Option<PeerId> = modified_multiaddr.pop().and_then(|protocol| {
                if let Protocol::P2p(peer_id) = protocol {
                    Some(peer_id)
                } else {
                    None
                }
            });

            if let Some(peer_id) = peer_id {
                Some((peer_id, modified_multiaddr))
            } else {
                warn!(%multiaddr, "Incorrect multiaddr provided.");

                None
            }
        })
        .collect()
}

pub(crate) type HandlerFn<A> = Arc<dyn Fn(&A) + Send + Sync + 'static>;
pub(crate) type Handler<A> = Bag<HandlerFn<A>, A>;
