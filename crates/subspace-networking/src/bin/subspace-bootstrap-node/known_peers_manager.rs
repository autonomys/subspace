use async_trait::async_trait;
use event_listener_primitives::{Bag, HandlerId};
use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use subspace_networking::{KnownPeersRegistry, PeerAddress, PeerAddressRemovedEvent};
use tracing::debug;

pub(crate) type HandlerFn<A> = Arc<dyn Fn(&A) + Send + Sync + 'static>;
pub(crate) type Handler<A> = Bag<HandlerFn<A>, A>;

/// Defines optional time for address dial failure
type FailureTime = Option<SystemTime>;

/// Networking manager implementation for DSN bootstrap node.
#[derive(Clone, Default)]
pub(crate) struct KnownPeersManager {
    address_removed: Handler<PeerAddressRemovedEvent>,
    known_addresses: HashMap<PeerId, HashMap<Multiaddr, FailureTime>>,
    failed_address_removal_interval: Duration,
}

impl KnownPeersManager {
    pub fn new(failed_address_removal_interval: Duration) -> Self {
        Self {
            address_removed: Default::default(),
            known_addresses: Default::default(),
            failed_address_removal_interval,
        }
    }
    /// Returns an instance of `NetworkingParametersManager` as the `Box` reference.
    pub fn boxed(self) -> Box<dyn KnownPeersRegistry> {
        Box::new(self)
    }
}

#[async_trait]
impl KnownPeersRegistry for KnownPeersManager {
    async fn add_known_peer(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>) {
        for addr in addresses {
            self.known_addresses
                .entry(peer_id)
                .and_modify(|known_addresses| {
                    known_addresses
                        .entry(addr.clone())
                        .and_modify(|failure_time| {
                            *failure_time = None;
                        })
                        .or_insert(None);
                })
                .or_insert(HashMap::from_iter(vec![(addr, None)]));
        }
    }

    async fn remove_known_peer_addresses(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>) {
        for addr in addresses {
            self.known_addresses
                .entry(peer_id)
                .and_modify(|known_addresses| {
                    let need_to_remove = known_addresses
                        .get_mut(&addr)
                        .map(|first_failure_time| {
                            if let Some(first_failure_time) = first_failure_time {
                                match SystemTime::now().duration_since(*first_failure_time) {
                                    Ok(duration) => duration > self.failed_address_removal_interval,
                                    Err(error) => {
                                        debug!(
                                            ?error,
                                            removal_interval=?self.failed_address_removal_interval,
                                            now=?SystemTime::now(),
                                            "System time was moved backwards.",
                                        );

                                        false
                                    }
                                }
                            } else {
                                *first_failure_time = Some(SystemTime::now());

                                false
                            }
                        })
                        .unwrap_or_default();

                    if need_to_remove {
                        known_addresses.remove(&addr);
                    }
                });
            self.address_removed.call_simple(&PeerAddressRemovedEvent {
                peer_id,
                address: addr.clone(),
            });
        }
    }

    fn remove_all_known_peer_addresses(&mut self, peer_id: PeerId) {
        self.known_addresses.remove(&peer_id);
    }

    async fn next_known_addresses_batch(&mut self) -> Vec<PeerAddress> {
        Vec::new()
    }

    async fn run(&mut self) {
        // Never resolves
        futures::future::pending().await
    }

    fn on_unreachable_address(
        &mut self,
        handler: HandlerFn<PeerAddressRemovedEvent>,
    ) -> Option<HandlerId> {
        let handler_id = self.address_removed.add(handler);

        Some(handler_id)
    }
}

impl KnownPeersManager {
    #[cfg(test)]
    fn contains_address(&self, peer_id: &PeerId, address: &Multiaddr) -> bool {
        self.known_addresses
            .get(peer_id)
            .map(|addresses| addresses.contains_key(address))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use crate::known_peers_manager::KnownPeersManager;
    use libp2p::multiaddr::Protocol;
    use libp2p::{Multiaddr, PeerId};
    use std::time::Duration;
    use subspace_networking::KnownPeersRegistry;
    use tokio::time::sleep;

    #[tokio::test()]
    async fn test_removal_address_after_specified_interval() {
        let mut known_peers = KnownPeersManager::new(Duration::from_millis(100));
        let peer_id = PeerId::random();
        let mut address = Multiaddr::empty();
        address.push(Protocol::P2p(peer_id));

        known_peers
            .add_known_peer(peer_id, vec![address.clone()])
            .await;

        // We added address successfully.
        assert!(known_peers.contains_address(&peer_id, &address));

        known_peers
            .remove_known_peer_addresses(peer_id, vec![address.clone()])
            .await;

        // We didn't remove address instantly.
        assert!(known_peers.contains_address(&peer_id, &address));

        sleep(Duration::from_millis(110)).await;

        known_peers
            .remove_known_peer_addresses(peer_id, vec![address.clone()])
            .await;

        // We removed address after the configured interval.
        assert!(!known_peers.contains_address(&peer_id, &address));
    }
}
