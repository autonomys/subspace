use crate::utils::{CollectionBatcher, PeerAddress};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::future::Fuse;
use futures::FutureExt;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use lru::LruCache;
use parity_db::{Db, Options};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::ops::Add;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::time::{sleep, Sleep};
use tracing::{debug, trace};

/// Parity DB error type alias.
pub type ParityDbError = parity_db::Error;

// Defines optional time for address dial failure
type FailureTime = Option<DateTime<Utc>>;

// Size of the LRU cache for peers.
const PEER_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(100).expect("Not zero; qed");
// Size of the LRU cache for addresses.
const ADDRESSES_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(30).expect("Not zero; qed");
// Pause duration between network parameters save.
const DATA_FLUSH_DURATION_SECS: u64 = 5;
// Defines a batch size for a combined collection for known peers addresses and boostrap addresses.
pub(crate) const PEERS_ADDRESSES_BATCH_SIZE: usize = 30;
// Defines an expiration period for the peer marked for the removal.
const REMOVE_KNOWN_PEERS_GRACE_PERIOD_SECS: i64 = 86400; // 1 DAY

/// Defines operations with the networking parameters.
#[async_trait]
pub trait NetworkingParametersRegistry: Send + Sync {
    /// Registers a peer ID and associated addresses
    async fn add_known_peer(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>);

    /// Unregisters associated addresses for peer ID.
    async fn remove_known_peer_addresses(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>);

    /// Unregisters associated addresses for peer ID.
    async fn remove_all_known_peer_addresses(&mut self, peer_id: PeerId);

    /// Returns a batch of the combined collection of known addresses from networking parameters DB
    /// and boostrap addresses from networking parameters initialization.
    /// It removes p2p-protocol suffix.
    async fn next_known_addresses_batch(&mut self) -> Vec<PeerAddress>;

    /// Reset the batching process to the initial state.
    fn start_over_address_batching(&mut self) {}

    /// Drive async work in the persistence provider
    async fn run(&mut self);

    /// Enables Clone implementation for `Box<dyn NetworkingParametersRegistry>`
    fn clone_box(&self) -> Box<dyn NetworkingParametersRegistry>;
}

impl Clone for Box<dyn NetworkingParametersRegistry> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// Networking manager implementation with NOOP implementation.
#[derive(Clone, Default)]
pub struct StubNetworkingParametersManager;

impl StubNetworkingParametersManager {
    /// Returns an instance of `StubNetworkingParametersManager` as the `Box` reference.
    pub fn boxed(self) -> Box<dyn NetworkingParametersRegistry> {
        Box::new(self)
    }
}

#[async_trait]
impl NetworkingParametersRegistry for StubNetworkingParametersManager {
    async fn add_known_peer(&mut self, _: PeerId, _: Vec<Multiaddr>) {}

    async fn remove_known_peer_addresses(&mut self, _peer_id: PeerId, _addresses: Vec<Multiaddr>) {}

    async fn remove_all_known_peer_addresses(&mut self, _peer_id: PeerId) {}

    async fn next_known_addresses_batch(&mut self) -> Vec<PeerAddress> {
        Vec::new()
    }

    async fn run(&mut self) {
        futures::future::pending().await // never resolves
    }

    fn clone_box(&self) -> Box<dyn NetworkingParametersRegistry> {
        Box::new(self.clone())
    }
}

/// Networking parameters persistence errors.
#[derive(Debug, Error)]
pub enum NetworkParametersPersistenceError {
    /// Parity DB error.
    #[error("DB error: {0}")]
    Db(#[from] parity_db::Error),

    /// Serialization error.
    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),
}

/// Handles networking parameters. It manages network parameters set and its persistence.
pub struct NetworkingParametersManager {
    // Defines whether the cache requires saving to DB
    cache_need_saving: bool,
    // LRU cache for the known peers and their addresses
    known_peers: LruCache<PeerId, LruCache<Multiaddr, FailureTime>>,
    // Period between networking parameters saves.
    networking_parameters_save_delay: Pin<Box<Fuse<Sleep>>>,
    // Parity DB instance
    db: Arc<Db>,
    // Column ID to persist parameters
    column_id: u8,
    // Key to persistent parameters
    object_id: &'static [u8],
    // Provides batching capabilities for the address collection (it stores the last batch index)
    collection_batcher: CollectionBatcher<PeerAddress>,
}

impl NetworkingParametersManager {
    /// Object constructor. It accepts `NetworkingParametersProvider` implementation as a parameter.
    /// On object creation it starts a job for networking parameters cache handling.
    pub fn new(path: &Path) -> Result<Self, NetworkParametersPersistenceError> {
        let mut options = Options::with_columns(path, 1);
        // We don't use stats
        options.stats = false;

        let db = Db::open_or_create(&options)?;
        let column_id = 0u8;
        let object_id = b"global_networking_parameters_key";

        // load known peers cache.
        let cache = db
            .get(column_id, object_id)?
            .map(|data| {
                let result = serde_json::from_slice::<NetworkingParameters>(&data)
                    .map(|data| data.to_cache());

                if result.is_ok() {
                    debug!("Networking parameters loaded from DB");
                }

                result
            })
            .unwrap_or_else(|| Ok(LruCache::new(PEER_CACHE_SIZE)))?;

        Ok(Self {
            cache_need_saving: false,
            db: Arc::new(db),
            column_id,
            object_id,
            known_peers: cache,
            networking_parameters_save_delay: Self::default_delay(),
            collection_batcher: CollectionBatcher::new(
                NonZeroUsize::new(PEERS_ADDRESSES_BATCH_SIZE)
                    .expect("Manual non-zero initialization failed."),
            ),
        })
    }

    // Returns known addresses from networking parameters DB.
    async fn known_addresses(&self) -> Vec<PeerAddress> {
        self.known_peers
            .iter()
            .flat_map(|(peer_id, addresses)| {
                addresses.iter().map(|addr| (*peer_id, addr.0.clone()))
            })
            .collect()
    }

    // Helps create a copy of the internal LruCache
    fn clone_known_peers(&self) -> LruCache<PeerId, LruCache<Multiaddr, FailureTime>> {
        let mut known_peers = LruCache::new(self.known_peers.cap());

        for (peer_id, addresses) in self.known_peers.iter() {
            known_peers.push(*peer_id, clone_lru_cache(addresses, ADDRESSES_CACHE_SIZE));
        }

        known_peers
    }

    /// Creates a reference to the `NetworkingParametersRegistry` trait implementation.
    pub fn boxed(self) -> Box<dyn NetworkingParametersRegistry> {
        Box::new(self)
    }

    // Create default delay for networking parameters.
    fn default_delay() -> Pin<Box<Fuse<Sleep>>> {
        Box::pin(sleep(Duration::from_secs(DATA_FLUSH_DURATION_SECS)).fuse())
    }
}

// Generic LRU-cache cloning function.
fn clone_lru_cache<K: Clone + Hash + Eq, V: Clone>(
    cache: &LruCache<K, V>,
    cap: NonZeroUsize,
) -> LruCache<K, V> {
    let mut cloned_cache = LruCache::new(cap);

    for (key, value) in cache.iter() {
        cloned_cache.push(key.clone(), value.clone());
    }

    cloned_cache
}

#[async_trait]
impl NetworkingParametersRegistry for NetworkingParametersManager {
    async fn add_known_peer(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>) {
        debug!(
            %peer_id,
            addr_num=addresses.len(),
            "Add new peer addresses to the networking parameters registry: {:?}",
            addresses
        );

        addresses
            .iter()
            .filter(|addr| {
                // filter Memory addresses
                !addr
                    .into_iter()
                    .any(|protocol| matches!(protocol, Protocol::Memory(..)))
            })
            .cloned()
            .map(remove_p2p_suffix)
            .for_each(|addr| {
                // Add new address cache if it doesn't exist previously.
                self.known_peers
                    .get_or_insert(peer_id, || LruCache::new(ADDRESSES_CACHE_SIZE));

                if let Some(addresses) = self.known_peers.get_mut(&peer_id) {
                    let previous_entry = addresses.push(addr, None);

                    if let Some(previous_entry) = previous_entry {
                        trace!(%peer_id, "Address cache entry replaced: {:?}", previous_entry);
                    }
                }
            });

        self.cache_need_saving = true;
    }

    async fn remove_known_peer_addresses(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>) {
        trace!(%peer_id, "Remove peer addresses from the networking parameters registry: {:?}", addresses);

        remove_known_peer_addresses_internal(
            &mut self.known_peers,
            peer_id,
            addresses,
            chrono::Duration::seconds(REMOVE_KNOWN_PEERS_GRACE_PERIOD_SECS),
        );

        self.cache_need_saving = true;
    }

    async fn remove_all_known_peer_addresses(&mut self, peer_id: PeerId) {
        trace!(%peer_id, "Remove all peer addresses from the networking parameters registry");

        self.known_peers.pop(&peer_id);

        self.cache_need_saving = true;
    }

    async fn next_known_addresses_batch(&mut self) -> Vec<PeerAddress> {
        // We take cached known addresses and combine them with manually provided bootstrap addresses.
        let combined_addresses = self.known_addresses().await.into_iter().collect::<Vec<_>>();

        trace!(
            "Peer addresses batch requested. Total list size: {}",
            combined_addresses.len()
        );

        self.collection_batcher.next_batch(combined_addresses)
    }

    fn start_over_address_batching(&mut self) {
        self.collection_batcher.reset();
    }

    async fn run(&mut self) {
        loop {
            (&mut self.networking_parameters_save_delay).await;

            if self.cache_need_saving {
                // save accumulated cache to DB
                let dto = NetworkingParameters::from_cache(self.clone_known_peers());
                let save_result = serde_json::to_vec(&dto)
                    .map_err(NetworkParametersPersistenceError::from)
                    .and_then(|data| {
                        let tx = vec![(self.column_id, self.object_id, Some(data))];

                        self.db.commit(tx).map_err(|err| err.into())
                    });

                if let Err(err) = save_result {
                    debug!(error=%err, "Error on saving network parameters");
                } else {
                    trace!("Networking parameters saved to DB");
                }

                self.cache_need_saving = false;
            }

            self.networking_parameters_save_delay = NetworkingParametersManager::default_delay();
        }
    }

    fn clone_box(&self) -> Box<dyn NetworkingParametersRegistry> {
        Self {
            cache_need_saving: self.cache_need_saving,
            known_peers: self.clone_known_peers(),
            networking_parameters_save_delay: Self::default_delay(),
            db: self.db.clone(),
            column_id: self.column_id,
            object_id: self.object_id,
            collection_batcher: self.collection_batcher.clone(),
        }
        .boxed()
    }
}

// Helper struct for NetworkingPersistence implementations (data transfer object).
#[derive(Default, Debug, Serialize, Deserialize)]
struct NetworkingParameters {
    pub known_peers: HashMap<PeerId, HashMap<Multiaddr, FailureTime>>,
}

impl NetworkingParameters {
    fn from_cache(cache: LruCache<PeerId, LruCache<Multiaddr, FailureTime>>) -> Self {
        Self {
            known_peers: cache
                .into_iter()
                .map(|(peer_id, addresses)| {
                    (peer_id, addresses.into_iter().collect::<HashMap<_, _>>())
                })
                .collect::<HashMap<_, _>>(),
        }
    }

    fn to_cache(&self) -> LruCache<PeerId, LruCache<Multiaddr, FailureTime>> {
        let mut peers_cache =
            LruCache::<PeerId, LruCache<Multiaddr, FailureTime>>::new(PEER_CACHE_SIZE);

        for (peer_id, address_map) in self.known_peers.iter() {
            let mut address_cache = LruCache::<Multiaddr, FailureTime>::new(ADDRESSES_CACHE_SIZE);

            for (address, last_failed) in address_map.iter() {
                address_cache.push(address.clone(), *last_failed);
            }
            peers_cache.push(*peer_id, address_cache);
        }

        peers_cache
    }
}

// Removes a P2p protocol suffix from the multiaddress if any.
fn remove_p2p_suffix(address: Multiaddr) -> Multiaddr {
    let mut modified_address = address.clone();

    if let Some(Protocol::P2p(_)) = modified_address.pop() {
        modified_address
    } else {
        address
    }
}

// Testable implementation of the `remove_known_peer_addresses`
pub(super) fn remove_known_peer_addresses_internal(
    known_peers: &mut LruCache<PeerId, LruCache<Multiaddr, FailureTime>>,
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    expired_address_duration: chrono::Duration,
) {
    addresses
        .into_iter()
        .map(remove_p2p_suffix)
        .for_each(|addr| {
            // if peer_id is present in the cache
            if let Some(addresses) = known_peers.peek_mut(&peer_id) {
                // Get mutable reference to first_failed_time for the address without updating
                // the item's position in the cache
                if let Some(first_failed_time) = addresses.peek_mut(&addr) {
                    // if we failed previously with this address
                    if let Some(time) = first_failed_time {
                        // if we failed first time more than a day ago
                        if time.add(expired_address_duration) < Utc::now() {
                            // Remove a failed address
                            addresses.pop(&addr);

                            // If the last address for peer
                            if addresses.is_empty() {
                                known_peers.pop(&peer_id);

                                trace!(%peer_id, "Peer removed from the cache");
                            }

                            trace!(%peer_id, "Address removed from the cache: {:?}", addr);
                        } else {
                            trace!(%peer_id, "Saving failed connection attempt to a peer: {:?}", addr);
                        }
                    } else {
                        // Set failure time
                        first_failed_time.replace(Utc::now());

                        trace!(%peer_id, "Address marked for removal from the cache: {:?}", addr);
                    }
                }
            }
        });
}
