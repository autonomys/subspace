use async_trait::async_trait;
use futures::future::Fuse;
use futures::FutureExt;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use lru::LruCache;
use parity_db::{Db, Options};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::time::{sleep, Sleep};
use tracing::{debug, trace};

// Size of the LRU cache for peers.
const PEER_CACHE_SIZE: usize = 100;
// Pause duration between network parameters save.
const DATA_FLUSH_DURATION_SECS: u64 = 5;

/// Defines operations with the networking parameters.
#[async_trait]
pub trait NetworkingParametersRegistry: Send {
    /// Registers a peer ID and associated addresses
    async fn add_known_peer(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>);

    /// Returns known addresses from networking parameters DB. It removes p2p-protocol suffix.
    /// Peer number parameter limits peers to retrieve.
    async fn known_addresses(&self, peer_number: usize) -> Vec<(PeerId, Multiaddr)>;

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

/// The default implementation for networking manager stub. All operations muted.
#[derive(Clone)]
pub struct NetworkingParametersRegistryStub;

#[async_trait]
impl NetworkingParametersRegistry for NetworkingParametersRegistryStub {
    async fn add_known_peer(&mut self, _: PeerId, _: Vec<Multiaddr>) {}

    async fn known_addresses(&self, _: usize) -> Vec<(PeerId, Multiaddr)> {
        Vec::new()
    }

    async fn run(&mut self) {
        futures::future::pending().await // never resolves
    }

    fn clone_box(&self) -> Box<dyn NetworkingParametersRegistry> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Error)]
pub enum NetworkParametersPersistenceError {
    #[error("DB error: {0}")]
    Db(#[from] parity_db::Error),

    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),
}

/// Handles networking parameters. It manages network parameters set and its persistence.
pub struct NetworkingParametersManager {
    // LRU cache for the known peers and their addresses
    known_peers: LruCache<PeerId, HashSet<Multiaddr>>, // LruCache<Multiaddr, ()>>,
    // Period between networking parameters saves.
    networking_parameters_save_delay: Pin<Box<Fuse<Sleep>>>,
    // Parity DB instance
    db: Arc<Db>,
    // Column ID to persist parameters
    column_id: u8,
    // Key to persistent parameters
    object_id: &'static [u8],
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

        // load known peeers cache.
        let cache = db
            .get(column_id, object_id)?
            .map(|data| {
                let result = serde_json::from_slice::<NetworkingParameters>(&data)
                    .map(|data| data.to_cache());

                if result.is_ok() {
                    trace!("Networking parameters loaded from DB");
                }

                result
            })
            .unwrap_or_else(|| Ok(LruCache::new(PEER_CACHE_SIZE)))?;

        Ok(Self {
            db: Arc::new(db),
            column_id,
            object_id,
            known_peers: cache,
            networking_parameters_save_delay: Self::default_delay(),
        })
    }

    // Helps create a copy of the internal LruCache
    fn clone_known_peers(&self) -> LruCache<PeerId, HashSet<Multiaddr>> {
        let mut known_peers = LruCache::new(self.known_peers.cap());

        for (peer_id, addresses) in self.known_peers.iter() {
            known_peers.push(*peer_id, addresses.clone());
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

#[async_trait]
impl NetworkingParametersRegistry for NetworkingParametersManager {
    async fn add_known_peer(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>) {
        let addr_set = addresses
            .iter()
            .cloned()
            .filter(|addr| {
                // filter Memory addresses
                !addr
                    .into_iter()
                    .any(|protocol| matches!(protocol, Protocol::Memory(..)))
            })
            .collect::<HashSet<_>>();

        if !addr_set.is_empty() {
            //TODO
            //    I think here we also want to have LRU, otherwise addresses of pathological peers can flood these hashsets.
            if let Some(addresses) = self.known_peers.get_mut(&peer_id) {
                *addresses = addresses.union(&addr_set).cloned().collect()
            } else {
                self.known_peers.push(peer_id, addr_set);
            }
        }
    }

    async fn known_addresses(&self, peer_number: usize) -> Vec<(PeerId, Multiaddr)> {
        self.known_peers
            .iter()
            .take(peer_number)
            .flat_map(|(peer_id, addresses)| addresses.iter().map(|addr| (*peer_id, addr.clone())))
            .map(|(peer_id, addr)| {
                // remove p2p-protocol suffix if any
                let mut modified_address = addr.clone();

                if let Some(Protocol::P2p(_)) = modified_address.pop() {
                    (peer_id, modified_address)
                } else {
                    (peer_id, addr)
                }
            })
            .collect()
    }

    async fn run(&mut self) {
        (&mut self.networking_parameters_save_delay).await;

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

        self.networking_parameters_save_delay = NetworkingParametersManager::default_delay();
    }

    fn clone_box(&self) -> Box<dyn NetworkingParametersRegistry> {
        Self {
            known_peers: self.clone_known_peers(),
            networking_parameters_save_delay: Self::default_delay(),
            db: self.db.clone(),
            column_id: self.column_id,
            object_id: self.object_id,
        }
        .boxed()
    }
}

// Helper struct for NetworkingPersistence implementations (data transfer object).
#[derive(Default, Debug, Serialize, Deserialize)]
struct NetworkingParameters {
    pub known_peers: HashMap<PeerId, HashSet<Multiaddr>>,
}

impl NetworkingParameters {
    fn from_cache(cache: LruCache<PeerId, HashSet<Multiaddr>>) -> Self {
        Self {
            known_peers: cache
                .iter()
                .map(|(peer_id, addresses)| (*peer_id, addresses.clone()))
                .collect(),
        }
    }

    fn to_cache(&self) -> LruCache<PeerId, HashSet<Multiaddr>> {
        let mut known_peers = LruCache::<PeerId, HashSet<Multiaddr>>::new(PEER_CACHE_SIZE);

        for (peer_id, addresses) in self.known_peers.iter() {
            known_peers.push(*peer_id, addresses.clone());
        }

        known_peers
    }
}
