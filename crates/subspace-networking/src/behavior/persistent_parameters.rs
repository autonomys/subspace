use crate::utils::{AsyncJoinOnDrop, Handler, HandlerFn};
use async_trait::async_trait;
use event_listener_primitives::HandlerId;
use fs2::FileExt;
use futures::FutureExt;
use futures::future::{Fuse, pending};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use memmap2::{MmapMut, MmapOptions};
use parity_scale_codec::{Compact, CompactLen, Decode, Encode};
use parking_lot::Mutex;
use schnellru::{ByLength, LruMap};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{io, mem};
use subspace_core_primitives::hashes::{Blake3Hash, blake3_hash};
use thiserror::Error;
use tokio::time::{Sleep, sleep};
use tracing::{debug, error, trace, warn};

/// Defines optional time for address dial failure
type FailureTime = Option<SystemTime>;

/// Size of the LRU cache for peers.
const KNOWN_PEERS_CACHE_SIZE: u32 = 100;
/// Size of the LRU cache for addresses of a single peer ID.
const ADDRESSES_CACHE_SIZE: u32 = 30;
/// Pause duration between network parameters save.
const DATA_FLUSH_DURATION_SECS: u64 = 5;
/// Defines an expiration period for the peer marked for the removal.
const REMOVE_KNOWN_PEERS_GRACE_PERIOD: Duration = Duration::from_secs(24 * 3600);
/// Defines an expiration period for the peer marked for the removal for Kademlia DHT.
const REMOVE_KNOWN_PEERS_GRACE_PERIOD_FOR_KADEMLIA: Duration = Duration::from_secs(3600);
/// Defines an expiration period for the peer marked for the removal for Kademlia DHT.
const STALE_KNOWN_PEERS_TIMEOUT: Duration = Duration::from_secs(24 * 3600);

/// Defines the event triggered when the peer address is removed from the permanent storage.
#[derive(Debug, Clone)]
pub struct PeerAddressRemovedEvent {
    /// Peer ID
    pub peer_id: PeerId,
    /// Peer address
    pub address: Multiaddr,
}

#[derive(Debug, Encode, Decode)]
struct EncodableKnownPeerAddress {
    multiaddr: Vec<u8>,
    /// Failure time as Unix timestamp in seconds
    failure_time: Option<u64>,
}

#[derive(Debug, Encode, Decode)]
struct EncodableKnownPeers {
    cache_size: u32,
    timestamp: u64,
    // Each entry is a tuple of peer ID + list of multiaddresses with corresponding failure time
    known_peers: Vec<(Vec<u8>, Vec<EncodableKnownPeerAddress>)>,
}

impl EncodableKnownPeers {
    fn into_cache(mut self) -> LruMap<PeerId, LruMap<Multiaddr, FailureTime>> {
        let mut peers_cache = LruMap::new(ByLength::new(self.cache_size));

        // Sort peers with the oldest expiration date first
        self.known_peers
            .sort_by_cached_key(|(_peer_id, addresses)| {
                addresses.iter().fold(0u64, |acc, address| {
                    acc.max(address.failure_time.unwrap_or(u64::MAX))
                })
            });

        // Iterate over known peers with most recent failure time (or no failire time) first
        'peers: for (peer_id, addresses) in self.known_peers.into_iter().rev() {
            let mut peer_cache =
                LruMap::<Multiaddr, FailureTime>::new(ByLength::new(ADDRESSES_CACHE_SIZE));

            let peer_id = match PeerId::from_bytes(&peer_id) {
                Ok(peer_id) => peer_id,
                Err(error) => {
                    debug!(%error, "Failed to decode known peer ID, skipping peer entry");
                    continue;
                }
            };
            for address in addresses {
                let multiaddr = match Multiaddr::try_from(address.multiaddr) {
                    Ok(multiaddr) => multiaddr,
                    Err(error) => {
                        debug!(
                            %error,
                            "Failed to decode known peer multiaddress, skipping peer entry"
                        );
                        continue 'peers;
                    }
                };

                peer_cache.insert(
                    multiaddr,
                    address.failure_time.map(|failure_time| {
                        SystemTime::UNIX_EPOCH + Duration::from_secs(failure_time)
                    }),
                );
            }

            peers_cache.insert(peer_id, peer_cache);
        }

        peers_cache
    }

    fn from_cache(cache: &LruMap<PeerId, LruMap<Multiaddr, FailureTime>>, cache_size: u32) -> Self {
        let single_peer_encoded_address_size =
            KnownPeersManager::single_peer_encoded_address_size();
        Self {
            cache_size,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Never before Unix epoch; qed")
                .as_secs(),
            known_peers: cache
                .iter()
                .map(|(peer_id, addresses)| {
                    (
                        peer_id.to_bytes(),
                        addresses
                            .iter()
                            .filter_map(|(multiaddr, failure_time)| {
                                let multiaddr_bytes = multiaddr.to_vec();

                                if multiaddr_bytes.encoded_size() > single_peer_encoded_address_size
                                {
                                    // Skip unexpectedly large multiaddresses
                                    debug!(
                                        encoded_multiaddress_size = %multiaddr_bytes.encoded_size(),
                                        limit = %single_peer_encoded_address_size,
                                        ?multiaddr,
                                        "Unexpectedly large multiaddress"
                                    );
                                    return None;
                                }

                                Some(EncodableKnownPeerAddress {
                                    multiaddr: multiaddr_bytes,
                                    failure_time: failure_time.map(|failure_time| {
                                        failure_time
                                            .duration_since(SystemTime::UNIX_EPOCH)
                                            .expect("Never before Unix epoch; qed")
                                            .as_secs()
                                    }),
                                })
                            })
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

/// A/b slots with known peers where we write serialized known peers in one after another
struct KnownPeersSlots {
    a: MmapMut,
    b: MmapMut,
}

impl KnownPeersSlots {
    fn write_to_inactive_slot(&mut self, encodable_known_peers: &EncodableKnownPeers) {
        let known_peers_bytes = encodable_known_peers.encode();
        let (encoded_bytes, remaining_bytes) = self.a.split_at_mut(known_peers_bytes.len());
        encoded_bytes.copy_from_slice(&known_peers_bytes);
        // Write checksum
        remaining_bytes[..Blake3Hash::SIZE]
            .copy_from_slice(blake3_hash(&known_peers_bytes).as_ref());
        if let Err(error) = self.a.flush() {
            warn!(%error, "Failed to flush known peers to disk");
        }

        // Swap slots such that we write into the opposite each time
        mem::swap(&mut self.a, &mut self.b);
    }
}

/// Defines operations with the networking parameters.
#[async_trait]
pub trait KnownPeersRegistry: Send + Sync {
    /// Registers a peer ID and associated addresses
    async fn add_known_peer(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>);

    /// Unregisters associated addresses for peer ID.
    async fn remove_known_peer_addresses(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>);

    /// Unregisters associated addresses for peer ID.
    fn remove_all_known_peer_addresses(&mut self, peer_id: PeerId);

    /// Returns all known peers and their addresses without P2P suffix at the end
    async fn all_known_peers(&mut self) -> Vec<(PeerId, Vec<Multiaddr>)>;

    /// Returns the number of known peers, and the number of addresses known for those peers.
    fn count_known_peers(&mut self) -> (usize, usize);

    /// Drive async work in the persistence provider
    async fn run(&mut self);

    /// Triggers when we removed the peer address from the permanent storage. Returns optional
    /// event HandlerId. Option enables stub implementation. One of the usages is to notify
    /// Kademlia about the expired(unreachable) address when it check for how long address was
    /// unreachable.
    fn on_unreachable_address(
        &mut self,
        handler: HandlerFn<PeerAddressRemovedEvent>,
    ) -> Option<HandlerId>;
}

/// Networking manager implementation with NOOP implementation.
#[derive(Clone, Default)]
pub(crate) struct StubNetworkingParametersManager;

impl StubNetworkingParametersManager {
    /// Returns an instance of `StubNetworkingParametersManager` as the `Box` reference.
    pub fn boxed(self) -> Box<dyn KnownPeersRegistry> {
        Box::new(self)
    }
}

#[async_trait]
impl KnownPeersRegistry for StubNetworkingParametersManager {
    async fn add_known_peer(&mut self, _: PeerId, _: Vec<Multiaddr>) {}

    async fn remove_known_peer_addresses(&mut self, _peer_id: PeerId, _addresses: Vec<Multiaddr>) {}

    fn remove_all_known_peer_addresses(&mut self, _peer_id: PeerId) {}

    async fn all_known_peers(&mut self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        Vec::new()
    }

    fn count_known_peers(&mut self) -> (usize, usize) {
        (0, 0)
    }

    async fn run(&mut self) {
        // Never resolves
        futures::future::pending().await
    }

    fn on_unreachable_address(
        &mut self,
        _handler: HandlerFn<PeerAddressRemovedEvent>,
    ) -> Option<HandlerId> {
        None
    }
}

/// Configuration for [`KnownPeersManager`].
#[derive(Debug, Clone)]
pub struct KnownPeersManagerConfig {
    /// Defines whether we return known peers in [`KnownPeersRegistry::all_known_peers()`]
    pub enable_known_peers_source: bool,
    /// Defines cache size.
    pub cache_size: u32,
    /// Peer ID list to filter on address adding.
    pub ignore_peer_list: HashSet<PeerId>,
    /// Defines whether we enable cache persistence.
    pub path: Option<Box<Path>>,
    /// Defines interval before the next peer address removes entry from the cache.
    pub failed_address_cache_removal_interval: Duration,
    /// Defines interval before the next peer address removal triggers [`PeerAddressRemovedEvent`].
    pub failed_address_kademlia_removal_interval: Duration,
    /// Amount of time after which stored known peers contents is assumed to be stale.
    pub stale_known_peers_timeout: Duration,
}

impl Default for KnownPeersManagerConfig {
    fn default() -> Self {
        Self {
            enable_known_peers_source: true,
            cache_size: KNOWN_PEERS_CACHE_SIZE,
            ignore_peer_list: Default::default(),
            path: None,
            failed_address_cache_removal_interval: REMOVE_KNOWN_PEERS_GRACE_PERIOD,
            failed_address_kademlia_removal_interval: REMOVE_KNOWN_PEERS_GRACE_PERIOD_FOR_KADEMLIA,
            stale_known_peers_timeout: STALE_KNOWN_PEERS_TIMEOUT,
        }
    }
}

/// Networking parameters persistence errors.
#[derive(Debug, Error)]
pub enum KnownPeersManagerPersistenceError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Can't preallocate known peers file, probably not enough space on disk
    #[error("Can't preallocate known peers file, probably not enough space on disk: {0}")]
    CantPreallocateKnownPeersFile(io::Error),
}

/// Handles networking parameters. It manages network parameters set and its persistence.
pub struct KnownPeersManager {
    /// Defines whether the cache requires saving to DB
    cache_need_saving: bool,
    /// LRU cache for the known peers and their addresses
    known_peers: LruMap<PeerId, LruMap<Multiaddr, FailureTime>>,
    /// Period between networking parameters saves.
    networking_parameters_save_delay: Pin<Box<Fuse<Sleep>>>,
    /// Slots backed by file that store known peers
    known_peers_slots: Option<Arc<Mutex<KnownPeersSlots>>>,
    /// Event handler triggered when we decide to remove address from the storage.
    address_removed: Handler<PeerAddressRemovedEvent>,
    /// Defines configuration.
    config: KnownPeersManagerConfig,
}

impl Drop for KnownPeersManager {
    fn drop(&mut self) {
        if self.cache_need_saving
            && let Some(known_peers_slots) = &self.known_peers_slots
        {
            known_peers_slots
                .lock()
                .write_to_inactive_slot(&EncodableKnownPeers::from_cache(
                    &self.known_peers,
                    self.config.cache_size,
                ));
        }
    }
}

impl KnownPeersManager {
    fn init_file(
        path: &Path,
        cache_size: u32,
    ) -> Result<
        (Option<EncodableKnownPeers>, Arc<Mutex<KnownPeersSlots>>),
        KnownPeersManagerPersistenceError,
    > {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let known_addresses_size = Self::known_addresses_size(cache_size);
        let file_size = Self::file_size(cache_size);
        // Try reading existing encoded known peers from file
        let mut maybe_newest_known_addresses = None::<EncodableKnownPeers>;

        {
            let mut file_contents = Vec::with_capacity(file_size);
            file.read_to_end(&mut file_contents)?;
            if !file_contents.is_empty() {
                for known_addresses_bytes in file_contents.chunks_exact(file_contents.len() / 2) {
                    let known_addresses =
                        match EncodableKnownPeers::decode(&mut &*known_addresses_bytes) {
                            Ok(known_addresses) => known_addresses,
                            Err(error) => {
                                debug!(%error, "Failed to decode encodable known peers");
                                continue;
                            }
                        };

                    let (encoded_bytes, remaining_bytes) =
                        known_addresses_bytes.split_at(known_addresses.encoded_size());
                    if remaining_bytes.len() < Blake3Hash::SIZE {
                        debug!(
                            remaining_bytes = %remaining_bytes.len(),
                            "Not enough bytes to decode checksum, file was likely corrupted"
                        );
                        continue;
                    }

                    // Verify checksum
                    let actual_checksum = blake3_hash(encoded_bytes);
                    let expected_checksum = &remaining_bytes[..Blake3Hash::SIZE];
                    if *actual_checksum != *expected_checksum {
                        debug!(
                            encoded_bytes_len = %encoded_bytes.len(),
                            actual_checksum = %hex::encode(actual_checksum),
                            expected_checksum = %hex::encode(expected_checksum),
                            "Hash doesn't match, possible disk corruption or file was just \
                            created, ignoring"
                        );
                        continue;
                    }

                    match &mut maybe_newest_known_addresses {
                        Some(newest_known_addresses) => {
                            if newest_known_addresses.timestamp < known_addresses.timestamp {
                                *newest_known_addresses = known_addresses;
                            }
                        }
                        None => {
                            maybe_newest_known_addresses.replace(known_addresses);
                        }
                    }
                }
            }
        }

        // *2 because we have a/b parts of the file
        let file_resized = if file.seek(SeekFrom::End(0))? != file_size as u64 {
            // Allocating the whole file (`set_len` below can create a sparse file, which will cause
            // writes to fail later)
            file.allocate(file_size as u64)
                .map_err(KnownPeersManagerPersistenceError::CantPreallocateKnownPeersFile)?;
            // Truncating file (if necessary)
            file.set_len(file_size as u64)?;
            true
        } else {
            false
        };

        let mut a_mmap = unsafe {
            MmapOptions::new()
                .len(known_addresses_size)
                .map_mut(&file)?
        };
        let mut b_mmap = unsafe {
            MmapOptions::new()
                .offset(known_addresses_size as u64)
                .len(known_addresses_size)
                .map_mut(&file)?
        };

        if file_resized {
            // File might have been resized, write current known addresses into it
            if let Some(newest_known_addresses) = &maybe_newest_known_addresses {
                let bytes = newest_known_addresses.encode();
                a_mmap[..bytes.len()].copy_from_slice(&bytes);
                a_mmap.flush()?;
                b_mmap[..bytes.len()].copy_from_slice(&bytes);
                b_mmap.flush()?;
            }
        }

        let known_peers_slots = Arc::new(Mutex::new(KnownPeersSlots {
            a: a_mmap,
            b: b_mmap,
        }));

        Ok((maybe_newest_known_addresses, known_peers_slots))
    }

    /// Object constructor.
    pub fn new(config: KnownPeersManagerConfig) -> Result<Self, KnownPeersManagerPersistenceError> {
        let (maybe_newest_known_addresses, known_peers_slots) = if let Some(path) = &config.path {
            Self::init_file(path, config.cache_size)
                .map(|(known_addresses, slots)| (known_addresses, Some(slots)))?
        } else {
            (None, None)
        };

        let known_peers = maybe_newest_known_addresses
            .filter(|newest_known_addresses| {
                let time_since_unix_epoch = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Never before Unix epoch; qed");
                let known_peers_age = time_since_unix_epoch
                    .saturating_sub(Duration::from_secs(newest_known_addresses.timestamp));

                known_peers_age <= config.stale_known_peers_timeout
            })
            .map(EncodableKnownPeers::into_cache)
            .unwrap_or_else(|| LruMap::new(ByLength::new(config.cache_size)));

        Ok(Self {
            cache_need_saving: false,
            known_peers,
            networking_parameters_save_delay: Self::default_delay(),
            known_peers_slots,
            address_removed: Default::default(),
            config,
        })
    }

    /// Size of the backing file on disk
    pub fn file_size(cache_size: u32) -> usize {
        // *2 because we have a/b parts of the file
        Self::known_addresses_size(cache_size) * 2
    }

    /// Creates a reference to the `NetworkingParametersRegistry` trait implementation.
    pub fn boxed(self) -> Box<dyn KnownPeersRegistry> {
        Box::new(self)
    }

    // Create default delay for networking parameters.
    fn default_delay() -> Pin<Box<Fuse<Sleep>>> {
        Box::pin(sleep(Duration::from_secs(DATA_FLUSH_DURATION_SECS)).fuse())
    }

    fn single_peer_encoded_address_size() -> usize {
        let multiaddr = Multiaddr::from_str(
            "/ip4/127.0.0.1/tcp/1234/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp",
        )
        .expect("Valid multiaddr; qed");
        // Use multiaddr size that is 3x larger than typical, should be enough for most practical
        // cases
        multiaddr.to_vec().encoded_size() * 3
    }

    /// Size of single peer known addresses, this is an estimate and in some pathological cases peer
    /// will have to be rejected if encoding exceeds this length.
    fn single_peer_encoded_size() -> usize {
        // Peer ID encoding + compact encoding of the length of list of addresses + (length of a
        // single peer address entry + optional failure time) * number of entries
        PeerId::random().to_bytes().encoded_size()
            + Compact::compact_len(&(ADDRESSES_CACHE_SIZE))
            + (Self::single_peer_encoded_address_size() + Some(0u64).encoded_size())
                * ADDRESSES_CACHE_SIZE as usize
    }

    /// Size of known addresses and accompanying metadata.
    ///
    /// NOTE: This is max size that needs to be allocated on disk for successful write of a single
    /// `known_addresses` copy, the actual written data can occupy only a part of this size
    fn known_addresses_size(cache_size: u32) -> usize {
        // Timestamp (when was written) + compact encoding of the length of peer records + peer
        // records + checksum
        mem::size_of::<u64>()
            + Compact::compact_len(&(cache_size))
            + Self::single_peer_encoded_size() * cache_size as usize
            + Blake3Hash::SIZE
    }

    fn persistent_enabled(&self) -> bool {
        self.config.path.is_some()
    }

    #[cfg(test)]
    pub(crate) fn contains_address(&self, peer_id: &PeerId, address: &Multiaddr) -> bool {
        self.known_peers
            .peek(peer_id)
            .map(|addresses| addresses.peek(address).is_some())
            .unwrap_or_default()
    }
}

#[async_trait]
impl KnownPeersRegistry for KnownPeersManager {
    async fn add_known_peer(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>) {
        if self.config.ignore_peer_list.contains(&peer_id) {
            debug!(
                %peer_id,
                addr_num=addresses.len(),
                "Adding new peer addresses canceled (ignore list): {:?}",
                addresses
            );

            return;
        }

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
                    .get_or_insert(peer_id, || LruMap::new(ByLength::new(ADDRESSES_CACHE_SIZE)));

                if let Some(addresses) = self.known_peers.get(&peer_id) {
                    let previous_entry = addresses.peek(&addr).cloned().flatten();
                    addresses.insert(addr, None);
                    if let Some(previous_entry) = previous_entry {
                        trace!(%peer_id, "Address cache entry replaced: {:?}", previous_entry);
                    }
                }
            });

        self.cache_need_saving = true;
    }

    async fn remove_known_peer_addresses(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>) {
        trace!(%peer_id, "Remove peer addresses from the networking parameters registry: {:?}", addresses);

        let removed_addresses = remove_known_peer_addresses_internal(
            &mut self.known_peers,
            peer_id,
            addresses,
            self.config.failed_address_cache_removal_interval,
            self.config.failed_address_kademlia_removal_interval,
        );

        for event in removed_addresses {
            self.address_removed.call_simple(&event);
        }

        self.cache_need_saving = true;
    }

    fn remove_all_known_peer_addresses(&mut self, peer_id: PeerId) {
        trace!(%peer_id, "Remove all peer addresses from the networking parameters registry");

        self.known_peers.remove(&peer_id);

        self.cache_need_saving = true;
    }

    async fn all_known_peers(&mut self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        if !self.config.enable_known_peers_source {
            return Vec::new();
        }

        self.known_peers
            .iter()
            .map(|(&peer_id, addresses)| {
                (
                    peer_id,
                    addresses
                        .iter()
                        .map(|(addr, _failure_time)| addr.clone())
                        .collect(),
                )
            })
            .collect()
    }

    fn count_known_peers(&mut self) -> (usize, usize) {
        if !self.config.enable_known_peers_source {
            return (0, 0);
        }

        (
            self.known_peers.len(),
            self.known_peers
                .iter()
                .map(|(_peer, addresses)| addresses.len())
                .sum(),
        )
    }

    async fn run(&mut self) {
        if !self.persistent_enabled() {
            pending().await
        }

        loop {
            (&mut self.networking_parameters_save_delay).await;

            if let Some(known_peers_slots) = &self.known_peers_slots
                && self.cache_need_saving
            {
                let known_peers =
                    EncodableKnownPeers::from_cache(&self.known_peers, self.config.cache_size);
                let known_peers_slots = Arc::clone(known_peers_slots);
                let write_known_peers_fut = AsyncJoinOnDrop::new(
                    tokio::task::spawn_blocking(move || {
                        known_peers_slots
                            .lock()
                            .write_to_inactive_slot(&known_peers);
                    }),
                    // Abort has no effect on spawn_blocking tasks
                    false,
                );

                if let Err(error) = write_known_peers_fut.await {
                    error!(%error, "Failed to write known peers");
                }

                self.cache_need_saving = false;
            }
            self.networking_parameters_save_delay = KnownPeersManager::default_delay();
        }
    }

    fn on_unreachable_address(
        &mut self,
        handler: HandlerFn<PeerAddressRemovedEvent>,
    ) -> Option<HandlerId> {
        let handler_id = self.address_removed.add(handler);

        Some(handler_id)
    }
}

/// Removes a P2p protocol suffix from the multiaddress if any.
pub(crate) fn remove_p2p_suffix(mut address: Multiaddr) -> Multiaddr {
    let last_protocol = address.pop();

    if let Some(Protocol::P2p(_)) = &last_protocol {
        return address;
    }

    if let Some(protocol) = last_protocol {
        address.push(protocol)
    }

    address
}

/// Appends a P2p protocol suffix to the multiaddress if required.
pub(crate) fn append_p2p_suffix(peer_id: PeerId, mut address: Multiaddr) -> Multiaddr {
    let last_protocol = address.pop();

    if let Some(protocol) = last_protocol
        && !matches!(protocol, Protocol::P2p(..))
    {
        address.push(protocol)
    }
    address.push(Protocol::P2p(peer_id));

    address
}

// Testable implementation of the `remove_known_peer_addresses`
pub(super) fn remove_known_peer_addresses_internal(
    known_peers: &mut LruMap<PeerId, LruMap<Multiaddr, FailureTime>>,
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    expired_address_duration_persistent_storage: Duration,
    expired_address_duration_kademlia: Duration,
) -> Vec<PeerAddressRemovedEvent> {
    let mut address_removed_events = Vec::new();
    let now = SystemTime::now();

    addresses
        .into_iter()
        .map(remove_p2p_suffix)
        .for_each(|addr| {
            // if peer_id is present in the cache
            if let Some(addresses) = known_peers.peek_mut(&peer_id) {
                let last_address = addresses.peek(&addr).is_some() && addresses.len() == 1;
                // Get mutable reference to first_failed_time for the address without updating
                // the item's position in the cache
                if let Some(first_failed_time) = addresses.peek_mut(&addr) {
                    // if we failed previously with this address
                    if let Some(time) = first_failed_time {
                        // if we failed first time more than an hour ago (for Kademlia)
                        if *time + expired_address_duration_kademlia < now {
                            let address_removed = PeerAddressRemovedEvent {
                                peer_id,
                                address: addr.clone(),
                            };

                            address_removed_events.push(address_removed);

                            trace!(%peer_id, "Address was marked for removal from Kademlia: {:?}", addr);
                        }

                        // if we failed first time more than a day ago (for persistent cache)
                        if *time + expired_address_duration_persistent_storage < now {
                            // Remove a failed address
                            addresses.remove(&addr);

                            // If the last address for peer
                            if last_address {
                                known_peers.remove(&peer_id);

                                trace!(%peer_id, "Peer removed from the cache");
                            }

                            trace!(%peer_id, "Address removed from the persistent cache: {:?}", addr);
                        } else {
                            trace!(
                                %peer_id, "Saving failed connection attempt to a peer: {:?}",
                                addr
                            );
                        }
                    } else {
                        // Set failure time
                        first_failed_time.replace(now);

                        trace!(%peer_id, "Address marked for removal from the cache: {:?}", addr);
                    }
                }
            }
        });

    address_removed_events
}
