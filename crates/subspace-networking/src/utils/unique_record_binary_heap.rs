#[cfg(test)]
mod tests;

use crate::utils::multihash::ToMultihash;
pub use libp2p::kad::record::Key;
use libp2p::kad::KBucketDistance;
pub use libp2p::PeerId;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use subspace_core_primitives::PieceIndex;

type KademliaBucketKey<T> = libp2p::kad::KBucketKey<T>;

// Helper structure. It wraps Kademlia distance to a given peer for heap-metrics.
#[derive(Debug, Clone)]
struct RecordHeapKey<K> {
    peer_distance: KBucketDistance,
    key: K,
}

impl<K> RecordHeapKey<K>
where
    Key: From<K>,
    K: Clone,
{
    fn peer_distance(&self) -> KBucketDistance {
        self.peer_distance
    }

    fn new(peer_key: &KademliaBucketKey<PeerId>, key: K) -> Self {
        let peer_distance = KademliaBucketKey::new(Key::from(key.clone())).distance(peer_key);
        Self { peer_distance, key }
    }
}

impl<K> Eq for RecordHeapKey<K>
where
    Key: From<K>,
    K: Clone,
{
}

impl<K> PartialEq<Self> for RecordHeapKey<K>
where
    Key: From<K>,
    K: Clone,
{
    fn eq(&self, other: &Self) -> bool {
        self.peer_distance().eq(&other.peer_distance())
    }
}

impl<K> PartialOrd<Self> for RecordHeapKey<K>
where
    Key: From<K>,
    K: Clone,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K> Ord for RecordHeapKey<K>
where
    Key: From<K>,
    K: Clone,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.peer_distance().cmp(&other.peer_distance())
    }
}

/// Wrapper data structure that allows to work with keys as Kademlia keys, while not storing 32
/// bytes if the key itself is smaller, while potentially trading a bit of runtime performance.
#[derive(Debug, Copy, Clone)]
pub struct KeyWrapper<T>(pub T);

impl From<KeyWrapper<PieceIndex>> for Key {
    fn from(value: KeyWrapper<PieceIndex>) -> Self {
        value.0.hash().to_multihash().into()
    }
}

/// Limited-size max binary heap for Kademlia records' keys.
///
/// The heap metrics depends on the Kademlia distance to the provided PeerId.
/// It maintains limited size and evicts (pops) items when this limited is exceeded.
/// Unique keys are only inserted once.
#[derive(Clone, Debug)]
pub struct UniqueRecordBinaryHeap<K = Key> {
    peer_key: KademliaBucketKey<PeerId>,
    set: BTreeSet<RecordHeapKey<K>>,
    limit: usize,
}

impl<K> UniqueRecordBinaryHeap<K>
where
    Key: From<K>,
    K: Clone,
{
    /// Constructs a heap with given PeerId and size limit.
    pub fn new(peer_id: PeerId, limit: usize) -> Self {
        Self {
            peer_key: KademliaBucketKey::from(peer_id),
            set: BTreeSet::new(),
            limit,
        }
    }

    /// Returns heap-size
    pub fn size(&self) -> usize {
        self.set.len()
    }

    /// Insert a key in the heap evicting (popping) if the size limit is exceeded.
    ///
    /// If key doesn't pass [`UniqueRecordBinaryHeap::should_include_key`] check, it will be
    /// silently ignored.
    pub fn insert(&mut self, key: K) -> Option<K> {
        let key = RecordHeapKey::new(&self.peer_key, key);

        if !self.should_include_key_internal(&key) {
            return None;
        }

        let evicted = if self.is_limit_reached() {
            self.set.pop_last().map(|key| key.key)
        } else {
            None
        };

        self.set.insert(key);

        evicted
    }

    /// Removes a key from the heap.
    pub fn remove(&mut self, key: K) {
        let key = RecordHeapKey::new(&self.peer_key, key);
        self.set.remove(&key);
    }

    /// Checks whether we include the key.
    pub fn should_include_key(&self, key: K) -> bool {
        let key = RecordHeapKey::new(&self.peer_key, key);
        self.should_include_key_internal(&key)
    }

    /// Checks whether the heap contains the given key.
    pub fn contains_key(&self, key: K) -> bool {
        let key = RecordHeapKey::new(&self.peer_key, key);
        self.set.contains(&key)
    }

    fn should_include_key_internal(&self, new_key: &RecordHeapKey<K>) -> bool {
        if self.set.contains(new_key) {
            return false;
        }

        if !self.is_limit_reached() {
            return true;
        }

        let top_key = self.set.last();

        if let Some(top_key) = top_key {
            top_key > new_key
        } else {
            false // TODO: consider adding error here
        }
    }

    /// Iterator over all keys in arbitrary order
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &'_ K> + '_ {
        self.set.iter().map(|key| &key.key)
    }

    fn is_limit_reached(&self) -> bool {
        self.size() >= self.limit
    }
}
