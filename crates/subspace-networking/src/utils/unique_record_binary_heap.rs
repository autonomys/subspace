#[cfg(test)]
mod tests;

use libp2p::kad::kbucket::Distance;
pub use libp2p::kad::record::Key;
pub use libp2p::PeerId;
use std::cmp::Ordering;
use std::collections::BTreeSet;

type KademliaBucketKey<T> = libp2p::kad::kbucket::Key<T>;

// Helper structure. It wraps Kademlia distance to a given peer for heap-metrics.
#[derive(Debug, Clone)]
struct RecordHeapKey {
    peer_distance: Distance,
    key: KademliaBucketKey<Key>,
}

impl RecordHeapKey {
    fn peer_distance(&self) -> Distance {
        self.peer_distance
    }

    fn new(peer_key: &KademliaBucketKey<PeerId>, key: KademliaBucketKey<Key>) -> Self {
        let peer_distance = key.distance(peer_key);
        Self { peer_distance, key }
    }
}

impl Eq for RecordHeapKey {}

impl PartialEq<Self> for RecordHeapKey {
    fn eq(&self, other: &Self) -> bool {
        self.peer_distance().eq(&other.peer_distance())
    }
}

impl PartialOrd<Self> for RecordHeapKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.peer_distance().partial_cmp(&other.peer_distance())
    }
}

impl Ord for RecordHeapKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.peer_distance().cmp(&other.peer_distance())
    }
}

/// Limited-size max binary heap for Kademlia records' keys.
///
/// The heap metrics depends on the Kademlia distance to the provided PeerId.
/// It maintains limited size and evicts (pops) items when this limited is exceeded.
/// Unique keys are only inserted once.
#[derive(Debug)]
pub struct UniqueRecordBinaryHeap {
    peer_key: KademliaBucketKey<PeerId>,
    set: BTreeSet<RecordHeapKey>,
    limit: usize,
}

impl UniqueRecordBinaryHeap {
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
    pub fn insert(&mut self, key: Key) -> Option<Key> {
        let key = RecordHeapKey::new(&self.peer_key, KademliaBucketKey::new(key));

        if !self.should_include_key_internal(&key) {
            return None;
        }

        let evicted = if self.is_limit_reached() {
            self.set.pop_last().map(|key| key.key.into_preimage())
        } else {
            None
        };

        self.set.insert(key);

        evicted
    }

    /// Removes a key from the heap.
    pub fn remove(&mut self, key: &Key) {
        let key = RecordHeapKey::new(&self.peer_key, KademliaBucketKey::new(key.clone()));
        self.set.remove(&key);
    }

    /// Checks whether we include the key
    pub fn should_include_key(&self, key: &Key) -> bool {
        let new_key = RecordHeapKey::new(&self.peer_key, KademliaBucketKey::new(key.clone()));

        self.should_include_key_internal(&new_key)
    }

    fn should_include_key_internal(&self, new_key: &RecordHeapKey) -> bool {
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
    pub fn keys(&self) -> impl Iterator<Item = &'_ Key> {
        self.set.iter().map(|key| key.key.preimage())
    }

    fn is_limit_reached(&self) -> bool {
        self.size() >= self.limit
    }
}
