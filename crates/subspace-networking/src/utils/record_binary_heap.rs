use libp2p::kad::kbucket::Distance;
pub use libp2p::kad::record::Key;
pub use libp2p::PeerId;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

type KademliaBucketKey<T> = libp2p::kad::kbucket::Key<T>;

// Helper structure. It wraps Kademlia distance to a given peer for heap-metrics.
#[derive(Debug, Clone)]
struct RecordHeapKey {
    peer_key: KademliaBucketKey<PeerId>,
    key: KademliaBucketKey<Key>,
}

impl RecordHeapKey {
    fn peer_distance(&self) -> Distance {
        self.key.distance(&self.peer_key)
    }

    fn new(peer_key: KademliaBucketKey<PeerId>, key: KademliaBucketKey<Key>) -> Self {
        Self { peer_key, key }
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

#[derive(Debug, Clone)]
/// Limited-size max binary heap for Kademlia records' keys.
/// The heap metrics depends on the Kademlia distance to the provided PeerId.
/// It maintains limited size and evicts (pops) items when this limited is exceeded.
pub struct RecordBinaryHeap {
    peer_key: KademliaBucketKey<PeerId>,
    max_heap: BinaryHeap<RecordHeapKey>,
    limit: usize,
}

impl RecordBinaryHeap {
    /// Constructs a heap with given PeerId and size limit.
    pub fn new(peer_id: PeerId, limit: usize) -> Self {
        Self {
            peer_key: KademliaBucketKey::from(peer_id),
            max_heap: BinaryHeap::new(),
            limit,
        }
    }

    /// Returns heap-size
    pub fn size(&self) -> usize {
        self.max_heap.len()
    }

    /// Insert a key in the heap evicting (popping) if the size limit is exceeded.
    pub fn insert(&mut self, key: Key) -> Option<Key> {
        let heap_key = RecordHeapKey::new(self.peer_key.clone(), KademliaBucketKey::new(key));
        self.max_heap.push(heap_key);

        if self.is_limit_exceeded() {
            let evicted = self.max_heap.pop();

            return evicted.map(|key| key.key.preimage().clone());
        }

        None
    }

    /// Removes a key from the heap.
    pub fn remove(&mut self, key: &Key) {
        self.max_heap.retain(|k| {
            *k != RecordHeapKey::new(self.peer_key.clone(), KademliaBucketKey::new(key.clone()))
        });
    }

    /// Checks whether we include the key
    pub fn should_include_key(&self, key: &Key) -> bool {
        if !self.is_limit_reached() {
            return true;
        }

        let new_key =
            RecordHeapKey::new(self.peer_key.clone(), KademliaBucketKey::new(key.clone()));
        let top_key = self.max_heap.peek().cloned();

        if let Some(top_key) = top_key {
            top_key > new_key
        } else {
            false // TODO: consider adding error here
        }
    }

    fn is_limit_reached(&self) -> bool {
        self.size() >= self.limit
    }

    fn is_limit_exceeded(&self) -> bool {
        self.size() > self.limit
    }
}
