pub use libp2p::PeerId;
use libp2p::kad::KBucketDistance;
pub use libp2p::kad::RecordKey;
use std::cmp::Ordering;
use std::hash::Hash;

type KademliaBucketKey<T> = libp2p::kad::KBucketKey<T>;

/// Helper structure. It wraps Kademlia distance to a given peer for heap-metrics.
#[derive(Debug, Clone, Eq)]
pub struct KeyWithDistance {
    key: RecordKey,
    distance: KBucketDistance,
}

impl KeyWithDistance {
    /// Creates a new [`KeyWithDistance`] instance with the given `PeerId` and `K` key.
    ///
    /// The `distance` is calculated as the distance between the `KademliaBucketKey` derived
    /// from the `PeerId` and the `KademliaBucketKey` derived from the `K` key.
    pub fn new<K>(peer_id: PeerId, key: K) -> Self
    where
        RecordKey: From<K>,
    {
        Self::new_with_record_key(peer_id, RecordKey::from(key))
    }

    /// Creates a new [`KeyWithDistance`] instance with the given `PeerId` and `RecordKey`.
    pub fn new_with_record_key(peer_id: PeerId, key: RecordKey) -> Self {
        let peer_key = KademliaBucketKey::from(peer_id);
        let distance = KademliaBucketKey::new(key.as_ref()).distance(&peer_key);
        Self { key, distance }
    }

    /// Returns a reference to the record key.
    pub fn record_key(&self) -> &RecordKey {
        &self.key
    }
}

impl PartialEq for KeyWithDistance {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl PartialOrd for KeyWithDistance {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyWithDistance {
    fn cmp(&self, other: &Self) -> Ordering {
        self.distance.cmp(&other.distance)
    }
}

impl Hash for KeyWithDistance {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}
