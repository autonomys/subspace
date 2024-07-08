use libp2p::kad::KBucketDistance;
pub use libp2p::kad::RecordKey;
pub use libp2p::PeerId;

type KademliaBucketKey<T> = libp2p::kad::KBucketKey<T>;

/// Helper structure. It wraps Kademlia distance to a given peer for heap-metrics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DistanceForKey(KBucketDistance);

impl DistanceForKey {
    /// Creates a new `DistanceForKey` instance with the given `PeerId` and `K` key.
    ///
    /// The `distance` is calculated as the distance between the `KademliaBucketKey` derived
    /// from the `PeerId` and the `KademliaBucketKey` derived from the `K` key.
    pub fn new<K>(peer_id: PeerId, key: K) -> Self
    where
        RecordKey: From<K>,
    {
        Self::new_with_record_key(peer_id, RecordKey::from(key))
    }

    /// Creates a new `DistanceForKey` instance with the given `PeerId` and `RecordKey`.
    pub fn new_with_record_key(peer_id: PeerId, key: RecordKey) -> Self {
        let peer_key = KademliaBucketKey::from(peer_id);
        let peer_distance = KademliaBucketKey::new(key).distance(&peer_key);
        Self(peer_distance)
    }
}
