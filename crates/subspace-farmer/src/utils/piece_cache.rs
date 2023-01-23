use subspace_core_primitives::Piece;
use subspace_networking::libp2p::kad::record::Key;

/// Defines persistent piece cache interface.
// TODO: This should be elsewhere, like in `subspace-dsn`
pub trait PieceCache: Sync + Send + 'static {
    /// Check whether key should be cached based on current cache size and key-to-peer-id distance.
    fn should_cache(&self, key: &Key) -> bool;

    /// Add piece to the cache.
    fn add_piece(&mut self, key: Key, piece: Piece);

    /// Get piece from the cache.
    fn get_piece(&self, key: &Key) -> Option<Piece>;
}
