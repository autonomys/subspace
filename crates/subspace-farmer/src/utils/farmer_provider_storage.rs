use crate::piece_cache::PieceCache;
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::PeerId;
use subspace_networking::ProviderStorage;

#[derive(Clone)]
pub struct FarmerProviderStorage {
    local_peer_id: PeerId,
    piece_cache: PieceCache,
}

impl FarmerProviderStorage {
    pub fn new(local_peer_id: PeerId, piece_cache: PieceCache) -> Self {
        Self {
            local_peer_id,
            piece_cache,
        }
    }
}

impl ProviderStorage for FarmerProviderStorage {
    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        if self.piece_cache.contains_piece(key.clone()) {
            // Note: We store our own provider records locally without local addresses
            // to avoid redundant storage and outdated addresses. Instead these are
            // acquired on demand when returning a `ProviderRecord` for the local node.
            vec![ProviderRecord {
                key: key.clone(),
                provider: self.local_peer_id,
                expires: None,
                addresses: Vec::new(),
            }]
        } else {
            Vec::new()
        }
    }
}
