use crate::utils::piece_cache::PieceCache;
use std::borrow::Cow;
use std::iter;
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::PeerId;
use subspace_networking::ProviderStorage;
use tracing::trace;

#[derive(Clone)]
pub struct FarmerProviderStorage<LocalPieceCache: Clone> {
    local_peer_id: PeerId,
    piece_cache: LocalPieceCache,
}

impl<LocalPieceCache> FarmerProviderStorage<LocalPieceCache>
where
    LocalPieceCache: PieceCache + Clone,
{
    pub fn new(local_peer_id: PeerId, piece_cache: LocalPieceCache) -> Self {
        Self {
            local_peer_id,
            piece_cache,
        }
    }
}

impl<LocalPieceCache> ProviderStorage for FarmerProviderStorage<LocalPieceCache>
where
    LocalPieceCache: PieceCache + Clone,
{
    type ProvidedIter<'a> = impl Iterator<Item = Cow<'a, ProviderRecord>>
    where
        Self:'a;

    fn add_provider(
        &self,
        record: ProviderRecord,
    ) -> subspace_networking::libp2p::kad::store::Result<()> {
        trace!(key=?record.key, peer_id=%record.provider, "Attempt to add provider record.");

        Ok(())
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        if self.piece_cache.contains_key(key) {
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

    fn provided(&self) -> Self::ProvidedIter<'_> {
        iter::empty()
    }

    fn remove_provider(&self, key: &Key, peer_id: &PeerId) {
        trace!(?key, %peer_id, "Attempt to remove provider record.");
    }
}
