#[cfg(test)]
mod tests;

use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_client_api::backend::AuxStore;
use std::collections::BTreeSet;
use std::error::Error;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, Piece, PieceIndex, PieceIndexHash};
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::LocalRecordProvider;
use tracing::info;

const LOCAL_PROVIDED_KEYS: &[u8] = b"LOCAL_PROVIDED_KEYS";

/// Cache of recently produced pieces in aux storage
pub struct PieceCache<AS> {
    aux_store: Arc<AS>,
    /// Limit for number of pieces to be stored in cache
    max_pieces_in_cache: PieceIndex,
    /// Peer ID of the current node.
    local_peer_id: PeerId,
    /// Local provided keys
    local_provided_keys: Arc<Mutex<PieceIndexKeyCollection>>,
}

impl<AS> Clone for PieceCache<AS> {
    fn clone(&self) -> Self {
        Self {
            aux_store: self.aux_store.clone(),
            max_pieces_in_cache: self.max_pieces_in_cache,
            local_peer_id: self.local_peer_id,
            local_provided_keys: self.local_provided_keys.clone(),
        }
    }
}

impl<AS> PieceCache<AS>
where
    AS: AuxStore,
{
    const KEY_PREFIX: &[u8] = b"piece_cache";

    /// Create new instance with specified size (in bytes)
    pub fn new(aux_store: Arc<AS>, cache_size: u64, local_peer_id: PeerId) -> Self {
        let max_pieces_in_cache = PieceIndex::from(cache_size / Piece::SIZE as u64);
        let local_provided_keys = Self::get_local_provided_keys(aux_store.clone())
            .expect("DB loading should succeed.")
            .unwrap_or_default();

        if local_provided_keys.is_empty() {
            info!("New storage provider initialized.");
        } else {
            info!(
                "Storage provider cache loaded - {} items.",
                local_provided_keys.len()
            );
        }

        Self {
            aux_store,
            max_pieces_in_cache,
            local_peer_id,
            local_provided_keys: Arc::new(Mutex::new(local_provided_keys)),
        }
    }

    fn get_local_provided_keys(
        aux_store: Arc<AS>,
    ) -> Result<Option<PieceIndexKeyCollection>, Box<dyn Error>> {
        Ok(aux_store.get_aux(LOCAL_PROVIDED_KEYS)?.map(|data| {
            let collection: PieceIndexKeyCollection =
                data.try_into().expect("DB loading should succeed.");

            collection
        }))
    }

    fn write_local_provided_keys(
        &self,
        local_provided_keys: PieceIndexKeyCollection,
    ) -> Result<(), Box<dyn Error>> {
        // TODO: Could be a slow process. We need to optimize it ASAP!
        self.aux_store
            .insert_aux(
                &vec![(LOCAL_PROVIDED_KEYS, local_provided_keys.encode().as_slice())],
                &Vec::new(),
            )
            .map_err(Into::into)
    }

    /// Get piece from storage
    pub fn get_piece(
        &self,
        piece_index_hash: PieceIndexHash,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        self.get_piece_by_index_multihash(&piece_index_hash.to_multihash().to_bytes())
    }

    /// Add pieces to cache (likely as the result of archiving)
    pub fn add_pieces(
        &mut self,
        first_piece_index: PieceIndex,
        pieces: &FlatPieces,
    ) -> Result<(), Box<dyn Error>> {
        if self.max_pieces_in_cache == PieceIndex::ZERO {
            return Ok(());
        }

        let insert_indexes = (first_piece_index..).take(pieces.len()).collect::<Vec<_>>();

        let delete_indexes = u64::from(first_piece_index)
            .checked_sub(u64::from(self.max_pieces_in_cache))
            .map(PieceIndex::from)
            .map(|delete_pieces_from_index| {
                (delete_pieces_from_index..first_piece_index).collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let insert_keys = insert_indexes
            .iter()
            .cloned()
            .map(Self::key)
            .collect::<Vec<_>>();

        let delete_keys = delete_indexes
            .iter()
            .cloned()
            .map(Self::key)
            .collect::<Vec<_>>();

        self.aux_store.insert_aux(
            &insert_keys
                .iter()
                .zip(pieces.iter())
                .map(|(key, piece)| (key.as_slice(), piece.as_ref()))
                .collect::<Vec<_>>(),
            &delete_keys
                .iter()
                .map(|key| key.as_slice())
                .collect::<Vec<_>>(),
        )?;

        let local_provided_keys = {
            let mut local_provided_keys = self.local_provided_keys.lock();

            local_provided_keys.remove_piece_indexes(&delete_indexes);
            local_provided_keys.insert_piece_indexes(&insert_indexes);

            local_provided_keys.clone()
        };

        self.write_local_provided_keys(local_provided_keys)?;

        Ok(())
    }

    fn key(piece_index: PieceIndex) -> Vec<u8> {
        Self::key_from_bytes(&piece_index.hash().to_multihash().to_bytes())
    }

    fn key_from_bytes(bytes: &[u8]) -> Vec<u8> {
        (Self::KEY_PREFIX, bytes).encode()
    }

    fn get_piece_by_index_multihash(
        &self,
        piece_index_multihash: &[u8],
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        Ok(self
            .aux_store
            .get_aux(Self::key_from_bytes(piece_index_multihash).as_slice())?
            .map(|piece| {
                Piece::try_from(piece).expect("Always correct piece unless DB is corrupted; qed")
            }))
    }
}

#[derive(Clone, Debug, Decode, Encode, Default)]
struct PieceIndexKeyCollection {
    piece_index_keys: BTreeSet<Vec<u8>>,
}

impl PieceIndexKeyCollection {
    fn insert_piece_indexes(&mut self, indexes: &[PieceIndex]) {
        for piece_index in indexes {
            let key: Key = piece_index.hash().to_multihash().into();
            self.piece_index_keys.insert(key.to_vec());
        }
    }

    fn remove_piece_indexes(&mut self, indexes: &[PieceIndex]) {
        for piece_index in indexes {
            let key: Key = piece_index.hash().to_multihash().into();
            self.piece_index_keys.remove::<Vec<_>>(&key.to_vec());
        }
    }

    fn is_empty(&self) -> bool {
        self.piece_index_keys.is_empty()
    }

    fn len(&self) -> usize {
        self.piece_index_keys.len()
    }
}

impl From<PieceIndexKeyCollection> for Vec<u8> {
    #[inline]
    fn from(value: PieceIndexKeyCollection) -> Self {
        value.encode()
    }
}

impl TryFrom<Vec<u8>> for PieceIndexKeyCollection {
    type Error = parity_scale_codec::Error;

    #[inline]
    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        PieceIndexKeyCollection::decode(&mut data.as_slice()).map(Into::into)
    }
}

impl<AS> LocalRecordProvider for PieceCache<AS>
where
    AS: AuxStore,
{
    fn record(&self, key: &Key) -> Option<ProviderRecord> {
        if self
            .local_provided_keys
            .lock()
            .piece_index_keys
            .contains(&key.to_vec())
        {
            Some(ProviderRecord {
                key: key.clone(),
                provider: self.local_peer_id,
                expires: None,
                addresses: vec![], // Kademlia adds addresses for local providers
            })
        } else {
            None
        }
    }
}
