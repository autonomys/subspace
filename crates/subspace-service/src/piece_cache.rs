#[cfg(test)]
mod tests;

use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_client_api::backend::AuxStore;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::error::Error;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, Piece, PieceIndex, PieceIndexHash, PIECE_SIZE};
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::ProviderRecord;
use subspace_networking::libp2p::PeerId;
use subspace_networking::{ProviderStorage, ToMultihash};
use tracing::{info, trace, warn};

const LOCAL_PROVIDED_KEYS: &[u8] = b"LOCAL_PROVIDED_KEYS";

/// Cache of recently produced pieces in aux storage
pub struct PieceCache<AS> {
    aux_store: Arc<AS>,
    /// Limit for number of pieces to be stored in cache
    max_pieces_in_cache: PieceIndex,
    /// Peer ID of the current node.
    local_peer_id: PeerId,
    /// Local provided keys
    local_provided_keys: Arc<Mutex<BTreeSet<PieceIndex>>>,
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
        let max_pieces_in_cache: PieceIndex = cache_size / PIECE_SIZE as PieceIndex;
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
    ) -> Result<Option<BTreeSet<PieceIndex>>, Box<dyn Error>> {
        Ok(aux_store.get_aux(LOCAL_PROVIDED_KEYS)?.map(|data| {
            let collection: ParityDbKeyCollection =
                data.try_into().expect("DB loading should succeed.");

            collection.set
        }))
    }

    fn write_local_provided_keys(
        &self,
        local_provided_keys: BTreeSet<PieceIndex>,
    ) -> Result<(), Box<dyn Error>> {
        // TODO: Could be a slow process. We need to optimize it ASAP!
        self.aux_store
            .insert_aux(
                &vec![(
                    LOCAL_PROVIDED_KEYS,
                    ParityDbKeyCollection {
                        set: local_provided_keys,
                    }
                    .encode()
                    .as_slice(),
                )],
                &Vec::new(),
            )
            .map_err(Into::into)
    }

    /// Get piece from storage
    pub fn get_piece(
        &self,
        piece_index_hash: PieceIndexHash,
    ) -> Result<Option<Piece>, Box<dyn Error>> {
        self.get_piece_by_index_multihash(&piece_index_hash.to_multihash().to_bytes())
    }

    /// Add pieces to cache (likely as the result of archiving)
    pub fn add_pieces(
        &mut self,
        first_piece_index: PieceIndex,
        pieces: &FlatPieces,
    ) -> Result<(), Box<dyn Error>> {
        if self.max_pieces_in_cache == 0 {
            return Ok(());
        }

        let insert_indexes = (first_piece_index..)
            .take(pieces.count())
            .collect::<Vec<_>>();

        let delete_indexes = first_piece_index
            .checked_sub(self.max_pieces_in_cache)
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
                .zip(pieces.as_pieces())
                .map(|(key, piece)| (key.as_slice(), piece))
                .collect::<Vec<_>>(),
            &delete_keys
                .iter()
                .map(|key| key.as_slice())
                .collect::<Vec<_>>(),
        )?;

        let local_provided_keys = {
            let mut local_provided_keys = self.local_provided_keys.lock();

            for piece_index in delete_indexes {
                local_provided_keys.remove(&piece_index);
            }

            for piece_index in insert_indexes {
                local_provided_keys.insert(piece_index);
            }

            local_provided_keys.clone()
        };

        self.write_local_provided_keys(local_provided_keys)?;

        Ok(())
    }

    fn key(piece_index: PieceIndex) -> Vec<u8> {
        Self::key_from_bytes(
            &PieceIndexHash::from_index(piece_index)
                .to_multihash()
                .to_bytes(),
        )
    }

    fn key_from_bytes(bytes: &[u8]) -> Vec<u8> {
        (Self::KEY_PREFIX, bytes).encode()
    }

    fn get_piece_by_index_multihash(
        &self,
        piece_index_multihash: &[u8],
    ) -> Result<Option<Piece>, Box<dyn Error>> {
        Ok(self
            .aux_store
            .get_aux(Self::key_from_bytes(piece_index_multihash).as_slice())?
            .map(|piece| {
                Piece::try_from(piece).expect("Always correct piece unless DB is corrupted; qed")
            }))
    }
}

#[derive(Clone, Debug, Decode, Encode, Default)]
struct ParityDbKeyCollection {
    pub set: BTreeSet<PieceIndex>,
}

impl From<ParityDbKeyCollection> for Vec<u8> {
    fn from(value: ParityDbKeyCollection) -> Self {
        value.encode()
    }
}

impl TryFrom<Vec<u8>> for ParityDbKeyCollection {
    type Error = parity_scale_codec::Error;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        ParityDbKeyCollection::decode(&mut data.as_slice()).map(Into::into)
    }
}

impl<AS> ProviderStorage for PieceCache<AS>
where
    AS: AuxStore,
{
    type ProvidedIter<'a> = AuxStoreProviderRecordIterator<'a, AS> where Self:'a;

    fn add_provider(
        &mut self,
        rec: ProviderRecord,
    ) -> subspace_networking::libp2p::kad::store::Result<()> {
        trace!(key=?rec.key, "Attempted to put a provider record to the aux piece record store.");

        Ok(())
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        let get_result = self.get_piece_by_index_multihash(key.as_ref());

        let providers = match get_result {
            Ok(result) => result.map(|_| {
                vec![ProviderRecord {
                    key: key.clone(),
                    provider: self.local_peer_id,
                    expires: None,
                    addresses: vec![], // TODO: add address hints
                }]
            }),
            Err(err) => {
                warn!(
                    ?err,
                    ?key,
                    "Couldn't get a piece by key from aux piece store."
                );

                None
            }
        };

        providers.unwrap_or_default()
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        let pieces_indexes = {
            self.local_provided_keys
                .lock()
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        };

        AuxStoreProviderRecordIterator::new(pieces_indexes, self.clone())
    }

    fn remove_provider(&mut self, key: &Key, peer_id: &PeerId) {
        trace!(
            ?key,
            %peer_id,
            "Attempted to remove a provider record from the aux piece record store."
        );
    }
}

pub struct AuxStoreProviderRecordIterator<'a, AS> {
    piece_indexes: Vec<PieceIndex>,
    piece_indexes_cursor: usize,
    piece_cache: PieceCache<AS>,
    marker: PhantomData<&'a ()>,
}

impl<'a, AS: AuxStore> AuxStoreProviderRecordIterator<'a, AS> {
    pub fn new(piece_indexes: Vec<PieceIndex>, piece_cache: PieceCache<AS>) -> Self {
        Self {
            piece_indexes,
            piece_indexes_cursor: 0,
            piece_cache,
            marker: PhantomData,
        }
    }
}

impl<'a, AS: AuxStore> Iterator for AuxStoreProviderRecordIterator<'a, AS> {
    type Item = Cow<'a, ProviderRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.piece_indexes.len() == self.piece_indexes_cursor {
            return None; // iterator finished
        }

        let peer_id = self.piece_cache.local_peer_id;
        let piece_index = self.piece_indexes[self.piece_indexes_cursor];
        let piece_index_hash = PieceIndexHash::from_index(piece_index);
        let key = Key::from(piece_index_hash.to_multihash());

        let result = self
            .piece_cache
            .get_piece(piece_index_hash)
            .ok()
            .flatten()
            .map(move |_| ProviderRecord {
                key: key.clone(),
                provider: peer_id,
                expires: None,
                addresses: vec![], // TODO: add address hints
            })
            .map(Cow::Owned);

        self.piece_indexes_cursor += 1; // increment iterator

        result
    }
}
