#[cfg(test)]
mod tests;

use parity_scale_codec::Encode;
use sc_client_api::backend::AuxStore;
use std::borrow::Cow;
use std::error::Error;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, Piece, PieceIndex, PieceIndexHash, PIECE_SIZE};
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::Record;
use subspace_networking::{RecordStorage, ToMultihash};
use tracing::{trace, warn};

/// Cache of recently produced pieces in aux storage
pub struct PieceCache<AS> {
    aux_store: Arc<AS>,
    /// Limit for number of pieces to be stored in cache
    max_pieces_in_cache: PieceIndex,
}

impl<AS> Clone for PieceCache<AS> {
    fn clone(&self) -> Self {
        Self {
            aux_store: self.aux_store.clone(),
            max_pieces_in_cache: self.max_pieces_in_cache,
        }
    }
}

impl<AS> PieceCache<AS>
where
    AS: AuxStore,
{
    const KEY_PREFIX: &[u8] = b"piece_cache";

    /// Create new instance with specified size (in bytes)
    pub fn new(aux_store: Arc<AS>, cache_size: u64) -> Self {
        let max_pieces_in_cache: PieceIndex = cache_size / PIECE_SIZE as PieceIndex;

        Self {
            aux_store,
            max_pieces_in_cache,
        }
    }

    /// Get piece from storage
    pub fn get_piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, Box<dyn Error>> {
        self.get_piece_by_index_multihash(
            &PieceIndexHash::from_index(piece_index)
                .to_multihash()
                .to_bytes(),
        )
    }

    /// Add pieces to cache (likely as the result of archiving)
    pub fn add_pieces(
        &self,
        first_piece_index: PieceIndex,
        pieces: &FlatPieces,
    ) -> Result<(), Box<dyn Error>> {
        if self.max_pieces_in_cache == 0 {
            return Ok(());
        }

        let insert_keys = (first_piece_index..)
            .take(pieces.count())
            .map(Self::key)
            .collect::<Vec<_>>();

        let delete_keys = first_piece_index
            .checked_sub(self.max_pieces_in_cache)
            .map(|delete_pieces_from_index| {
                (delete_pieces_from_index..first_piece_index)
                    .map(Self::key)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

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

impl<'a, AS> RecordStorage<'a> for PieceCache<AS>
where
    AS: AuxStore + 'a,
{
    fn get(&'a self, key: &Key) -> Option<Cow<'_, Record>> {
        let get_result = self.get_piece_by_index_multihash(key.as_ref());

        match get_result {
            Ok(result) => result.map(|piece| {
                Cow::Owned(Record {
                    key: key.clone(),
                    value: piece.to_vec(),
                    publisher: None,
                    expires: None,
                })
            }),
            Err(err) => {
                warn!(
                    ?err,
                    ?key,
                    "Couldn't get a piece by key from aux piece store."
                );

                None
            }
        }
    }

    fn put(&mut self, rec: Record) -> subspace_networking::libp2p::kad::store::Result<()> {
        trace!(key=?rec.key, "Attempted to put a record to the aux piece record store.");

        Ok(())
    }

    fn remove(&mut self, key: &Key) {
        trace!(
            ?key,
            "Attempted to remove a record from the aux piece record store."
        );
    }
}
