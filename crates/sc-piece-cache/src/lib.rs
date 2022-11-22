//! Caching layer for pieces produced during archiving to make them available for some time after
//! they were produced.

#![warn(rust_2018_idioms, missing_docs, missing_debug_implementations)]

#[cfg(test)]
mod tests;

use parity_scale_codec::Encode;
use sc_client_api::backend::AuxStore;
use std::error::Error;
use std::fmt::Debug;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, Piece, PieceIndex, PieceIndexHash, PIECES_IN_SEGMENT};
use subspace_networking::ToMultihash;

/// Defines maximum segments number stored in the cache (as pieces).
pub const MAX_SEGMENTS_NUMBER_IN_CACHE: u64 = 32; // ~ 1 GB

// Defines how often we clear pieces from cache.
pub(crate) const TOLERANCE_SEGMENTS_NUMBER: u64 = 2;

/// Caching layer for pieces produced during archiving to make them available for some time after
/// they were produced.
pub trait PieceCache: Clone {
    /// Add pieces to cache
    fn add_pieces(
        &self,
        first_piece_index: PieceIndex,
        pieces: &FlatPieces,
    ) -> Result<(), Box<dyn Error>>;

    /// Get piece from cache
    fn get_piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, Box<dyn Error>>;

    /// Get piece from cache using key bytes (expects Multihash.to_bytes() output)
    fn get_piece_by_key(&self, key: Vec<u8>) -> Result<Option<Piece>, Box<dyn Error>>;
}

// TODO: Refactor AuxPieceCache once we remove RPC endpoint.
/// Cache of pieces in aux storage
#[derive(Debug)]
pub struct AuxPieceCache<AS> {
    aux_store: Arc<AS>,
}

impl<AS> Clone for AuxPieceCache<AS> {
    fn clone(&self) -> Self {
        Self {
            aux_store: Arc::clone(&self.aux_store),
        }
    }
}

impl<AS> AuxPieceCache<AS>
where
    AS: AuxStore,
{
    const KEY_PREFIX: &[u8] = b"piece_cache";

    /// Create new instance
    pub fn new(aux_store: Arc<AS>) -> Self {
        Self { aux_store }
    }

    fn key(piece_index: PieceIndex) -> Vec<u8> {
        Self::key_from_bytes(Self::index_to_multihash(piece_index))
    }

    fn key_from_bytes(bytes: Vec<u8>) -> Vec<u8> {
        (Self::KEY_PREFIX, bytes).encode()
    }

    fn index_to_multihash(piece_index: PieceIndex) -> Vec<u8> {
        PieceIndexHash::from_index(piece_index)
            .to_multihash()
            .to_bytes()
    }
}

impl<AS> PieceCache for AuxPieceCache<AS>
where
    AS: AuxStore,
{
    /// Add pieces to cache
    fn add_pieces(
        &self,
        first_piece_index: PieceIndex,
        pieces: &FlatPieces,
    ) -> Result<(), Box<dyn Error>> {
        let keys = (first_piece_index..)
            .take(pieces.count())
            .map(Self::key)
            .collect::<Vec<_>>();
        self.aux_store.insert_aux(
            keys.iter()
                .zip(pieces.as_pieces())
                .map(|(key, piece)| (key.as_slice(), piece))
                .collect::<Vec<_>>()
                .as_slice(),
            &[],
        )?;

        // Remove obsolete pieces once in TOLERANCE_SEGMENTS_NUMBER times
        let segment_index = first_piece_index / PIECES_IN_SEGMENT as u64;

        let starting_piece_index = segment_index
            .checked_sub(MAX_SEGMENTS_NUMBER_IN_CACHE + TOLERANCE_SEGMENTS_NUMBER - 1)
            .map(|starting_segment_index| starting_segment_index * PIECES_IN_SEGMENT as u64);

        let pieces_to_delete_number =
            (TOLERANCE_SEGMENTS_NUMBER * PIECES_IN_SEGMENT as u64) as usize;
        if let Some(starting_piece_index) = starting_piece_index {
            let keys = (starting_piece_index..)
                .take(pieces_to_delete_number)
                .map(Self::key)
                .collect::<Vec<_>>();

            self.aux_store.insert_aux(
                &[],
                keys.iter()
                    .map(|key| key.as_slice())
                    .collect::<Vec<_>>()
                    .as_slice(),
            )?;
        }

        Ok(())
    }

    fn get_piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, Box<dyn Error>> {
        self.get_piece_by_key(Self::index_to_multihash(piece_index))
    }

    fn get_piece_by_key(&self, key: Vec<u8>) -> Result<Option<Piece>, Box<dyn Error>> {
        Ok(self
            .aux_store
            .get_aux(Self::key_from_bytes(key).as_slice())?
            .map(|piece| {
                Piece::try_from(piece).expect("Always correct piece unless DB is corrupted; qed")
            }))
    }
}
