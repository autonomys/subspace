//! Caching layer for pieces produced during archiving to make them available for some time after
//! they were produced.

#![warn(rust_2018_idioms, missing_docs, missing_debug_implementations)]

use parity_scale_codec::Encode;
use sc_client_api::backend::AuxStore;
use std::error::Error;
use std::fmt::Debug;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, Piece, PieceIndex};

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
}

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
        // TODO: Limit number of stored pieces
        Self { aux_store }
    }

    fn key(piece_index: PieceIndex) -> Vec<u8> {
        (Self::KEY_PREFIX, piece_index).encode()
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
        self.aux_store
            .insert_aux(
                keys.iter()
                    .zip(pieces.as_pieces())
                    .map(|(key, piece)| (key.as_slice(), piece))
                    .collect::<Vec<_>>()
                    .as_slice(),
                &[],
            )
            .map_err(Into::into)
    }

    /// TODO: Remove pieces from cache
    fn get_piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, Box<dyn Error>> {
        Ok(self
            .aux_store
            .get_aux(Self::key(piece_index).as_slice())?
            .map(|piece| {
                Piece::try_from(piece).expect("Always correct piece unless DB is corrupted; qed")
            }))
    }
}
