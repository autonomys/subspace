use parity_scale_codec::Encode;
use sc_client_api::backend::AuxStore;
use std::borrow::Cow;
use std::error::Error;
use std::sync::Arc;
use subspace_core_primitives::{
    FlatPieces, Piece, PieceIndex, PieceIndexHash, PIECES_IN_SEGMENT, PIECE_SIZE,
};
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::Record;
use subspace_networking::{RecordStorage, ToMultihash};
use tracing::{trace, warn};

// Defines how often we clear pieces from cache.
const TOLERANCE_SEGMENTS_NUMBER: u64 = 2;

pub(crate) struct AuxRecordStorage<AS> {
    aux_store: Arc<AS>,
    max_segments_number_in_cache: u64,
}

impl<AS> Clone for AuxRecordStorage<AS> {
    fn clone(&self) -> Self {
        Self {
            aux_store: self.aux_store.clone(),
            max_segments_number_in_cache: self.max_segments_number_in_cache,
        }
    }
}

impl<AS> AuxRecordStorage<AS>
where
    AS: AuxStore,
{
    const KEY_PREFIX: &[u8] = b"piece_cache";

    pub(crate) fn new(aux_store: Arc<AS>, cache_size: u64) -> Self {
        let max_segments_number_in_cache =
            cache_size / (PIECES_IN_SEGMENT as u64 * PIECE_SIZE as u64);

        Self {
            aux_store,
            max_segments_number_in_cache,
        }
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

    /// Returns configured maximum configured segments number in the cache.
    pub(crate) fn max_segments_number_in_cache(&self) -> u64 {
        self.max_segments_number_in_cache
    }

    /// Add pieces to cache
    pub(crate) fn add_pieces(
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
            .checked_sub(self.max_segments_number_in_cache() + TOLERANCE_SEGMENTS_NUMBER - 1)
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

    pub(crate) fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error>> {
        self.get_piece_by_key(Self::index_to_multihash(piece_index))
    }

    pub(crate) fn get_piece_by_key(&self, key: Vec<u8>) -> Result<Option<Piece>, Box<dyn Error>> {
        Ok(self
            .aux_store
            .get_aux(Self::key_from_bytes(key).as_slice())?
            .map(|piece| {
                Piece::try_from(piece).expect("Always correct piece unless DB is corrupted; qed")
            }))
    }
}

impl<'a, AS> RecordStorage<'a> for AuxRecordStorage<AS>
where
    AS: AuxStore + 'a,
{
    fn get(&'a self, key: &Key) -> Option<Cow<'_, Record>> {
        let get_result = self.get_piece_by_key(key.to_vec());

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
