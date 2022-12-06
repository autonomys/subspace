pub mod piece_cache;

use piece_cache::AuxPieceCache;
use sc_client_api::AuxStore;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::{PieceIndex, PieceIndexHash, PIECES_IN_SEGMENT};
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::kad::Record;
use subspace_networking::{RecordStorage, ToMultihash};
use tracing::{trace, warn};

pub(crate) type SegmentIndexGetter = Arc<dyn Fn() -> u64 + Send + Sync + 'static>;

pub(crate) struct AuxRecordStorage<AS> {
    piece_cache: AuxPieceCache<AS>,
    // TODO: Remove it when we delete RPC-endpoint for farmers.
    last_segment_index_getter: SegmentIndexGetter,
}

impl<AS> AuxRecordStorage<AS> {
    pub(crate) fn new(
        piece_cache: AuxPieceCache<AS>,
        last_segment_index_getter: SegmentIndexGetter,
    ) -> Self {
        Self {
            piece_cache,
            last_segment_index_getter,
        }
    }
}

impl<'a, AS: AuxStore> RecordStorage<'a> for AuxRecordStorage<AS> {
    type RecordsIter = AuxStoreRecordIterator<'a, AS>;

    fn get(&'a self, key: &Key) -> Option<Cow<'_, Record>> {
        let get_result = self.piece_cache.get_piece_by_key(key.to_vec());

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

    fn records(&'a self) -> Self::RecordsIter {
        let segment_index = (self.last_segment_index_getter)();

        let starting_piece_index: PieceIndex = segment_index
            .saturating_sub(self.piece_cache.max_segments_number_in_cache())
            * PIECES_IN_SEGMENT as u64;

        AuxStoreRecordIterator::new(starting_piece_index, self.piece_cache.clone())
    }
}

pub(crate) struct AuxStoreRecordIterator<'a, AS> {
    next_piece_index: PieceIndex,
    piece_cache: AuxPieceCache<AS>,
    marker: PhantomData<&'a ()>,
}

impl<'a, AS: AuxStore> AuxStoreRecordIterator<'a, AS> {
    pub(crate) fn new(first_piece_index: PieceIndex, piece_cache: AuxPieceCache<AS>) -> Self {
        Self {
            next_piece_index: first_piece_index,
            piece_cache,
            marker: PhantomData,
        }
    }
}

impl<'a, AS: AuxStore> Iterator for AuxStoreRecordIterator<'a, AS> {
    type Item = Cow<'a, Record>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = Key::from(PieceIndexHash::from_index(self.next_piece_index).to_multihash());

        let result = self
            .piece_cache
            .get_piece_by_key(key.to_vec())
            .ok()
            .flatten()
            .map(move |piece| Record {
                key,
                value: piece.to_vec(),
                publisher: None,
                expires: None,
            })
            .map(Cow::Owned);

        self.next_piece_index += 1;

        result
    }
}
