use crate::piece_cache::PieceCache;
use sc_client_api::AuxStore;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use subspace_core_primitives::{
    ArchivedHistorySegment, FlatPieces, Piece, PieceIndex, PieceIndexHash,
};
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::ToMultihash;

#[derive(Default)]
pub struct TestAuxStore {
    store: RefCell<HashMap<Vec<u8>, Vec<u8>>>,
}

impl AuxStore for TestAuxStore {
    fn insert_aux<'a, 'b, 'c, I, D>(
        &self,
        insert: I,
        delete: D,
    ) -> sc_client_api::blockchain::Result<()>
    where
        'b: 'a,
        'c: 'a,
        I: IntoIterator<Item = &'a (&'c [u8], &'c [u8])>,
        D: IntoIterator<Item = &'a &'b [u8]>,
    {
        for pair in insert {
            self.store
                .borrow_mut()
                .insert(pair.0.to_vec(), pair.1.to_vec());
        }

        for key in delete {
            self.store.borrow_mut().remove(&key.to_vec());
        }

        Ok(())
    }

    fn get_aux(&self, key: &[u8]) -> sc_client_api::blockchain::Result<Option<Vec<u8>>> {
        Ok(self.store.borrow().get(&key.to_vec()).cloned())
    }
}

#[test]
fn basic() {
    let mut store = PieceCache::new(
        Arc::new(TestAuxStore::default()),
        ArchivedHistorySegment::SIZE as u64,
        PeerId::random(),
    );

    store
        .add_pieces(PieceIndex::default(), &ArchivedHistorySegment::default())
        .unwrap();

    let piece_index = PieceIndex::default();
    let piece_by_kad_key = store
        .get_piece_by_index_multihash(&PieceIndexHash::from(piece_index).to_multihash().to_bytes())
        .unwrap()
        .unwrap();

    let piece_res = store.get_piece(PieceIndexHash::from(piece_index)).unwrap();
    let piece = piece_res.unwrap();

    assert_eq!(piece_by_kad_key, piece);
}

#[test]
fn cache_nothing() {
    let mut store = PieceCache::new(Arc::new(TestAuxStore::default()), 0, PeerId::random());

    store
        .add_pieces(PieceIndex::default(), &ArchivedHistorySegment::default())
        .unwrap();

    let piece_index = PieceIndex::default();

    assert!(store
        .get_piece(PieceIndexHash::from(piece_index))
        .unwrap()
        .is_none());
}

#[test]
fn auto_cleanup() {
    let mut store = PieceCache::new(
        Arc::new(TestAuxStore::default()),
        Piece::SIZE as u64,
        PeerId::random(),
    );

    // Store the first piece
    store
        .add_pieces(PieceIndex::default(), &FlatPieces::new(1))
        .unwrap();
    // It must be stored
    store
        .get_piece(PieceIndexHash::from(PieceIndex::default()))
        .unwrap()
        .unwrap();

    // Store second piece
    store
        .add_pieces(PieceIndex::ONE, &FlatPieces::new(1))
        .unwrap();
    // It must be stored
    store
        .get_piece(PieceIndexHash::from(PieceIndex::ONE))
        .unwrap()
        .unwrap();
    // But the first piece is evicted because it exceeds cache size
    assert!(store
        .get_piece(PieceIndexHash::from(PieceIndex::default()))
        .unwrap()
        .is_none());
}
