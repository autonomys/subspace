use crate::piece_cache::PieceCache;
use sc_client_api::AuxStore;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, PieceIndexHash, PIECES_IN_SEGMENT, PIECE_SIZE};
use subspace_networking::{RecordStorage, ToMultihash};

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
    let store = PieceCache::new(
        Arc::new(TestAuxStore::default()),
        u64::from(PIECES_IN_SEGMENT) * PIECE_SIZE as u64,
    );

    store
        .add_pieces(0, &FlatPieces::new(PIECES_IN_SEGMENT as usize))
        .unwrap();

    let piece_index = 0u64;

    let piece_by_kad_key = store
        .get(
            &PieceIndexHash::from_index(piece_index)
                .to_multihash()
                .into(),
        )
        .unwrap()
        .value
        .clone();

    let piece_res = store.get_piece(piece_index).unwrap();
    let piece = piece_res.unwrap();

    assert_eq!(piece_by_kad_key.as_slice(), piece.as_ref());
}

#[test]
fn cache_nothing() {
    let store = PieceCache::new(Arc::new(TestAuxStore::default()), 0);

    store
        .add_pieces(0, &FlatPieces::new(PIECES_IN_SEGMENT as usize))
        .unwrap();

    let piece_index = 0u64;

    assert!(store.get_piece(piece_index).unwrap().is_none());
}

#[test]
fn auto_cleanup() {
    let store = PieceCache::new(Arc::new(TestAuxStore::default()), PIECE_SIZE as u64);

    // Store the first piece
    store.add_pieces(0, &FlatPieces::new(1)).unwrap();
    // It must be stored
    store.get_piece(0).unwrap().unwrap();

    // Store second piece
    store.add_pieces(1, &FlatPieces::new(1)).unwrap();
    // It must be stored
    store.get_piece(1).unwrap().unwrap();
    // But the first piece is evicted because it exceeds cache size
    assert!(store.get_piece(0).unwrap().is_none());
}
