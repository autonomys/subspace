use crate::{AuxPieceCache, PieceCache, ONE_GB, TOLERANCE_SEGMENTS_NUMBER};
use sc_client_api::AuxStore;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, PieceIndexHash, PIECES_IN_SEGMENT};
use subspace_networking::ToMultihash;

#[derive(Default)]
pub struct TestAuxStore {
    store: RefCell<HashMap<Vec<u8>, Vec<u8>>>,
}

impl AuxStore for TestAuxStore {
    fn insert_aux<
        'a,
        'b: 'a,
        'c: 'a,
        I: IntoIterator<Item = &'a (&'c [u8], &'c [u8])>,
        D: IntoIterator<Item = &'a &'b [u8]>,
    >(
        &self,
        insert: I,
        delete: D,
    ) -> sc_client_api::blockchain::Result<()> {
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
fn adding_retrieval_operations_work() {
    let store = AuxPieceCache::new(Arc::new(TestAuxStore::default()), ONE_GB);

    store
        .add_pieces(0, &FlatPieces::new(PIECES_IN_SEGMENT as usize))
        .unwrap();

    let piece_index = 0u64;

    let piece_2_res = store
        .get_piece_by_key(
            PieceIndexHash::from_index(piece_index)
                .to_multihash()
                .to_bytes(),
        )
        .unwrap();
    let piece_2 = piece_2_res.unwrap();

    let piece_1_res = store.get_piece(piece_index).unwrap();
    let piece_1 = piece_1_res.unwrap();

    assert_eq!(piece_1, piece_2);
}

#[test]
fn test_segment_deletion() {
    let store = AuxPieceCache::new(Arc::new(TestAuxStore::default()), ONE_GB);

    for i in 0..store.max_segments_number_in_cache() {
        store
            .add_pieces(
                i * PIECES_IN_SEGMENT as u64,
                &FlatPieces::new(PIECES_IN_SEGMENT as usize),
            )
            .unwrap();

        assert!(store.get_piece(0).unwrap().is_some());
        assert!(store
            .get_piece(PIECES_IN_SEGMENT as u64 - 1)
            .unwrap()
            .is_some());
        assert!(store
            .get_piece(i * PIECES_IN_SEGMENT as u64)
            .unwrap()
            .is_some());
        assert!(store
            .get_piece((i + 1) * PIECES_IN_SEGMENT as u64 - 1)
            .unwrap()
            .is_some());
    }
    // Tolerance works
    store
        .add_pieces(
            store.max_segments_number_in_cache() * PIECES_IN_SEGMENT as u64,
            &FlatPieces::new(PIECES_IN_SEGMENT as usize),
        )
        .unwrap();
    assert!(store.get_piece(0).unwrap().is_some());
    assert!(store
        .get_piece(PIECES_IN_SEGMENT as u64 - 1)
        .unwrap()
        .is_some());

    // Deletion
    store
        .add_pieces(
            (1 + store.max_segments_number_in_cache()) * PIECES_IN_SEGMENT as u64,
            &FlatPieces::new(PIECES_IN_SEGMENT as usize),
        )
        .unwrap();
    assert!(store.get_piece(0).unwrap().is_none());
    assert!(store
        .get_piece(PIECES_IN_SEGMENT as u64 - 1)
        .unwrap()
        .is_none());
    assert!(store.get_piece(PIECES_IN_SEGMENT as u64).unwrap().is_none());
    assert!(store
        .get_piece(2 * PIECES_IN_SEGMENT as u64 - 1)
        .unwrap()
        .is_none());

    // Edge cases
    assert!(store
        .get_piece(2 * PIECES_IN_SEGMENT as u64)
        .unwrap()
        .is_some());
    assert!(store
        .get_piece(
            (TOLERANCE_SEGMENTS_NUMBER + store.max_segments_number_in_cache())
                * PIECES_IN_SEGMENT as u64
                - 1
        )
        .unwrap()
        .is_some());
    assert!(store
        .get_piece(
            (TOLERANCE_SEGMENTS_NUMBER + store.max_segments_number_in_cache())
                * PIECES_IN_SEGMENT as u64
        )
        .unwrap()
        .is_none());
}
