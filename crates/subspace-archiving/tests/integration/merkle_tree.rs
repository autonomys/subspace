use rand::prelude::*;
use std::iter;
use subspace_archiving::merkle_tree::MerkleTree;
use subspace_core_primitives::{crypto, Piece, Sha256Hash, PIECE_SIZE};

fn generate_random_piece() -> Piece {
    let mut bytes = [0u8; PIECE_SIZE];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

#[test]
fn merkle_tree() {
    let number_of_pieces = 16_usize;
    let pieces: Vec<Piece> = iter::repeat_with(generate_random_piece)
        .take(number_of_pieces)
        .collect();
    let hashes: Vec<Sha256Hash> = pieces
        .iter()
        .map(|p| crypto::sha256_hash(p.as_ref()))
        .collect();

    let merkle_tree_data = MerkleTree::from_data(&pieces);
    let merkle_tree_hashes = MerkleTree::new(hashes.iter().copied());

    let root = merkle_tree_data.root();
    assert_eq!(root, merkle_tree_hashes.root());

    for index in 0..number_of_pieces {
        let witness = merkle_tree_data.get_witness(index).unwrap();

        assert_eq!(witness, merkle_tree_hashes.get_witness(index).unwrap());

        assert!(witness.is_valid(root, index, *hashes.get(index).unwrap()));
    }
}
