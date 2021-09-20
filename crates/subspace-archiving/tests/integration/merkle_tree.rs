use std::iter;
use subspace_archiving::merkle_tree::MerkleTree;
use subspace_core_primitives::{crypto, Piece, Sha256Hash};

#[test]
fn merkle_tree() {
    let number_of_pieces = 16_usize;
    let pieces: Vec<Piece> = iter::repeat_with(rand::random)
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
        assert!(!witness.is_valid(rand::random(), index, *hashes.get(index).unwrap()));
        assert!(!witness.is_valid(root, index, rand::random()));
        assert!(!witness.is_valid(root, rand::random(), *hashes.get(index).unwrap()));
    }
}
