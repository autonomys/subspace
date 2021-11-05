use std::iter;
use subspace_archiving::merkle_tree::{MerkleTree, MerkleTreeWitnessError};
use subspace_core_primitives::{crypto, Piece, Sha256Hash, PIECE_SIZE};

#[test]
fn merkle_tree() {
    let number_of_pieces = 16_usize;
    let pieces: Vec<Piece> = iter::repeat_with(|| rand::random::<[u8; PIECE_SIZE]>().into())
        .take(number_of_pieces)
        .collect();
    let hashes: Vec<Sha256Hash> = pieces.iter().map(crypto::sha256_hash).collect();

    let merkle_tree_data = MerkleTree::from_data(&pieces);
    let merkle_tree_hashes = MerkleTree::new(hashes.iter().copied());

    let root = merkle_tree_data.root();
    assert_eq!(root, merkle_tree_hashes.root());

    for position in 0..number_of_pieces {
        let witness = merkle_tree_data.get_witness(position).unwrap();

        assert_eq!(witness, merkle_tree_hashes.get_witness(position).unwrap());

        assert!(witness.is_valid(root, position, *hashes.get(position).unwrap()));
        assert!(!witness.is_valid(rand::random(), position, *hashes.get(position).unwrap()));
        assert!(!witness.is_valid(root, position, rand::random()));
        assert!(!witness.is_valid(root, rand::random(), *hashes.get(position).unwrap()));
    }

    assert_eq!(
        merkle_tree_data.get_witness(number_of_pieces),
        Err(MerkleTreeWitnessError::WrongPosition(number_of_pieces)),
    );
}
