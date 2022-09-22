use std::iter;
use subspace_archiving::merkle_tree::{MerkleTree, MerkleTreeWitnessError};
use subspace_core_primitives::{crypto, Blake2b256Hash, Piece, PIECE_SIZE};

#[test]
fn merkle_tree() {
    let number_of_pieces = 16_usize;
    let pieces: Vec<Piece> = iter::repeat_with(|| rand::random::<[u8; PIECE_SIZE]>().into())
        .take(number_of_pieces)
        .collect();
    let hashes: Vec<Blake2b256Hash> = pieces
        .iter()
        .map(|item| crypto::blake2b_256_hash(item.as_ref()))
        .collect();

    let merkle_tree_data = MerkleTree::from_data(&pieces);
    let merkle_tree_hashes = MerkleTree::new(hashes.iter().copied());

    let root = merkle_tree_data.root();
    assert_eq!(root, merkle_tree_hashes.root());

    for position in 0..number_of_pieces {
        let witness = merkle_tree_data.get_witness(position).unwrap();

        assert_eq!(witness, merkle_tree_hashes.get_witness(position).unwrap());

        assert!(witness.is_valid(root, position as u32, *hashes.get(position).unwrap()));
        assert!(!witness.is_valid(
            rand::random(),
            position as u32,
            *hashes.get(position).unwrap()
        ));
        assert!(!witness.is_valid(root, position as u32, rand::random()));
        assert!(!witness.is_valid(root, rand::random(), *hashes.get(position).unwrap()));
    }

    assert_eq!(
        merkle_tree_data.get_witness(number_of_pieces),
        Err(MerkleTreeWitnessError::WrongPosition(number_of_pieces)),
    );
}
