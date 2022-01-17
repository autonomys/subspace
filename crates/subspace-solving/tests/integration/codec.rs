use std::iter;
use subspace_core_primitives::{FlatPieces, PIECE_SIZE};
use subspace_solving::SubspaceCodec;

#[test]
fn single_piece() {
    let public_key = rand::random::<[u8; 32]>();
    let original_piece = rand::random::<[u8; PIECE_SIZE]>();
    let piece_index = rand::random();

    let subspace_codec = SubspaceCodec::new(&public_key);
    let mut piece = original_piece;

    subspace_codec.encode(&mut piece, piece_index).unwrap();
    assert_ne!(original_piece, piece);

    subspace_codec.decode(&mut piece, piece_index).unwrap();
    assert_eq!(original_piece, piece);
}

#[test]
fn batch() {
    let public_key = rand::random::<[u8; 32]>();
    let subspace_codec = SubspaceCodec::new(&public_key);
    // Use 2.5 batches worth of pieces
    let piece_count = subspace_codec.batch_size() * 2 + subspace_codec.batch_size() / 2;

    let mut pieces = FlatPieces::new(piece_count);
    for piece in pieces.as_pieces_mut() {
        piece.copy_from_slice(&rand::random::<[u8; PIECE_SIZE]>());
    }
    let original_pieces = pieces.clone();
    let piece_indexes: Vec<u64> = iter::repeat_with(rand::random).take(piece_count).collect();

    subspace_codec
        .batch_encode(&mut pieces, &piece_indexes)
        .unwrap();

    for ((original_piece, piece), piece_index) in original_pieces
        .as_pieces()
        .zip(pieces.as_pieces_mut())
        .zip(piece_indexes)
    {
        assert_ne!(original_piece, piece);
        subspace_codec.decode(piece, piece_index).unwrap();
        assert_eq!(original_piece, piece);
    }
}
