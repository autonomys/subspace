use subspace_codec::SubspaceCodec;
use subspace_core_primitives::PIECE_SIZE;

#[test]
fn test_random_piece() {
    let public_key = rand::random::<[u8; 32]>();
    let original_piece = rand::random::<[u8; PIECE_SIZE]>();
    let piece_index = rand::random();

    let subspace_codec = SubspaceCodec::new(&public_key);
    let mut piece = original_piece;
    subspace_codec.encode(piece_index, &mut piece).unwrap();
    subspace_codec.decode(piece_index, &mut piece).unwrap();

    assert_eq!(original_piece, piece);
}
