use subspace_solving::PieceDistance;

mod codec;

#[test]
fn piece_distance_middle() {
    assert_eq!(PieceDistance::MIDDLE, PieceDistance::MAX / 2);
}
