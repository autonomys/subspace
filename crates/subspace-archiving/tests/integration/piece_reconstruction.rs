use subspace_archiving::archiver::Archiver;
use subspace_archiving::piece_reconstructor::PiecesReconstructor;
use subspace_core_primitives::crypto::blake2b_256_254_hash;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{FlatPieces, Piece, RECORD_SIZE};

// This is data + parity shards
const PIECES_IN_SEGMENT: u32 = 8;
// In terms of source data that can be stored in the segment, not the size after archiving
const SEGMENT_SIZE: u32 = RECORD_SIZE * PIECES_IN_SEGMENT / 2;

fn flat_pieces_to_regular(pieces: &FlatPieces) -> Vec<Piece> {
    pieces
        .as_pieces()
        .map(|piece| piece.try_into().unwrap())
        .collect()
}

fn pieces_to_option_of_pieces(pieces: &[Piece]) -> Vec<Option<Piece>> {
    pieces.iter().cloned().map(Some).collect()
}

#[test]
fn piece_reconstruction_works() {
    let kzg = Kzg::random(PIECES_IN_SEGMENT).unwrap();
    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE, kzg.clone()).unwrap();
    // Block that fits into the segment fully
    let block = rand::random::<[u8; SEGMENT_SIZE as usize]>().to_vec();

    let archived_segments = archiver.add_block(block, BlockObjectMapping::default());

    assert_eq!(archived_segments.len(), 1);

    let pieces = flat_pieces_to_regular(&archived_segments.into_iter().next().unwrap().pieces);
    let mut maybe_pieces = pieces_to_option_of_pieces(&pieces);

    assert_eq!(pieces.len(), PIECES_IN_SEGMENT as usize);
    assert_eq!(maybe_pieces.len(), PIECES_IN_SEGMENT as usize);

    // Remove some pieces from the array
    for i in 0..PIECES_IN_SEGMENT {
        if i > 100 && i < 140 {
            maybe_pieces[i as usize] = None;
        }
    }

    let reconstructor = PiecesReconstructor::new(RECORD_SIZE, SEGMENT_SIZE, kzg).unwrap();

    let reconstructed_pieces = reconstructor.retrieve_pieces(&maybe_pieces).unwrap();

    assert_eq!(reconstructed_pieces.len(), PIECES_IN_SEGMENT as usize);
    pieces.iter().zip(reconstructed_pieces.iter()).for_each(
        |(original_piece, reconstructed_piece)| {
            assert_eq!(
                blake2b_256_254_hash(original_piece.as_ref()),
                blake2b_256_254_hash(reconstructed_piece.as_ref())
            );
        },
    );
}
