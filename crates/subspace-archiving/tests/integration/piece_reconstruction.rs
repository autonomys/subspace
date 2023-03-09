use rand::Rng;
use std::iter;
use subspace_archiving::archiver::Archiver;
use subspace_archiving::piece_reconstructor::{
    PiecesReconstructor, ReconstructorError, ReconstructorInstantiationError,
};
use subspace_core_primitives::crypto::blake2b_256_254_hash;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{
    FlatPieces, Piece, PIECES_IN_SEGMENT, RECORDED_HISTORY_SEGMENT_SIZE, RECORD_SIZE,
};

fn flat_pieces_to_regular(pieces: &FlatPieces) -> Vec<Piece> {
    pieces
        .as_pieces()
        .map(|piece| piece.try_into().unwrap())
        .collect()
}

fn pieces_to_option_of_pieces(pieces: &[Piece]) -> Vec<Option<Piece>> {
    pieces.iter().cloned().map(Some).collect()
}

// Block that fits into the segment fully
fn get_random_block() -> Vec<u8> {
    let mut rng = rand::thread_rng();

    iter::repeat(())
        .take(RECORDED_HISTORY_SEGMENT_SIZE as usize)
        .map(|_| rng.gen())
        .collect::<Vec<_>>()
}

#[test]
fn segment_reconstruction_works() {
    let kzg = Kzg::random(PIECES_IN_SEGMENT).unwrap();
    let mut archiver =
        Archiver::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg.clone()).unwrap();

    let block = get_random_block();

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

    let reconstructor =
        PiecesReconstructor::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg).unwrap();

    let flat_pieces = reconstructor.reconstruct_segment(&maybe_pieces).unwrap();

    let reconstructed_pieces = flat_pieces
        .as_pieces()
        .map(|bytes| Piece::try_from(bytes).expect("Piece must have the correct size"))
        .collect::<Vec<_>>();

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

#[test]
fn piece_reconstruction_works() {
    let kzg = Kzg::random(PIECES_IN_SEGMENT).unwrap();
    let mut archiver =
        Archiver::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg.clone()).unwrap();
    // Block that fits into the segment fully
    let block = get_random_block();

    let archived_segments = archiver.add_block(block, BlockObjectMapping::default());

    assert_eq!(archived_segments.len(), 1);

    let pieces = flat_pieces_to_regular(&archived_segments.into_iter().next().unwrap().pieces);
    let mut maybe_pieces = pieces_to_option_of_pieces(&pieces);

    assert_eq!(pieces.len(), PIECES_IN_SEGMENT as usize);
    assert_eq!(maybe_pieces.len(), PIECES_IN_SEGMENT as usize);

    // Remove some pieces from the array
    let missing_piece_position = 110;
    for i in 0..PIECES_IN_SEGMENT {
        if i > 100 && i < 140 {
            maybe_pieces[i as usize] = None;
        }
    }

    let reconstructor =
        PiecesReconstructor::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg).unwrap();

    let missing_piece = reconstructor
        .reconstruct_piece(&maybe_pieces, missing_piece_position)
        .unwrap();

    assert_eq!(
        blake2b_256_254_hash(pieces[missing_piece_position].as_ref()),
        blake2b_256_254_hash(missing_piece.as_ref())
    );
}

#[test]
fn piece_reconstructor_creation_fails() {
    let kzg = Kzg::random(PIECES_IN_SEGMENT).unwrap();

    let reconstructor = PiecesReconstructor::new(10, 1, kzg.clone());

    assert!(reconstructor.is_err());

    if let Err(error) = reconstructor {
        assert_eq!(error, ReconstructorInstantiationError::SegmentSizeTooSmall);
    }

    let reconstructor = PiecesReconstructor::new(10, 12, kzg);

    assert!(reconstructor.is_err());

    if let Err(error) = reconstructor {
        assert_eq!(
            error,
            ReconstructorInstantiationError::SegmentSizesNotMultipleOfRecordSize
        );
    }
}

#[test]
fn segment_reconstruction_fails() {
    let kzg = Kzg::random(PIECES_IN_SEGMENT).unwrap();

    let reconstructor =
        PiecesReconstructor::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg.clone()).unwrap();

    let pieces = vec![None];
    let result = reconstructor.reconstruct_segment(&pieces);

    assert!(result.is_err());

    if let Err(error) = result {
        assert!(matches!(
            error,
            ReconstructorError::DataShardsReconstruction(..)
        ));
    }

    let mut archiver = Archiver::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg).unwrap();
    // Block that fits into the segment fully
    let block = get_random_block();

    let archived_segments = archiver.add_block(block, BlockObjectMapping::default());

    assert_eq!(archived_segments.len(), 1);

    let pieces = flat_pieces_to_regular(&archived_segments.into_iter().next().unwrap().pieces);
    let maybe_pieces = pieces_to_option_of_pieces(&pieces);

    let result = reconstructor.reconstruct_piece(&maybe_pieces, 4000);

    assert!(result.is_err());

    if let Err(error) = result {
        assert_eq!(error, ReconstructorError::IncorrectPiecePosition);
    }
}

#[test]
fn piece_reconstruction_fails() {
    let kzg = Kzg::random(PIECES_IN_SEGMENT).unwrap();

    let reconstructor =
        PiecesReconstructor::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg.clone()).unwrap();

    let pieces = vec![None];
    let result = reconstructor.reconstruct_piece(&pieces, 0);

    assert!(result.is_err());

    if let Err(error) = result {
        assert!(matches!(
            error,
            ReconstructorError::DataShardsReconstruction(..)
        ));
    }

    let mut archiver = Archiver::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE, kzg).unwrap();
    // Block that fits into the segment fully
    let block = get_random_block();

    let archived_segments = archiver.add_block(block, BlockObjectMapping::default());

    assert_eq!(archived_segments.len(), 1);

    let pieces = flat_pieces_to_regular(&archived_segments.into_iter().next().unwrap().pieces);
    let maybe_pieces = pieces_to_option_of_pieces(&pieces);

    let result = reconstructor.reconstruct_piece(&maybe_pieces, 4000);

    assert!(result.is_err());

    if let Err(error) = result {
        assert_eq!(error, ReconstructorError::IncorrectPiecePosition);
    }
}
