use rand::Rng;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::num::NonZeroUsize;
use subspace_archiving::archiver::Archiver;
use subspace_archiving::piece_reconstructor::{PiecesReconstructor, ReconstructorError};
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::pieces::{FlatPieces, Piece, Record};
use subspace_core_primitives::segments::{ArchivedHistorySegment, RecordedHistorySegment};
use subspace_erasure_coding::ErasureCoding;
use subspace_kzg::Kzg;

fn pieces_to_option_of_pieces(pieces: &FlatPieces) -> Vec<Option<Piece>> {
    pieces.pieces().map(Some).collect()
}

// Block that fits into the segment fully
fn get_random_block() -> Vec<u8> {
    let mut block = vec![0u8; RecordedHistorySegment::SIZE];
    rand::thread_rng().fill(block.as_mut_slice());
    block
}

#[test]
fn segment_reconstruction_works() {
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg.clone(), erasure_coding.clone());

    let block = get_random_block();

    let archived_segments = archiver
        .add_block(block, BlockObjectMapping::default(), true)
        .archived_segments;

    assert_eq!(archived_segments.len(), 1);

    let mut maybe_pieces = pieces_to_option_of_pieces(&archived_segments.first().unwrap().pieces);

    assert_eq!(maybe_pieces.len(), ArchivedHistorySegment::NUM_PIECES);

    // Remove some pieces from the array
    maybe_pieces
        .iter_mut()
        .skip(100)
        .take(30)
        .for_each(|piece| {
            piece.take();
        });

    let reconstructor = PiecesReconstructor::new(kzg, erasure_coding);

    let flat_pieces = reconstructor.reconstruct_segment(&maybe_pieces).unwrap();

    assert_eq!(flat_pieces.len(), ArchivedHistorySegment::NUM_PIECES);
    archived_segments
        .into_iter()
        .next()
        .unwrap()
        .pieces
        .iter()
        .zip(flat_pieces.iter())
        .for_each(|(original_piece, reconstructed_piece)| {
            assert_eq!(original_piece, reconstructed_piece);
        });
}

#[test]
fn piece_reconstruction_works() {
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg.clone(), erasure_coding.clone());
    // Block that fits into the segment fully
    let block = get_random_block();

    let archived_segments = archiver
        .add_block(block, BlockObjectMapping::default(), true)
        .archived_segments;

    assert_eq!(archived_segments.len(), 1);

    let mut maybe_pieces = pieces_to_option_of_pieces(&archived_segments.first().unwrap().pieces);

    assert_eq!(maybe_pieces.len(), ArchivedHistorySegment::NUM_PIECES);

    // Remove some pieces from the vector
    let missing_pieces = maybe_pieces
        .iter_mut()
        .enumerate()
        .skip(120)
        .take(10)
        .map(|(piece_position, piece)| (piece_position, piece.take().unwrap()))
        .collect::<Vec<_>>();

    let reconstructor = PiecesReconstructor::new(kzg, erasure_coding);

    #[cfg(not(feature = "parallel"))]
    let iter = missing_pieces.iter();
    #[cfg(feature = "parallel")]
    let iter = missing_pieces.par_iter();
    let reconstructed_pieces = iter
        .map(|(missing_piece_position, _missing_piece)| {
            reconstructor
                .reconstruct_piece(&maybe_pieces, *missing_piece_position)
                .unwrap()
        })
        .collect::<Vec<_>>();

    for ((_, missing_piece), reconstructed_piece) in
        missing_pieces.iter().zip(&reconstructed_pieces)
    {
        assert_eq!(missing_piece, reconstructed_piece);
    }
}

#[test]
fn segment_reconstruction_fails() {
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let reconstructor = PiecesReconstructor::new(kzg.clone(), erasure_coding.clone());

    let pieces = vec![None];
    let result = reconstructor.reconstruct_segment(&pieces);

    assert!(result.is_err());

    if let Err(error) = result {
        assert!(matches!(
            error,
            ReconstructorError::DataShardsReconstruction(..)
        ));
    }

    let mut archiver = Archiver::new(kzg, erasure_coding);
    // Block that fits into the segment fully
    let block = get_random_block();

    let archived_segments = archiver
        .add_block(block, BlockObjectMapping::default(), true)
        .archived_segments;

    assert_eq!(archived_segments.len(), 1);

    let maybe_pieces = pieces_to_option_of_pieces(&archived_segments.first().unwrap().pieces);

    let result = reconstructor.reconstruct_piece(&maybe_pieces, 4000);

    assert!(result.is_err());

    if let Err(error) = result {
        assert_eq!(error, ReconstructorError::IncorrectPiecePosition);
    }
}

#[test]
fn piece_reconstruction_fails() {
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let reconstructor = PiecesReconstructor::new(kzg.clone(), erasure_coding.clone());

    let pieces = vec![None];
    let result = reconstructor.reconstruct_piece(&pieces, 0);

    assert!(result.is_err());

    if let Err(error) = result {
        assert!(matches!(
            error,
            ReconstructorError::DataShardsReconstruction(..)
        ));
    }

    let mut archiver = Archiver::new(kzg, erasure_coding);
    // Block that fits into the segment fully
    let block = get_random_block();

    let archived_segments = archiver
        .add_block(block, BlockObjectMapping::default(), true)
        .archived_segments;

    assert_eq!(archived_segments.len(), 1);

    let maybe_pieces = pieces_to_option_of_pieces(&archived_segments.first().unwrap().pieces);

    let result = reconstructor.reconstruct_piece(&maybe_pieces, 4000);

    assert!(result.is_err());

    if let Err(error) = result {
        assert_eq!(error, ReconstructorError::IncorrectPiecePosition);
    }
}
