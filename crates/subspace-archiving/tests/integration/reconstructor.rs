use std::assert_matches::assert_matches;
use std::iter;
use subspace_archiving::archiver::Archiver;
use subspace_archiving::reconstructor::{
    Reconstructor, ReconstructorError, ReconstructorInstantiationError,
};
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{
    ArchivedBlockProgress, FlatPieces, LastArchivedBlock, Piece, BLAKE2B_256_HASH_SIZE, PIECE_SIZE,
};

const MERKLE_NUM_LEAVES: usize = 8_usize;
const WITNESS_SIZE: usize = BLAKE2B_256_HASH_SIZE * MERKLE_NUM_LEAVES.ilog2() as usize;
const RECORD_SIZE: usize = PIECE_SIZE - WITNESS_SIZE;
const SEGMENT_SIZE: usize = RECORD_SIZE * MERKLE_NUM_LEAVES / 2;

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
fn basic() {
    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();
    // Block that fits into the segment fully
    let block_0 = rand::random::<[u8; SEGMENT_SIZE / 2]>().to_vec();
    // Block that overflows into the next segment
    let block_1 = rand::random::<[u8; SEGMENT_SIZE]>().to_vec();
    // Block that also fits into the segment fully
    let block_2 = rand::random::<[u8; SEGMENT_SIZE / 4]>().to_vec();
    // Block that occupies multiple segments
    let block_3 = rand::random::<[u8; SEGMENT_SIZE * 3]>().to_vec();
    // Extra block
    let block_4 = rand::random::<[u8; SEGMENT_SIZE]>().to_vec();
    let archived_segments = archiver
        .add_block(block_0.clone(), BlockObjectMapping::default())
        .into_iter()
        .chain(archiver.add_block(block_1.clone(), BlockObjectMapping::default()))
        .chain(archiver.add_block(block_2.clone(), BlockObjectMapping::default()))
        .chain(archiver.add_block(block_3.clone(), BlockObjectMapping::default()))
        .chain(archiver.add_block(block_4, BlockObjectMapping::default()))
        .collect::<Vec<_>>();

    assert_eq!(archived_segments.len(), 5);

    let mut reconstructor = Reconstructor::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&flat_pieces_to_regular(
                &archived_segments[0].pieces,
            )))
            .unwrap();

        // Only first block fits
        assert_eq!(contents.blocks, vec![(0, block_0)]);
        assert_eq!(contents.root_block, None);
    }

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&flat_pieces_to_regular(
                &archived_segments[1].pieces,
            )))
            .unwrap();

        // Second block is finished, but also third is included
        assert_eq!(contents.blocks, vec![(1, block_1), (2, block_2.clone())]);
        assert!(contents.root_block.is_some());
        assert_eq!(contents.root_block.unwrap().segment_index(), 0);
        assert_eq!(
            contents.root_block.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 1,
                archived_progress: ArchivedBlockProgress::Partial(7992)
            }
        );

        let mut partial_reconstructor = Reconstructor::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();
        let contents = partial_reconstructor
            .add_segment(&pieces_to_option_of_pieces(&flat_pieces_to_regular(
                &archived_segments[1].pieces,
            )))
            .unwrap();

        // Only third block is fully contained
        assert_eq!(contents.blocks, vec![(2, block_2)]);
        assert!(contents.root_block.is_some());
        assert_eq!(contents.root_block.unwrap().segment_index(), 0);
        assert_eq!(
            contents.root_block.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 1,
                archived_progress: ArchivedBlockProgress::Partial(7992)
            }
        );
    }

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&flat_pieces_to_regular(
                &archived_segments[2].pieces,
            )))
            .unwrap();

        // Nothing is fully contained here
        assert_eq!(contents.blocks, vec![]);
        assert!(contents.root_block.is_some());
        assert_eq!(contents.root_block.unwrap().segment_index(), 1);
        assert_eq!(
            contents.root_block.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 3,
                archived_progress: ArchivedBlockProgress::Partial(3896)
            }
        );

        let mut partial_reconstructor = Reconstructor::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();
        let contents = partial_reconstructor
            .add_segment(&pieces_to_option_of_pieces(&flat_pieces_to_regular(
                &archived_segments[2].pieces,
            )))
            .unwrap();

        // Nothing is fully contained here
        assert_eq!(contents.blocks, vec![]);
        assert!(contents.root_block.is_some());
        assert_eq!(contents.root_block.unwrap().segment_index(), 1);
        assert_eq!(
            contents.root_block.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 3,
                archived_progress: ArchivedBlockProgress::Partial(3896)
            }
        );
    }

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&flat_pieces_to_regular(
                &archived_segments[3].pieces,
            )))
            .unwrap();

        // Nothing is fully contained here
        assert_eq!(contents.blocks, vec![]);
        assert!(contents.root_block.is_some());
        assert_eq!(contents.root_block.unwrap().segment_index(), 2);
        assert_eq!(
            contents.root_block.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 3,
                archived_progress: ArchivedBlockProgress::Partial(19806)
            }
        );
    }

    {
        let mut partial_reconstructor = Reconstructor::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();
        let contents = partial_reconstructor
            .add_segment(&pieces_to_option_of_pieces(&flat_pieces_to_regular(
                &archived_segments[3].pieces,
            )))
            .unwrap();

        // Nothing is fully contained here
        assert_eq!(contents.blocks, vec![]);
        assert!(contents.root_block.is_some());
        assert_eq!(contents.root_block.unwrap().segment_index(), 2);
        assert_eq!(
            contents.root_block.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 3,
                archived_progress: ArchivedBlockProgress::Partial(19806)
            }
        );
    }

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&flat_pieces_to_regular(
                &archived_segments[4].pieces,
            )))
            .unwrap();

        // Enough data to reconstruct fourth block
        assert_eq!(contents.blocks, vec![(3, block_3)]);
        assert!(contents.root_block.is_some());
        assert_eq!(contents.root_block.unwrap().segment_index(), 3);
        assert_eq!(
            contents.root_block.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 3,
                archived_progress: ArchivedBlockProgress::Partial(35716)
            }
        );
    }

    {
        let mut partial_reconstructor = Reconstructor::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();
        let contents = partial_reconstructor
            .add_segment(&pieces_to_option_of_pieces(&flat_pieces_to_regular(
                &archived_segments[4].pieces,
            )))
            .unwrap();

        // Nothing is fully contained here
        assert_eq!(contents.blocks, vec![]);
        assert!(contents.root_block.is_some());
        assert_eq!(contents.root_block.unwrap().segment_index(), 3);
        assert_eq!(
            contents.root_block.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 3,
                archived_progress: ArchivedBlockProgress::Partial(35716)
            }
        );
    }
}

#[test]
fn partial_data() {
    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();
    // Block that fits into the segment fully
    let block_0 = rand::random::<[u8; SEGMENT_SIZE / 2]>().to_vec();
    // Block that overflows into the next segment
    let block_1 = rand::random::<[u8; SEGMENT_SIZE]>().to_vec();

    let archived_segments = archiver
        .add_block(block_0.clone(), BlockObjectMapping::default())
        .into_iter()
        .chain(archiver.add_block(block_1, BlockObjectMapping::default()))
        .collect::<Vec<_>>();

    assert_eq!(archived_segments.len(), 1);

    let pieces = flat_pieces_to_regular(&archived_segments.into_iter().next().unwrap().pieces);

    {
        // Take just data shards
        let contents = Reconstructor::new(RECORD_SIZE, SEGMENT_SIZE)
            .unwrap()
            .add_segment(
                &pieces
                    .iter()
                    .take(MERKLE_NUM_LEAVES / 2)
                    .cloned()
                    .map(Some)
                    .chain(iter::repeat(None).take(MERKLE_NUM_LEAVES / 2))
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        assert_eq!(contents.blocks, vec![(0, block_0.clone())]);
    }

    {
        // Take just parity shards
        let contents = Reconstructor::new(RECORD_SIZE, SEGMENT_SIZE)
            .unwrap()
            .add_segment(
                &iter::repeat(None)
                    .take(MERKLE_NUM_LEAVES / 2)
                    .chain(pieces.iter().skip(MERKLE_NUM_LEAVES / 2).cloned().map(Some))
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        assert_eq!(contents.blocks, vec![(0, block_0.clone())]);
    }

    {
        // Mix of data and parity shards
        let mut pieces = pieces.into_iter().map(Some).collect::<Vec<_>>();
        pieces[MERKLE_NUM_LEAVES / 4..]
            .iter_mut()
            .take(MERKLE_NUM_LEAVES / 2)
            .for_each(|piece| {
                piece.take();
            });
        let contents = Reconstructor::new(RECORD_SIZE, SEGMENT_SIZE)
            .unwrap()
            .add_segment(&pieces)
            .unwrap();

        assert_eq!(contents.blocks, vec![(0, block_0)]);
    }
}

#[test]
fn invalid_usage() {
    assert_matches!(
        Reconstructor::new(10, 9),
        Err(ReconstructorInstantiationError::SegmentSizeTooSmall),
    );
    assert_matches!(
        Reconstructor::new(SEGMENT_SIZE, SEGMENT_SIZE),
        Err(ReconstructorInstantiationError::SegmentSizeTooSmall),
    );

    assert_matches!(
        Reconstructor::new(17, SEGMENT_SIZE),
        Err(ReconstructorInstantiationError::SegmentSizesNotMultipleOfRecordSize),
    );

    assert_matches!(
        Reconstructor::new(17, 34),
        Err(ReconstructorInstantiationError::WrongRecordAndSegmentCombination),
    );

    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();
    // Block that overflows into the next segments
    let block_0 = rand::random::<[u8; SEGMENT_SIZE * 4]>().to_vec();

    let archived_segments = archiver.add_block(block_0, BlockObjectMapping::default());

    assert_eq!(archived_segments.len(), 4);

    {
        // Not enough shards with contents
        let result = Reconstructor::new(RECORD_SIZE, SEGMENT_SIZE)
            .unwrap()
            .add_segment(
                &flat_pieces_to_regular(&archived_segments[0].pieces)
                    .iter()
                    .take(MERKLE_NUM_LEAVES / 2 - 1)
                    .cloned()
                    .map(Some)
                    .chain(iter::repeat(None).take(MERKLE_NUM_LEAVES / 2 + 1))
                    .collect::<Vec<_>>(),
            );

        assert_matches!(result, Err(ReconstructorError::DataShardsReconstruction(_)));
    }

    {
        // Garbage data
        let result = Reconstructor::new(RECORD_SIZE, SEGMENT_SIZE)
            .unwrap()
            .add_segment(
                &iter::repeat_with(|| Some(rand::random::<[u8; PIECE_SIZE]>().into()))
                    .take(MERKLE_NUM_LEAVES)
                    .collect::<Vec<_>>(),
            );

        assert_matches!(result, Err(ReconstructorError::SegmentDecoding(_)));
    }

    {
        let mut reconstructor = Reconstructor::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

        reconstructor
            .add_segment(&pieces_to_option_of_pieces(&flat_pieces_to_regular(
                &archived_segments[0].pieces,
            )))
            .unwrap();

        let result = reconstructor.add_segment(&pieces_to_option_of_pieces(
            &flat_pieces_to_regular(&archived_segments[2].pieces),
        ));

        assert_eq!(
            result,
            Err(ReconstructorError::IncorrectSegmentOrder {
                expected_segment_index: 1,
                actual_segment_index: 2
            })
        );

        reconstructor
            .add_segment(&pieces_to_option_of_pieces(&flat_pieces_to_regular(
                &archived_segments[1].pieces,
            )))
            .unwrap();

        let result = reconstructor.add_segment(&pieces_to_option_of_pieces(
            &flat_pieces_to_regular(&archived_segments[3].pieces),
        ));

        assert_eq!(
            result,
            Err(ReconstructorError::IncorrectSegmentOrder {
                expected_segment_index: 2,
                actual_segment_index: 3
            })
        );
    }
}
