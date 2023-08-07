use rand::{thread_rng, Rng};
use std::assert_matches::assert_matches;
use std::iter;
use subspace_archiving::archiver::Archiver;
use subspace_archiving::reconstructor::{Reconstructor, ReconstructorError};
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{
    ArchivedBlockProgress, ArchivedHistorySegment, FlatPieces, LastArchivedBlock, Piece,
    RecordedHistorySegment, SegmentIndex,
};

fn pieces_to_option_of_pieces(pieces: &FlatPieces) -> Vec<Option<Piece>> {
    pieces.iter().map(Piece::from).map(Some).collect()
}

#[test]
fn basic() {
    let kzg = Kzg::new(embedded_kzg_settings());
    let mut archiver = Archiver::new(kzg).unwrap();
    // Block that fits into the segment fully
    let block_0 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE / 2];
        thread_rng().fill(block.as_mut_slice());
        block
    };
    // Block that overflows into the next segment
    let block_1 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE];
        thread_rng().fill(block.as_mut_slice());
        block
    };
    // Block that also fits into the segment fully
    let block_2 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE / 4];
        thread_rng().fill(block.as_mut_slice());
        block
    };
    // Block that occupies multiple segments
    let block_3 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE * 3];
        thread_rng().fill(block.as_mut_slice());
        block
    };
    // Extra block
    let block_4 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE];
        thread_rng().fill(block.as_mut_slice());
        block
    };
    let archived_segments = archiver
        .add_block(block_0.clone(), BlockObjectMapping::default(), true)
        .into_iter()
        .chain(archiver.add_block(block_1.clone(), BlockObjectMapping::default(), true))
        .chain(archiver.add_block(block_2.clone(), BlockObjectMapping::default(), true))
        .chain(archiver.add_block(block_3.clone(), BlockObjectMapping::default(), true))
        .chain(archiver.add_block(block_4, BlockObjectMapping::default(), true))
        .collect::<Vec<_>>();

    assert_eq!(archived_segments.len(), 5);

    let mut reconstructor = Reconstructor::new().unwrap();

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[0].pieces))
            .unwrap();

        // Only first block fits
        assert_eq!(contents.blocks, vec![(0, block_0)]);
        assert_eq!(contents.segment_header, None);
    }

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[1].pieces))
            .unwrap();

        // Second block is finished, but also third is included
        assert_eq!(contents.blocks, vec![(1, block_1), (2, block_2.clone())]);
        assert!(contents.segment_header.is_some());
        assert_eq!(
            contents.segment_header.unwrap().segment_index(),
            SegmentIndex::ZERO
        );
        assert_eq!(
            contents.segment_header.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 1,
                archived_progress: ArchivedBlockProgress::Partial(65011701)
            }
        );

        let mut partial_reconstructor = Reconstructor::new().unwrap();
        let contents = partial_reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[1].pieces))
            .unwrap();

        // Only third block is fully contained
        assert_eq!(contents.blocks, vec![(2, block_2)]);
        assert!(contents.segment_header.is_some());
        assert_eq!(
            contents.segment_header.unwrap().segment_index(),
            SegmentIndex::ZERO
        );
        assert_eq!(
            contents.segment_header.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 1,
                archived_progress: ArchivedBlockProgress::Partial(65011701)
            }
        );
    }

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[2].pieces))
            .unwrap();

        // Nothing is fully contained here
        assert_eq!(contents.blocks, vec![]);
        assert!(contents.segment_header.is_some());
        assert_eq!(
            contents.segment_header.unwrap().segment_index(),
            SegmentIndex::ONE
        );
        assert_eq!(
            contents.segment_header.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 3,
                archived_progress: ArchivedBlockProgress::Partial(32505730)
            }
        );

        let mut partial_reconstructor = Reconstructor::new().unwrap();
        let contents = partial_reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[2].pieces))
            .unwrap();

        // Nothing is fully contained here
        assert_eq!(contents.blocks, vec![]);
        assert!(contents.segment_header.is_some());
        assert_eq!(
            contents.segment_header.unwrap().segment_index(),
            SegmentIndex::ONE
        );
        assert_eq!(
            contents.segment_header.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 3,
                archived_progress: ArchivedBlockProgress::Partial(32505730)
            }
        );
    }

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[3].pieces))
            .unwrap();

        // Nothing is fully contained here
        assert_eq!(contents.blocks, vec![]);
        assert!(contents.segment_header.is_some());
        assert_eq!(
            contents.segment_header.unwrap().segment_index(),
            SegmentIndex::from(2)
        );
        assert_eq!(
            contents.segment_header.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 3,
                archived_progress: ArchivedBlockProgress::Partial(162529049)
            }
        );
    }

    {
        let mut partial_reconstructor = Reconstructor::new().unwrap();
        let contents = partial_reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[3].pieces))
            .unwrap();

        // Nothing is fully contained here
        assert_eq!(contents.blocks, vec![]);
        assert!(contents.segment_header.is_some());
        assert_eq!(
            contents.segment_header.unwrap().segment_index(),
            SegmentIndex::from(2)
        );
        assert_eq!(
            contents.segment_header.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 3,
                archived_progress: ArchivedBlockProgress::Partial(162529049)
            }
        );
    }

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[4].pieces))
            .unwrap();

        // Enough data to reconstruct fourth block
        assert_eq!(contents.blocks, vec![(3, block_3)]);
        assert!(contents.segment_header.is_some());
        assert_eq!(
            contents.segment_header.unwrap().segment_index(),
            SegmentIndex::from(3)
        );
        assert_eq!(
            contents.segment_header.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 3,
                archived_progress: ArchivedBlockProgress::Partial(292552368)
            }
        );
    }

    {
        let mut partial_reconstructor = Reconstructor::new().unwrap();
        let contents = partial_reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[4].pieces))
            .unwrap();

        // Nothing is fully contained here
        assert_eq!(contents.blocks, vec![]);
        assert!(contents.segment_header.is_some());
        assert_eq!(
            contents.segment_header.unwrap().segment_index(),
            SegmentIndex::from(3)
        );
        assert_eq!(
            contents.segment_header.unwrap().last_archived_block(),
            LastArchivedBlock {
                number: 3,
                archived_progress: ArchivedBlockProgress::Partial(292552368)
            }
        );
    }
}

#[test]
fn partial_data() {
    let kzg = Kzg::new(embedded_kzg_settings());
    let mut archiver = Archiver::new(kzg).unwrap();
    // Block that fits into the segment fully
    let block_0 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE / 2];
        thread_rng().fill(block.as_mut_slice());
        block
    };
    // Block that overflows into the next segment
    let block_1 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE];
        thread_rng().fill(block.as_mut_slice());
        block
    };
    let archived_segments = archiver
        .add_block(block_0.clone(), BlockObjectMapping::default(), true)
        .into_iter()
        .chain(archiver.add_block(block_1, BlockObjectMapping::default(), true))
        .collect::<Vec<_>>();

    assert_eq!(archived_segments.len(), 1);

    let pieces = archived_segments.into_iter().next().unwrap().pieces;

    {
        // Take just source shards
        let contents = Reconstructor::new()
            .unwrap()
            .add_segment(
                &pieces
                    .source()
                    .map(Piece::from)
                    .map(Some)
                    .zip(iter::repeat(None).take(RecordedHistorySegment::NUM_RAW_RECORDS))
                    .flat_map(|(a, b)| [a, b])
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        assert_eq!(contents.blocks, vec![(0, block_0.clone())]);
    }

    {
        // Take just parity shards
        let contents = Reconstructor::new()
            .unwrap()
            .add_segment(
                &iter::repeat(None)
                    .take(RecordedHistorySegment::NUM_RAW_RECORDS)
                    .chain(
                        pieces
                            .iter()
                            .skip(RecordedHistorySegment::NUM_RAW_RECORDS)
                            .map(Piece::from)
                            .map(Some),
                    )
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        assert_eq!(contents.blocks, vec![(0, block_0.clone())]);
    }

    {
        // Mix of data and parity shards
        let mut pieces = pieces.iter().map(Piece::from).map(Some).collect::<Vec<_>>();
        pieces[ArchivedHistorySegment::NUM_PIECES / 4..]
            .iter_mut()
            .take(RecordedHistorySegment::NUM_RAW_RECORDS)
            .for_each(|piece| {
                piece.take();
            });
        let contents = Reconstructor::new().unwrap().add_segment(&pieces).unwrap();

        assert_eq!(contents.blocks, vec![(0, block_0)]);
    }
}

#[test]
fn invalid_usage() {
    let kzg = Kzg::new(embedded_kzg_settings());

    let mut archiver = Archiver::new(kzg).unwrap();
    // Block that overflows into the next segments
    let block_0 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE * 4];
        thread_rng().fill(block.as_mut_slice());
        block
    };

    let archived_segments = archiver.add_block(block_0, BlockObjectMapping::default(), true);

    assert_eq!(archived_segments.len(), 4);

    {
        // Not enough shards with contents
        let result = Reconstructor::new().unwrap().add_segment(
            &archived_segments[0]
                .pieces
                .iter()
                .take(RecordedHistorySegment::NUM_RAW_RECORDS - 1)
                .map(Piece::from)
                .map(Some)
                .chain(iter::repeat(None))
                .take(ArchivedHistorySegment::NUM_PIECES)
                .collect::<Vec<_>>(),
        );

        assert_matches!(result, Err(ReconstructorError::DataShardsReconstruction(_)));
    }

    {
        // Garbage data
        let result = Reconstructor::new().unwrap().add_segment(
            &iter::repeat_with(|| {
                let mut piece = Piece::default();
                thread_rng().fill(piece.as_mut());
                Some(piece)
            })
            .take(ArchivedHistorySegment::NUM_PIECES)
            .collect::<Vec<_>>(),
        );

        assert_matches!(result, Err(ReconstructorError::SegmentDecoding(_)));
    }

    {
        let mut reconstructor = Reconstructor::new().unwrap();

        reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[0].pieces))
            .unwrap();

        let result =
            reconstructor.add_segment(&pieces_to_option_of_pieces(&archived_segments[2].pieces));

        assert_eq!(
            result,
            Err(ReconstructorError::IncorrectSegmentOrder {
                expected_segment_index: SegmentIndex::ONE,
                actual_segment_index: SegmentIndex::from(2)
            })
        );

        reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[1].pieces))
            .unwrap();

        let result =
            reconstructor.add_segment(&pieces_to_option_of_pieces(&archived_segments[3].pieces));

        assert_eq!(
            result,
            Err(ReconstructorError::IncorrectSegmentOrder {
                expected_segment_index: SegmentIndex::from(2),
                actual_segment_index: SegmentIndex::from(3)
            })
        );
    }
}
