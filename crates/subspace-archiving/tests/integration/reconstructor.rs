use parity_scale_codec::Encode;
use rand::RngExt;
use std::num::NonZeroUsize;
use std::{assert_matches, iter};
use subspace_archiving::archiver::{Archiver, Segment, SegmentItem};
use subspace_archiving::reconstructor::{Reconstructor, ReconstructorError};
use subspace_core_primitives::BlockNumber;
use subspace_core_primitives::hashes::Blake3Hash;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::pieces::{FlatPieces, Piece, Record};
use subspace_core_primitives::segments::{
    ArchivedBlockProgress, ArchivedHistorySegment, LastArchivedBlock, RecordedHistorySegment,
    SegmentCommitment, SegmentHeader, SegmentIndex,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_kzg::Kzg;

fn pieces_to_option_of_pieces(pieces: &FlatPieces) -> Vec<Option<Piece>> {
    pieces.pieces().map(Some).collect()
}

/// Compare block numbers and sizes before contents, such that a mismatch doesn't print whole blocks
fn assert_blocks(actual: &[(BlockNumber, Vec<u8>)], expected: &[(BlockNumber, &[u8])]) {
    assert_eq!(
        actual
            .iter()
            .map(|(block_number, block)| (*block_number, block.len()))
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(|(block_number, block)| (*block_number, block.len()))
            .collect::<Vec<_>>()
    );
    for ((block_number, actual_block), (_, expected_block)) in actual.iter().zip(expected) {
        assert!(
            actual_block == expected_block,
            "Contents of block {block_number} differ"
        );
    }
}

#[test]
fn basic() {
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg, erasure_coding.clone());
    // Block that fits into the segment fully
    let block_0 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE / 2];
        rand::rng().fill(block.as_mut_slice());
        block
    };
    // Block that overflows into the next segment
    let block_1 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE];
        rand::rng().fill(block.as_mut_slice());
        block
    };
    // Block that also fits into the segment fully
    let block_2 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE / 4];
        rand::rng().fill(block.as_mut_slice());
        block
    };
    // Block that occupies multiple segments
    let block_3 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE * 3];
        rand::rng().fill(block.as_mut_slice());
        block
    };
    // Extra block
    let block_4 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE];
        rand::rng().fill(block.as_mut_slice());
        block
    };
    let archived_segments = archiver
        .add_block(block_0.clone(), BlockObjectMapping::default(), true)
        .archived_segments
        .into_iter()
        .chain(
            archiver
                .add_block(block_1.clone(), BlockObjectMapping::default(), true)
                .archived_segments,
        )
        .chain(
            archiver
                .add_block(block_2.clone(), BlockObjectMapping::default(), true)
                .archived_segments,
        )
        .chain(
            archiver
                .add_block(block_3.clone(), BlockObjectMapping::default(), true)
                .archived_segments,
        )
        .chain(
            archiver
                .add_block(block_4, BlockObjectMapping::default(), true)
                .archived_segments,
        )
        .collect::<Vec<_>>();

    assert_eq!(archived_segments.len(), 5);

    let mut reconstructor = Reconstructor::new(erasure_coding.clone());

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

        let mut partial_reconstructor = Reconstructor::new(erasure_coding.clone());
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

        let mut partial_reconstructor = Reconstructor::new(erasure_coding.clone());
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
        let mut partial_reconstructor = Reconstructor::new(erasure_coding.clone());
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
        let mut partial_reconstructor = Reconstructor::new(erasure_coding);
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
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg, erasure_coding.clone());
    // Block that fits into the segment fully
    let block_0 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE / 2];
        rand::rng().fill(block.as_mut_slice());
        block
    };
    // Block that overflows into the next segment
    let block_1 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE];
        rand::rng().fill(block.as_mut_slice());
        block
    };
    let archived_segments = archiver
        .add_block(block_0.clone(), BlockObjectMapping::default(), true)
        .archived_segments
        .into_iter()
        .chain(
            archiver
                .add_block(block_1, BlockObjectMapping::default(), true)
                .archived_segments,
        )
        .collect::<Vec<_>>();

    assert_eq!(archived_segments.len(), 1);

    let pieces = archived_segments.into_iter().next().unwrap().pieces;

    {
        // Take just source shards
        let contents = Reconstructor::new(erasure_coding.clone())
            .add_segment(
                &pieces
                    .source_pieces()
                    .map(Some)
                    .zip(iter::repeat_n(
                        None,
                        RecordedHistorySegment::NUM_RAW_RECORDS,
                    ))
                    .flat_map(|(a, b)| [a, b])
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        assert_eq!(contents.blocks, vec![(0, block_0.clone())]);
    }

    {
        // Take just parity shards
        let contents = Reconstructor::new(erasure_coding.clone())
            .add_segment(
                &iter::repeat_n(None, RecordedHistorySegment::NUM_RAW_RECORDS)
                    .chain(
                        pieces
                            .pieces()
                            .skip(RecordedHistorySegment::NUM_RAW_RECORDS)
                            .map(Some),
                    )
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        assert_eq!(contents.blocks, vec![(0, block_0.clone())]);
    }

    {
        // Mix of data and parity shards
        let mut pieces = pieces.pieces().map(Some).collect::<Vec<_>>();
        pieces[ArchivedHistorySegment::NUM_PIECES / 4..]
            .iter_mut()
            .take(RecordedHistorySegment::NUM_RAW_RECORDS)
            .for_each(|piece| {
                piece.take();
            });
        let contents = Reconstructor::new(erasure_coding)
            .add_segment(&pieces)
            .unwrap();

        assert_eq!(contents.blocks, vec![(0, block_0)]);
    }
}

#[test]
fn invalid_usage() {
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg, erasure_coding.clone());
    // Block that overflows into the next segments
    let block_0 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE * 4];
        rand::rng().fill(block.as_mut_slice());
        block
    };

    let archived_segments = archiver
        .add_block(block_0, BlockObjectMapping::default(), true)
        .archived_segments;

    assert_eq!(archived_segments.len(), 4);

    {
        // Not enough shards with contents
        let result = Reconstructor::new(erasure_coding.clone()).add_segment(
            &archived_segments[0]
                .pieces
                .pieces()
                .take(RecordedHistorySegment::NUM_RAW_RECORDS - 1)
                .map(Some)
                .chain(iter::repeat(None))
                .take(ArchivedHistorySegment::NUM_PIECES)
                .collect::<Vec<_>>(),
        );

        assert_matches!(result, Err(ReconstructorError::DataShardsReconstruction(_)));
    }

    {
        // Garbage data
        let result = Reconstructor::new(erasure_coding.clone()).add_segment(
            &iter::repeat_with(|| {
                let mut piece = Piece::default();
                rand::rng().fill(piece.as_mut());
                Some(piece)
            })
            .take(ArchivedHistorySegment::NUM_PIECES)
            .collect::<Vec<_>>(),
        );

        assert_matches!(result, Err(ReconstructorError::SegmentDecoding(_)));
    }

    {
        let mut reconstructor = Reconstructor::new(erasure_coding);

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

#[test]
fn blocks_completed_at_segment_end() {
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg, erasure_coding.clone());
    let segment_overhead = Segment::default().encoded_size();
    let segment_header_item_size = |archived_progress: ArchivedBlockProgress| {
        SegmentItem::ParentSegmentHeader(SegmentHeader::V0 {
            segment_index: SegmentIndex::ZERO,
            segment_commitment: SegmentCommitment::default(),
            prev_segment_header_hash: Blake3Hash::default(),
            last_archived_block: LastArchivedBlock {
                number: 0,
                archived_progress,
            },
        })
        .encoded_size()
    };
    // Segment item enum variant and compact bytes length, which is 4 bytes for blocks of these
    // sizes
    let block_item_overhead = 1 + 4;
    // Block bytes that fit into a segment with a parent segment header and a single block item,
    // the parent segment header is smaller when its last archived block is complete
    let segment_block_bytes_after_partial = RecordedHistorySegment::SIZE
        - segment_overhead
        - segment_header_item_size(ArchivedBlockProgress::Partial(0))
        - block_item_overhead;
    let segment_block_bytes_after_complete = RecordedHistorySegment::SIZE
        - segment_overhead
        - segment_header_item_size(ArchivedBlockProgress::Complete)
        - block_item_overhead;
    // Block that fits into the segment fully
    let block_0 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE / 2];
        rand::rng().fill(block.as_mut_slice());
        block
    };
    let block_1_bytes_in_segment_0 =
        RecordedHistorySegment::SIZE - segment_overhead - block_item_overhead * 2 - block_0.len();
    // Block that fills the rest of the first segment and the whole second and third segments
    let block_1 = {
        let mut block =
            vec![0u8; block_1_bytes_in_segment_0 + segment_block_bytes_after_partial * 2];
        rand::rng().fill(block.as_mut_slice());
        block
    };
    // Block that fills the whole fourth segment
    let block_2 = {
        let mut block = vec![0u8; segment_block_bytes_after_complete];
        rand::rng().fill(block.as_mut_slice());
        block
    };
    // Block that fits into the fifth segment fully
    let block_3 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE / 2];
        rand::rng().fill(block.as_mut_slice());
        block
    };
    // Block that overflows into the next segment
    let block_4 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE];
        rand::rng().fill(block.as_mut_slice());
        block
    };
    let archived_segments = [&block_0, &block_1, &block_2, &block_3, &block_4]
        .into_iter()
        .flat_map(|block| {
            archiver
                .add_block(block.clone(), BlockObjectMapping::default(), true)
                .archived_segments
        })
        .collect::<Vec<_>>();

    let partial = |archived_bytes: usize| {
        ArchivedBlockProgress::Partial(u32::try_from(archived_bytes).unwrap())
    };

    // Third and fourth segments end exactly with the end of a block
    assert_eq!(
        archived_segments
            .iter()
            .map(|archived_segment| archived_segment.segment_header.last_archived_block())
            .map(|last_archived_block| (
                last_archived_block.number,
                last_archived_block.archived_progress
            ))
            .collect::<Vec<_>>(),
        vec![
            (1, partial(block_1_bytes_in_segment_0)),
            (
                1,
                partial(block_1_bytes_in_segment_0 + segment_block_bytes_after_partial)
            ),
            (1, ArchivedBlockProgress::Complete),
            (2, ArchivedBlockProgress::Complete),
            (
                4,
                partial(segment_block_bytes_after_complete - block_item_overhead - block_3.len())
            ),
        ]
    );

    let mut reconstructor = Reconstructor::new(erasure_coding.clone());

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[0].pieces))
            .unwrap();

        // Only first block fits
        assert_blocks(&contents.blocks, &[(0, &block_0)]);
    }

    for archived_segment in &archived_segments[1..3] {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segment.pieces))
            .unwrap();

        // Second block continues here and ends exactly with the third segment, which is only known
        // from the next segment
        assert_blocks(&contents.blocks, &[]);

        let contents = Reconstructor::new(erasure_coding.clone())
            .add_segment(&pieces_to_option_of_pieces(&archived_segment.pieces))
            .unwrap();

        // Nothing is fully contained here
        assert_blocks(&contents.blocks, &[]);
    }

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[3].pieces))
            .unwrap();

        // Second block is finished, and the third block is fully contained
        assert_blocks(&contents.blocks, &[(1, &block_1), (2, &block_2)]);

        let contents = Reconstructor::new(erasure_coding.clone())
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[3].pieces))
            .unwrap();

        // Only third block is fully contained
        assert_blocks(&contents.blocks, &[(2, &block_2)]);
    }

    {
        let contents = reconstructor
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[4].pieces))
            .unwrap();

        // Previous segment ended with a whole block, only fourth block is fully contained
        assert_blocks(&contents.blocks, &[(3, &block_3)]);

        let contents = Reconstructor::new(erasure_coding)
            .add_segment(&pieces_to_option_of_pieces(&archived_segments[4].pieces))
            .unwrap();

        assert_blocks(&contents.blocks, &[(3, &block_3)]);
    }
}
