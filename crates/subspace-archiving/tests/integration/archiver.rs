use std::assert_matches::assert_matches;
use subspace_archiving::archiver;
use subspace_archiving::archiver::{Archiver, ArchiverInstantiationError};
use subspace_core_primitives::{PIECE_SIZE, SHA256_HASH_SIZE};

const MERKLE_NUM_LEAVES: usize = 8_usize;
const WITNESS_SIZE: usize = SHA256_HASH_SIZE * MERKLE_NUM_LEAVES.log2() as usize;
const RECORD_SIZE: usize = PIECE_SIZE - WITNESS_SIZE;
const SEGMENT_SIZE: usize = RECORD_SIZE * MERKLE_NUM_LEAVES / 2;

#[test]
fn archiver() {
    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

    assert!(archiver
        .add_block(rand::random::<[u8; SEGMENT_SIZE / 2]>())
        .is_empty());

    let archived_segments = archiver.add_block(rand::random::<[u8; SEGMENT_SIZE / 3 * 2]>());
    assert_eq!(archived_segments.len(), 1);

    let first_archived_segment = archived_segments.into_iter().next().unwrap();
    assert_eq!(first_archived_segment.pieces.len(), MERKLE_NUM_LEAVES);
    assert_eq!(first_archived_segment.root_block.segment_index(), 0);
    assert_eq!(
        first_archived_segment.root_block.prev_root_block_hash(),
        [0u8; SHA256_HASH_SIZE]
    );
    let last_archived_block = first_archived_segment.root_block.last_archived_block();
    assert_eq!(last_archived_block.number, 1);
    assert_eq!(last_archived_block.bytes, Some(7992));

    for (index, piece) in first_archived_segment.pieces.iter().enumerate() {
        assert!(archiver::is_piece_valid(
            piece,
            first_archived_segment.root_block.merkle_tree_root(),
            index,
            RECORD_SIZE,
        ));
    }

    let archived_segments = archiver.add_block(rand::random::<[u8; SEGMENT_SIZE * 2]>());
    assert_eq!(archived_segments.len(), 2);
    {
        let archived_segment = archived_segments.get(0).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 2);
        assert_eq!(last_archived_block.bytes, Some(13229));
    }
    {
        let archived_segment = archived_segments.get(1).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 2);
        assert_eq!(last_archived_block.bytes, Some(29135));
    }

    let mut expected_segment_index = 1_u64;
    let mut previous_root_block_hash = first_archived_segment.root_block.hash();
    for archived_segment in archived_segments {
        assert_eq!(archived_segment.pieces.len(), MERKLE_NUM_LEAVES);
        assert_eq!(
            archived_segment.root_block.segment_index(),
            expected_segment_index
        );
        assert_eq!(
            archived_segment.root_block.prev_root_block_hash(),
            previous_root_block_hash
        );

        for (index, piece) in archived_segment.pieces.iter().enumerate() {
            assert!(archiver::is_piece_valid(
                piece,
                archived_segment.root_block.merkle_tree_root(),
                index,
                RECORD_SIZE,
            ));
        }

        expected_segment_index += 1;
        previous_root_block_hash = archived_segment.root_block.hash();
    }

    // Add a block such that it fits in the next segment exactly
    let archived_segments = archiver.add_block(rand::random::<[u8; SEGMENT_SIZE - 2960]>());
    assert_eq!(archived_segments.len(), 1);
    {
        let archived_segment = archived_segments.get(0).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 3);
        assert_eq!(last_archived_block.bytes, None);
    }
}

#[test]
fn archiver_invalid_usage() {
    assert_matches!(
        Archiver::new(5, SEGMENT_SIZE),
        Err(ArchiverInstantiationError::RecordSizeTooSmall),
    );

    assert_matches!(
        Archiver::new(10, 9),
        Err(ArchiverInstantiationError::SegmentSizeTooSmall),
    );
    assert_matches!(
        Archiver::new(SEGMENT_SIZE, SEGMENT_SIZE),
        Err(ArchiverInstantiationError::SegmentSizeTooSmall),
    );

    assert_matches!(
        Archiver::new(17, SEGMENT_SIZE),
        Err(ArchiverInstantiationError::SegmentSizesNotMultipleOfRecordSize),
    );

    assert_matches!(
        Archiver::new(17, 34),
        Err(ArchiverInstantiationError::WrongRecordAndSegmentCombination),
    );
}
