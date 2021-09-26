use std::assert_matches::assert_matches;
use std::num::NonZeroU32;
use subspace_archiving::archiver;
use subspace_archiving::archiver::{Archiver, ArchiverInstantiationError};
use subspace_core_primitives::{
    LastArchivedBlock, RootBlock, Sha256Hash, PIECE_SIZE, SHA256_HASH_SIZE,
};

const MERKLE_NUM_LEAVES: usize = 8_usize;
const WITNESS_SIZE: usize = SHA256_HASH_SIZE * MERKLE_NUM_LEAVES.log2() as usize;
const RECORD_SIZE: usize = PIECE_SIZE - WITNESS_SIZE;
const SEGMENT_SIZE: usize = RECORD_SIZE * MERKLE_NUM_LEAVES / 2;

#[test]
fn archiver() {
    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

    let block_0 = rand::random::<[u8; SEGMENT_SIZE / 2]>();
    // There is not enough data to produce archived segment yet
    assert!(archiver.add_block(block_0).is_empty());

    let block_1 = rand::random::<[u8; SEGMENT_SIZE / 3 * 2]>();
    // This should produce 1 archived segment
    let archived_segments = archiver.add_block(block_1);
    assert_eq!(archived_segments.len(), 1);

    let first_archived_segment = archived_segments.into_iter().next().unwrap();
    assert_eq!(first_archived_segment.pieces.len(), MERKLE_NUM_LEAVES);
    assert_eq!(first_archived_segment.root_block.segment_index(), 0);
    assert_eq!(
        first_archived_segment.root_block.prev_root_block_hash(),
        [0u8; SHA256_HASH_SIZE]
    );
    {
        let last_archived_block = first_archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 1);
        assert_eq!(
            last_archived_block.bytes,
            Some(NonZeroU32::new(7992).unwrap()),
        );
    }

    // Check that all pieces are valid
    for (index, piece) in first_archived_segment.pieces.iter().enumerate() {
        assert!(archiver::is_piece_valid(
            piece,
            first_archived_segment.root_block.merkle_tree_root(),
            index,
            RECORD_SIZE,
        ));
    }

    let block_2 = rand::random::<[u8; SEGMENT_SIZE * 2]>();
    // This should be big enough to produce two archived segments in one go
    let archived_segments = archiver.add_block(block_2);
    assert_eq!(archived_segments.len(), 2);

    // Check that initializing archiver with initial state before last block results in the same
    // archived segments once last block is added
    {
        let mut archiver_with_initial_state = Archiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            first_archived_segment.root_block,
            block_1,
        )
        .unwrap();

        assert_eq!(
            archiver_with_initial_state.add_block(block_2),
            archived_segments,
        );
    }

    // Check archived bytes for block with index `2` in each archived segment
    {
        let archived_segment = archived_segments.get(0).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 2);
        assert_eq!(
            last_archived_block.bytes,
            Some(NonZeroU32::new(13233).unwrap()),
        );
    }
    {
        let archived_segment = archived_segments.get(1).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 2);
        assert_eq!(
            last_archived_block.bytes,
            Some(NonZeroU32::new(29143).unwrap()),
        );
    }

    // Check that both archived segments have expected content and valid pieces in them
    let mut expected_segment_index = 1_u64;
    let mut previous_root_block_hash = first_archived_segment.root_block.hash();
    let last_root_block = archived_segments.iter().last().unwrap().root_block;
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
    let block_3 = rand::random::<[u8; SEGMENT_SIZE - 2948]>();
    let archived_segments = archiver.add_block(block_3);
    assert_eq!(archived_segments.len(), 1);

    // Check that initializing archiver with initial state before last block results in the same
    // archived segments once last block is added
    {
        let mut archiver_with_initial_state =
            Archiver::with_initial_state(RECORD_SIZE, SEGMENT_SIZE, last_root_block, block_2)
                .unwrap();

        assert_eq!(
            archiver_with_initial_state.add_block(block_3),
            archived_segments,
        );
    }

    // Archived segment should fit exactly into the last archived segment (rare case)
    {
        let archived_segment = archived_segments.get(0).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 3);
        assert_eq!(last_archived_block.bytes, None);

        for (index, piece) in archived_segment.pieces.iter().enumerate() {
            assert!(archiver::is_piece_valid(
                piece,
                archived_segment.root_block.merkle_tree_root(),
                index,
                RECORD_SIZE,
            ));
        }
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

    {
        let result = Archiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            RootBlock::V0 {
                segment_index: 0,
                merkle_tree_root: Sha256Hash::default(),
                prev_root_block_hash: Sha256Hash::default(),
                last_archived_block: LastArchivedBlock {
                    number: 0,
                    bytes: Some(NonZeroU32::new(10).unwrap()),
                },
            },
            vec![0u8; 9],
        );

        assert_matches!(
            result,
            Err(ArchiverInstantiationError::InvalidLastArchivedBlock(_)),
        );

        if let Err(ArchiverInstantiationError::InvalidLastArchivedBlock(size)) = result {
            assert_eq!(size, NonZeroU32::new(10).unwrap());
        }
    }

    {
        let result = Archiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            RootBlock::V0 {
                segment_index: 0,
                merkle_tree_root: Sha256Hash::default(),
                prev_root_block_hash: Sha256Hash::default(),
                last_archived_block: LastArchivedBlock {
                    number: 0,
                    bytes: Some(NonZeroU32::new(10).unwrap()),
                },
            },
            vec![0u8; 5],
        );

        assert_matches!(
            result,
            Err(ArchiverInstantiationError::InvalidBlockSmallSize { .. }),
        );

        if let Err(ArchiverInstantiationError::InvalidBlockSmallSize {
            block_bytes,
            archived_block_bytes,
        }) = result
        {
            assert_eq!(block_bytes, NonZeroU32::new(6).unwrap());
            assert_eq!(archived_block_bytes, NonZeroU32::new(10).unwrap());
        }
    }
}
