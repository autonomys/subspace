use rand::Rng;
use std::assert_matches::assert_matches;
use subspace_archiving::archiver;
use subspace_archiving::archiver::{ArchiverInstantiationError, BlockArchiver, ObjectArchiver};
use subspace_core_primitives::{
    LastArchivedBlock, RootBlock, Sha256Hash, PIECE_SIZE, SHA256_HASH_SIZE,
};

const MERKLE_NUM_LEAVES: usize = 8_usize;
const WITNESS_SIZE: usize = SHA256_HASH_SIZE * MERKLE_NUM_LEAVES.log2() as usize;
const RECORD_SIZE: usize = PIECE_SIZE - WITNESS_SIZE;
const SEGMENT_SIZE: usize = RECORD_SIZE * MERKLE_NUM_LEAVES / 2;

#[test]
fn archiver() {
    let mut archiver = BlockArchiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

    let block_0 = rand::random::<[u8; SEGMENT_SIZE / 2]>();
    // There is not enough data to produce archived segment yet
    assert!(archiver.add_block(block_0.to_vec()).is_empty());

    let block_1 = rand::random::<[u8; SEGMENT_SIZE / 3 * 2]>();
    // This should produce 1 archived segment
    let archived_segments = archiver.add_block(block_1.to_vec());
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
        assert_eq!(last_archived_block.bytes, Some(7992),);
    }

    // Check that all pieces are valid
    for (position, piece) in first_archived_segment.pieces.iter().enumerate() {
        assert!(archiver::is_piece_valid(
            piece,
            first_archived_segment.root_block.merkle_tree_root(),
            position,
            RECORD_SIZE,
        ));
    }

    let block_2 = rand::random::<[u8; SEGMENT_SIZE * 2]>();
    // This should be big enough to produce two archived segments in one go
    let archived_segments = archiver.add_block(block_2.to_vec());
    assert_eq!(archived_segments.len(), 2);

    // Check that initializing archiver with initial state before last block results in the same
    // archived segments once last block is added
    {
        let mut archiver_with_initial_state = BlockArchiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            first_archived_segment.root_block,
            block_1.to_vec(),
        )
        .unwrap();

        assert_eq!(
            archiver_with_initial_state.add_block(block_2.to_vec()),
            archived_segments,
        );
    }

    // Check archived bytes for block with index `2` in each archived segment
    {
        let archived_segment = archived_segments.get(0).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 2);
        assert_eq!(last_archived_block.bytes, Some(13233),);
    }
    {
        let archived_segment = archived_segments.get(1).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 2);
        assert_eq!(last_archived_block.bytes, Some(29143),);
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

        for (position, piece) in archived_segment.pieces.iter().enumerate() {
            assert!(archiver::is_piece_valid(
                piece,
                archived_segment.root_block.merkle_tree_root(),
                position,
                RECORD_SIZE,
            ));
        }

        expected_segment_index += 1;
        previous_root_block_hash = archived_segment.root_block.hash();
    }

    // Add a block such that it fits in the next segment exactly
    let block_3 = rand::random::<[u8; SEGMENT_SIZE - 2948]>();
    let archived_segments = archiver.add_block(block_3.to_vec());
    assert_eq!(archived_segments.len(), 1);

    // Check that initializing archiver with initial state before last block results in the same
    // archived segments once last block is added
    {
        let mut archiver_with_initial_state = BlockArchiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            last_root_block,
            block_2.to_vec(),
        )
        .unwrap();

        assert_eq!(
            archiver_with_initial_state.add_block(block_3.to_vec()),
            archived_segments,
        );
    }

    // Archived segment should fit exactly into the last archived segment (rare case)
    {
        let archived_segment = archived_segments.get(0).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 3);
        assert_eq!(last_archived_block.bytes, None);

        for (position, piece) in archived_segment.pieces.iter().enumerate() {
            assert!(archiver::is_piece_valid(
                piece,
                archived_segment.root_block.merkle_tree_root(),
                position,
                RECORD_SIZE,
            ));
        }
    }
}

#[test]
fn object_archiver() {
    let mut archiver = ObjectArchiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

    let mut rng = rand::thread_rng();
    {
        let mut object = vec![0u8; SEGMENT_SIZE];

        for _ in 0..10 {
            rng.fill(object.as_mut_slice());

            assert_eq!(archiver.add_object(object.to_vec()).len(), 1);
        }
    }

    let mut archiver = archiver.into_block_archiver();

    let block_0 = rand::random::<[u8; SEGMENT_SIZE]>();

    let root_block = archiver
        .add_block(block_0.to_vec())
        .into_iter()
        .next()
        .unwrap()
        .root_block;

    let mut archiver_with_initial_state =
        BlockArchiver::with_initial_state(RECORD_SIZE, SEGMENT_SIZE, root_block, block_0.to_vec())
            .unwrap();

    let block_1 = rand::random::<[u8; SEGMENT_SIZE]>();
    assert_eq!(
        archiver.add_block(block_1.to_vec()),
        archiver_with_initial_state.add_block(block_1.to_vec()),
    );
}

#[test]
fn archiver_invalid_usage() {
    assert_matches!(
        BlockArchiver::new(5, SEGMENT_SIZE),
        Err(ArchiverInstantiationError::RecordSizeTooSmall),
    );

    assert_matches!(
        BlockArchiver::new(10, 9),
        Err(ArchiverInstantiationError::SegmentSizeTooSmall),
    );
    assert_matches!(
        BlockArchiver::new(SEGMENT_SIZE, SEGMENT_SIZE),
        Err(ArchiverInstantiationError::SegmentSizeTooSmall),
    );

    assert_matches!(
        BlockArchiver::new(17, SEGMENT_SIZE),
        Err(ArchiverInstantiationError::SegmentSizesNotMultipleOfRecordSize),
    );

    assert_matches!(
        BlockArchiver::new(17, 34),
        Err(ArchiverInstantiationError::WrongRecordAndSegmentCombination),
    );

    {
        let result = BlockArchiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            RootBlock::V0 {
                segment_index: 0,
                merkle_tree_root: Sha256Hash::default(),
                prev_root_block_hash: Sha256Hash::default(),
                last_archived_block: LastArchivedBlock {
                    number: 0,
                    bytes: Some(10),
                },
            },
            &vec![0u8; 10],
        );

        assert_matches!(
            result,
            Err(ArchiverInstantiationError::InvalidLastArchivedBlock(_)),
        );

        if let Err(ArchiverInstantiationError::InvalidLastArchivedBlock(size)) = result {
            assert_eq!(size, 10);
        }
    }

    {
        let result = BlockArchiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            RootBlock::V0 {
                segment_index: 0,
                merkle_tree_root: Sha256Hash::default(),
                prev_root_block_hash: Sha256Hash::default(),
                last_archived_block: LastArchivedBlock {
                    number: 0,
                    bytes: Some(10),
                },
            },
            &vec![0u8; 6],
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
            assert_eq!(block_bytes, 6);
            assert_eq!(archived_block_bytes, 10);
        }
    }

    {
        let result = BlockArchiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            RootBlock::V0 {
                segment_index: 0,
                merkle_tree_root: Sha256Hash::default(),
                prev_root_block_hash: Sha256Hash::default(),
                last_archived_block: LastArchivedBlock {
                    number: 0,
                    bytes: Some(0),
                },
            },
            &vec![0u8; 5],
        );

        assert_matches!(
            result,
            Err(ArchiverInstantiationError::NoBlocksInvalidInitialState),
        );
    }
}

#[test]
fn one_byte_smaller_segment() {
    let mut archiver = BlockArchiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

    // Carefully compute the block size such that there is just 2 bytes left to fill the segment,
    // but this should already produce archived segment since just enum variant and smallest compact
    // vector length encoding will take 2 bytes to encode, thus it will be impossible to slice
    // internal bytes of the segment item anyway
    assert_eq!(archiver.add_block(vec![0u8; SEGMENT_SIZE - 7]).len(), 1);
}

#[test]
fn spill_over_edge_case() {
    let mut archiver = BlockArchiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

    // Carefully compute the block size such that there is just 3 byte left to fill the segment
    assert!(archiver.add_block(vec![0u8; SEGMENT_SIZE - 8]).is_empty());

    // Here we add one more block with internal length that takes 4 bytes in compact length
    // encoding + one more for enum variant, this should result in new segment being created, but
    // the very first segment item will not include newly added block because it would result in
    // subtracting with overflow when trying to slice internal bytes of the segment item
    assert_eq!(archiver.add_block(vec![0u8; 2_usize.pow(14)]).len(), 2);
}
