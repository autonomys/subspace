use parity_scale_codec::{Compact, Decode, Encode};
use std::assert_matches::assert_matches;
use std::io::Write;
use std::iter;
use subspace_archiving::archiver;
use subspace_archiving::archiver::{Archiver, ArchiverInstantiationError};
use subspace_core_primitives::objects::{BlockObject, BlockObjectMapping, PieceObject};
use subspace_core_primitives::{
    ArchivedBlockProgress, LastArchivedBlock, RootBlock, Sha256Hash, PIECE_SIZE, SHA256_HASH_SIZE,
};

const MERKLE_NUM_LEAVES: usize = 8_usize;
const WITNESS_SIZE: usize = SHA256_HASH_SIZE * MERKLE_NUM_LEAVES.log2() as usize;
const RECORD_SIZE: usize = PIECE_SIZE - WITNESS_SIZE;
const SEGMENT_SIZE: usize = RECORD_SIZE * MERKLE_NUM_LEAVES / 2;

fn extract_data<O: Into<u64>>(data: &[u8], offset: O) -> &[u8] {
    let offset: u64 = offset.into();
    let Compact(size) = Compact::<u64>::decode(&mut &data[offset as usize..]).unwrap();
    &data[offset as usize..][..size as usize]
}

#[track_caller]
fn compare_block_objects_to_piece_objects<'a>(
    block_objects: impl Iterator<Item = (&'a [u8], &'a BlockObject)>,
    piece_objects: impl Iterator<Item = (&'a [u8], &'a PieceObject)>,
) {
    block_objects.zip(piece_objects).for_each(
        |((block, block_object_mapping), (piece, piece_object_mapping))| {
            assert_eq!(
                extract_data(piece, piece_object_mapping.offset()),
                extract_data(block, block_object_mapping.offset())
            );
        },
    );
}

#[test]
fn archiver() {
    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

    let (block_0, block_0_object_mapping) = {
        let mut block = rand::random::<[u8; SEGMENT_SIZE / 2]>().to_vec();
        block[0..]
            .as_mut()
            .write_all(&Compact(100_u64).encode())
            .unwrap();
        block[7000..]
            .as_mut()
            .write_all(&Compact(128_u64).encode())
            .unwrap();
        let object_mapping = BlockObjectMapping {
            objects: vec![
                BlockObject::V0 {
                    hash: Sha256Hash::default(),
                    offset: 0u32,
                },
                BlockObject::V0 {
                    hash: Sha256Hash::default(),
                    offset: 7000u32,
                },
            ],
        };

        (block, object_mapping)
    };
    // There is not enough data to produce archived segment yet
    assert!(archiver
        .add_block(block_0.clone(), block_0_object_mapping.clone())
        .is_empty());

    let (block_1, block_1_object_mapping) = {
        let mut block = rand::random::<[u8; SEGMENT_SIZE / 3 * 2]>().to_vec();
        block[100..]
            .as_mut()
            .write_all(&Compact(100_u64).encode())
            .unwrap();
        block[1000..]
            .as_mut()
            .write_all(&Compact(2048_u64).encode())
            .unwrap();
        block[10000..]
            .as_mut()
            .write_all(&Compact(100_u64).encode())
            .unwrap();
        let object_mapping = BlockObjectMapping {
            objects: vec![
                BlockObject::V0 {
                    hash: Sha256Hash::default(),
                    offset: 100u32,
                },
                BlockObject::V0 {
                    hash: Sha256Hash::default(),
                    offset: 1000u32,
                },
                BlockObject::V0 {
                    hash: Sha256Hash::default(),
                    offset: 10000u32,
                },
            ],
        };
        (block, object_mapping)
    };
    // This should produce 1 archived segment
    let archived_segments = archiver.add_block(block_1.clone(), block_1_object_mapping.clone());
    assert_eq!(archived_segments.len(), 1);

    let first_archived_segment = archived_segments.into_iter().next().unwrap();
    assert_eq!(first_archived_segment.pieces.count(), MERKLE_NUM_LEAVES);
    assert_eq!(first_archived_segment.root_block.segment_index(), 0);
    assert_eq!(
        first_archived_segment.root_block.prev_root_block_hash(),
        [0u8; SHA256_HASH_SIZE]
    );
    {
        let last_archived_block = first_archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 1);
        assert_eq!(last_archived_block.partial_archived(), Some(7992));
    }

    // 4 objects fit into the first segment
    assert_eq!(first_archived_segment.object_mapping.len(), 4);
    assert_eq!(first_archived_segment.object_mapping[0].objects.len(), 1);
    assert_eq!(first_archived_segment.object_mapping[1].objects.len(), 1);
    assert_eq!(first_archived_segment.object_mapping[2].objects.len(), 2);
    assert_eq!(first_archived_segment.object_mapping[3].objects.len(), 0);
    {
        let block_objects = iter::repeat(block_0.as_ref())
            .zip(&block_0_object_mapping.objects)
            .chain(iter::repeat(block_1.as_ref()).zip(block_1_object_mapping.objects.iter()));
        let piece_objects = first_archived_segment
            .pieces
            .as_pieces()
            .zip(&first_archived_segment.object_mapping)
            .flat_map(|(piece, object_mapping)| iter::repeat(piece).zip(&object_mapping.objects));

        compare_block_objects_to_piece_objects(block_objects, piece_objects);
    }

    // Check that all pieces are valid
    for (position, piece) in first_archived_segment.pieces.as_pieces().enumerate() {
        assert!(archiver::is_piece_valid(
            piece,
            first_archived_segment.root_block.records_root(),
            position,
            RECORD_SIZE,
        ));
    }

    let block_2 = rand::random::<[u8; SEGMENT_SIZE * 2]>().to_vec();
    // This should be big enough to produce two archived segments in one go
    let archived_segments = archiver.add_block(block_2.clone(), BlockObjectMapping::default());
    assert_eq!(archived_segments.len(), 2);

    // Check that initializing archiver with initial state before last block results in the same
    // archived segments once last block is added
    {
        let mut archiver_with_initial_state = Archiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            first_archived_segment.root_block,
            &block_1,
            block_1_object_mapping.clone(),
        )
        .unwrap();

        assert_eq!(
            archiver_with_initial_state.add_block(block_2.clone(), BlockObjectMapping::default()),
            archived_segments,
        );
    }

    // 1 object fits into the second segment
    assert_eq!(archived_segments[0].object_mapping.len(), 4);
    assert_eq!(archived_segments[0].object_mapping[0].objects.len(), 1);
    assert_eq!(archived_segments[0].object_mapping[1].objects.len(), 0);
    assert_eq!(archived_segments[0].object_mapping[2].objects.len(), 0);
    assert_eq!(archived_segments[0].object_mapping[3].objects.len(), 0);
    // 0 object fits into the second segment
    assert_eq!(archived_segments[1].object_mapping.len(), 4);
    assert_eq!(archived_segments[1].object_mapping[0].objects.len(), 0);
    assert_eq!(archived_segments[1].object_mapping[1].objects.len(), 0);
    assert_eq!(archived_segments[1].object_mapping[2].objects.len(), 0);
    assert_eq!(archived_segments[1].object_mapping[3].objects.len(), 0);
    {
        let block_objects =
            iter::repeat(block_1.as_ref()).zip(block_1_object_mapping.objects.iter().skip(2));
        let piece_objects = archived_segments[0]
            .pieces
            .as_pieces()
            .zip(&archived_segments[0].object_mapping)
            .flat_map(|(piece, object_mapping)| iter::repeat(piece).zip(&object_mapping.objects));

        compare_block_objects_to_piece_objects(block_objects, piece_objects);
    }

    // Check archived bytes for block with index `2` in each archived segment
    {
        let archived_segment = archived_segments.get(0).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 2);
        assert_eq!(last_archived_block.partial_archived(), Some(13201));
    }
    {
        let archived_segment = archived_segments.get(1).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 2);
        assert_eq!(last_archived_block.partial_archived(), Some(29079));
    }

    // Check that both archived segments have expected content and valid pieces in them
    let mut expected_segment_index = 1_u64;
    let mut previous_root_block_hash = first_archived_segment.root_block.hash();
    let last_root_block = archived_segments.iter().last().unwrap().root_block;
    for archived_segment in archived_segments {
        assert_eq!(archived_segment.pieces.count(), MERKLE_NUM_LEAVES);
        assert_eq!(
            archived_segment.root_block.segment_index(),
            expected_segment_index
        );
        assert_eq!(
            archived_segment.root_block.prev_root_block_hash(),
            previous_root_block_hash
        );

        for (position, piece) in archived_segment.pieces.as_pieces().enumerate() {
            assert!(archiver::is_piece_valid(
                piece,
                archived_segment.root_block.records_root(),
                position,
                RECORD_SIZE,
            ));
        }

        expected_segment_index += 1;
        previous_root_block_hash = archived_segment.root_block.hash();
    }

    // Add a block such that it fits in the next segment exactly
    let block_3 = rand::random::<[u8; SEGMENT_SIZE - 2948]>().to_vec();
    let archived_segments = archiver.add_block(block_3.clone(), BlockObjectMapping::default());
    assert_eq!(archived_segments.len(), 1);

    // Check that initializing archiver with initial state before last block results in the same
    // archived segments once last block is added
    {
        let mut archiver_with_initial_state = Archiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            last_root_block,
            &block_2,
            BlockObjectMapping::default(),
        )
        .unwrap();

        assert_eq!(
            archiver_with_initial_state.add_block(block_3, BlockObjectMapping::default()),
            archived_segments,
        );
    }

    // Archived segment should fit exactly into the last archived segment (rare case)
    {
        let archived_segment = archived_segments.get(0).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 3);
        assert_eq!(last_archived_block.partial_archived(), Some(12956));

        for (position, piece) in archived_segment.pieces.as_pieces().enumerate() {
            assert!(archiver::is_piece_valid(
                piece,
                archived_segment.root_block.records_root(),
                position,
                RECORD_SIZE,
            ));
        }
    }
}

#[test]
fn invalid_usage() {
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
                records_root: Sha256Hash::default(),
                object_mappings_root: Sha256Hash::default(),
                prev_root_block_hash: Sha256Hash::default(),
                last_archived_block: LastArchivedBlock {
                    number: 0,
                    archived_progress: ArchivedBlockProgress::Partial(10),
                },
            },
            &[0u8; 10],
            BlockObjectMapping::default(),
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
        let result = Archiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            RootBlock::V0 {
                segment_index: 0,
                records_root: Sha256Hash::default(),
                object_mappings_root: Sha256Hash::default(),
                prev_root_block_hash: Sha256Hash::default(),
                last_archived_block: LastArchivedBlock {
                    number: 0,
                    archived_progress: ArchivedBlockProgress::Partial(10),
                },
            },
            &[0u8; 6],
            BlockObjectMapping::default(),
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
}

#[test]
fn one_byte_smaller_segment() {
    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

    // Carefully compute the block size such that there is just 2 bytes left to fill the segment,
    // but this should already produce archived segment since just enum variant and smallest compact
    // vector length encoding will take 2 bytes to encode, thus it will be impossible to slice
    // internal bytes of the segment item anyway
    assert_eq!(
        archiver
            .add_block(vec![0u8; SEGMENT_SIZE - 7], BlockObjectMapping::default())
            .len(),
        1
    );
}

#[test]
fn spill_over_edge_case() {
    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

    // Carefully compute the block size such that there is just 3 byte left to fill the segment
    assert!(archiver
        .add_block(vec![0u8; SEGMENT_SIZE - 8], BlockObjectMapping::default())
        .is_empty());

    // Here we add one more block with internal length that takes 4 bytes in compact length
    // encoding + one more for enum variant, this should result in new segment being created, but
    // the very first segment item will not include newly added block because it would result in
    // subtracting with overflow when trying to slice internal bytes of the segment item
    assert_eq!(
        archiver
            .add_block(vec![0u8; 2_usize.pow(14)], BlockObjectMapping::default())
            .len(),
        2
    );
}

#[test]
fn object_on_the_edge_of_segment() {
    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();
    assert_eq!(
        archiver
            .add_block(vec![0u8; SEGMENT_SIZE], BlockObjectMapping::default())
            .len(),
        1
    );
    let archived_segment = archiver.add_block(
        vec![0u8; SEGMENT_SIZE * 2],
        BlockObjectMapping {
            objects: vec![BlockObject::V0 {
                hash: Sha256Hash::default(),
                // Offset is designed to fall exactly on the edge of the segment and is equal to
                // segment size minus:
                // * one byte for segment enum variant
                // * compact length of number of segment items
                // * one byte root block segment item enum variant
                // * root block segment item
                // * one byte for block continuation segment item enum variant
                // * compact length of block continuation segment item bytes length
                // * block continuation segment item bytes
                // * one byte for segment item enum variant
                // * compact length of bytes length
                offset: SEGMENT_SIZE as u32
                    - 1
                    - 1
                    - 1
                    - RootBlock::V0 {
                        segment_index: 0,
                        records_root: Default::default(),
                        object_mappings_root: Default::default(),
                        prev_root_block_hash: Default::default(),
                        last_archived_block: LastArchivedBlock {
                            number: 0,
                            archived_progress: Default::default(),
                        },
                    }
                    .encoded_size() as u32
                    - 1
                    - 4
                    - 6
                    - 1
                    - 4,
            }],
        },
    );

    assert_eq!(archived_segment.len(), 2);
    assert_eq!(
        archived_segment[0]
            .object_mapping
            .iter()
            .filter(|o| !o.objects.is_empty())
            .count(),
        0
    );
    // Object should fall in the next archived segment
    assert_eq!(
        archived_segment[1]
            .object_mapping
            .iter()
            .filter(|o| !o.objects.is_empty())
            .count(),
        1
    );

    // This will only need to be adjusted when implementation changes
    assert_eq!(
        archived_segment[1].object_mapping[0].objects[0].offset(),
        120
    );
}
