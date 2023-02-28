use parity_scale_codec::{Compact, CompactLen, Decode, Encode};
use std::assert_matches::assert_matches;
use std::io::Write;
use std::iter;
use subspace_archiving::archiver;
use subspace_archiving::archiver::{Archiver, ArchiverInstantiationError, SegmentItem};
use subspace_core_primitives::crypto::kzg::{Commitment, Kzg};
use subspace_core_primitives::objects::{BlockObject, BlockObjectMapping, PieceObject};
use subspace_core_primitives::{
    ArchivedBlockProgress, Blake2b256Hash, LastArchivedBlock, RootBlock, BLAKE2B_256_HASH_SIZE,
    RECORD_SIZE,
};

// This is data + parity shards
const PIECES_IN_SEGMENT: u32 = 8;
// In terms of source data that can be stored in the segment, not the size after archiving
const SEGMENT_SIZE: u32 = RECORD_SIZE * PIECES_IN_SEGMENT / 2;

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
    let kzg = Kzg::random(PIECES_IN_SEGMENT).unwrap();
    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE, kzg.clone()).unwrap();

    let (block_0, block_0_object_mapping) = {
        let mut block = rand::random::<[u8; SEGMENT_SIZE as usize / 2]>().to_vec();
        block[0..]
            .as_mut()
            .write_all(&Compact(100_u64).encode())
            .unwrap();
        block[SEGMENT_SIZE as usize / 3..]
            .as_mut()
            .write_all(&Compact(128_u64).encode())
            .unwrap();
        let object_mapping = BlockObjectMapping {
            objects: vec![
                BlockObject::V0 {
                    hash: Blake2b256Hash::default(),
                    offset: 0u32,
                },
                BlockObject::V0 {
                    hash: Blake2b256Hash::default(),
                    offset: SEGMENT_SIZE / 3,
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
        let mut block = rand::random::<[u8; SEGMENT_SIZE as usize / 3 * 2]>().to_vec();
        block[SEGMENT_SIZE as usize / 6..]
            .as_mut()
            .write_all(&Compact(100_u64).encode())
            .unwrap();
        block[SEGMENT_SIZE as usize / 5..]
            .as_mut()
            .write_all(&Compact(2048_u64).encode())
            .unwrap();
        block[SEGMENT_SIZE as usize / 3 * 2 - 200..]
            .as_mut()
            .write_all(&Compact(100_u64).encode())
            .unwrap();
        let object_mapping = BlockObjectMapping {
            objects: vec![
                BlockObject::V0 {
                    hash: Blake2b256Hash::default(),
                    offset: SEGMENT_SIZE / 6,
                },
                BlockObject::V0 {
                    hash: Blake2b256Hash::default(),
                    offset: SEGMENT_SIZE / 5,
                },
                BlockObject::V0 {
                    hash: Blake2b256Hash::default(),
                    offset: SEGMENT_SIZE / 3 * 2 - 200,
                },
            ],
        };
        (block, object_mapping)
    };
    // This should produce 1 archived segment
    let archived_segments = archiver.add_block(block_1.clone(), block_1_object_mapping.clone());
    assert_eq!(archived_segments.len(), 1);

    let first_archived_segment = archived_segments.into_iter().next().unwrap();
    assert_eq!(
        first_archived_segment.pieces.count(),
        PIECES_IN_SEGMENT as usize
    );
    assert_eq!(first_archived_segment.root_block.segment_index(), 0);
    assert_eq!(
        first_archived_segment.root_block.prev_root_block_hash(),
        [0u8; BLAKE2B_256_HASH_SIZE]
    );
    {
        let last_archived_block = first_archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 1);
        assert_eq!(last_archived_block.partial_archived(), Some(63381));
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
            &kzg,
            PIECES_IN_SEGMENT,
            piece,
            first_archived_segment.root_block.records_root(),
            position as u32,
            RECORD_SIZE,
        ));
    }

    let block_2 = rand::random::<[u8; SEGMENT_SIZE as usize * 2]>().to_vec();
    // This should be big enough to produce two archived segments in one go
    let archived_segments = archiver.add_block(block_2.clone(), BlockObjectMapping::default());
    assert_eq!(archived_segments.len(), 2);

    // Check that initializing archiver with initial state before last block results in the same
    // archived segments once last block is added
    {
        let mut archiver_with_initial_state = Archiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            kzg.clone(),
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
        assert_eq!(last_archived_block.partial_archived(), Some(105533));
    }
    {
        let archived_segment = archived_segments.get(1).unwrap();
        let last_archived_block = archived_segment.root_block.last_archived_block();
        assert_eq!(last_archived_block.number, 2);
        assert_eq!(last_archived_block.partial_archived(), Some(232212));
    }

    // Check that both archived segments have expected content and valid pieces in them
    let mut expected_segment_index = 1_u64;
    let mut previous_root_block_hash = first_archived_segment.root_block.hash();
    let last_root_block = archived_segments.iter().last().unwrap().root_block;
    for archived_segment in archived_segments {
        assert_eq!(archived_segment.pieces.count(), PIECES_IN_SEGMENT as usize);
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
                &kzg,
                PIECES_IN_SEGMENT,
                piece,
                archived_segment.root_block.records_root(),
                position as u32,
                RECORD_SIZE,
            ));
        }

        expected_segment_index += 1;
        previous_root_block_hash = archived_segment.root_block.hash();
    }

    // Add a block such that it fits in the next segment exactly
    let block_3 = rand::random::<[u8; SEGMENT_SIZE as usize - 21468]>().to_vec();
    let archived_segments = archiver.add_block(block_3.clone(), BlockObjectMapping::default());
    assert_eq!(archived_segments.len(), 1);

    // Check that initializing archiver with initial state before last block results in the same
    // archived segments once last block is added
    {
        let mut archiver_with_initial_state = Archiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            kzg.clone(),
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
        assert_eq!(last_archived_block.partial_archived(), None);

        for (position, piece) in archived_segment.pieces.as_pieces().enumerate() {
            assert!(archiver::is_piece_valid(
                &kzg,
                PIECES_IN_SEGMENT,
                piece,
                archived_segment.root_block.records_root(),
                position as u32,
                RECORD_SIZE,
            ));
        }
    }
}

#[test]
fn invalid_usage() {
    let kzg = Kzg::random(PIECES_IN_SEGMENT).unwrap();
    assert_matches!(
        Archiver::new(4, SEGMENT_SIZE, kzg.clone()),
        Err(ArchiverInstantiationError::RecordSizeTooSmall),
    );

    assert_matches!(
        Archiver::new(10, 9, kzg.clone()),
        Err(ArchiverInstantiationError::SegmentSizeTooSmall),
    );
    assert_matches!(
        Archiver::new(SEGMENT_SIZE, SEGMENT_SIZE, kzg.clone()),
        Err(ArchiverInstantiationError::SegmentSizeTooSmall),
    );

    assert_matches!(
        Archiver::new(17, SEGMENT_SIZE, kzg.clone()),
        Err(ArchiverInstantiationError::SegmentSizesNotMultipleOfRecordSize),
    );

    {
        let result = Archiver::with_initial_state(
            RECORD_SIZE,
            SEGMENT_SIZE,
            kzg.clone(),
            RootBlock::V0 {
                segment_index: 0,
                records_root: Commitment::default(),
                prev_root_block_hash: Blake2b256Hash::default(),
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
            kzg,
            RootBlock::V0 {
                segment_index: 0,
                records_root: Commitment::default(),
                prev_root_block_hash: Blake2b256Hash::default(),
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

// Please check commits where this tests are introduced for the edge cases they are testing (filling
// encoded segment) and ensure they still test those edge cases in case you have to decrease piece
// size in the future.

#[test]
fn one_byte_smaller_segment() {
    let kzg = Kzg::random(PIECES_IN_SEGMENT).unwrap();

    // Carefully compute the block size such that there is just 2 bytes left to fill the segment,
    // but this should already produce archived segment since just enum variant and smallest compact
    // vector length encoding will take 2 bytes to encode, thus it will be impossible to slice
    // internal bytes of the segment item anyway
    let block_size = SEGMENT_SIZE as usize
        // Segment enum variant
        - 1
        - 1
        // This is a rough number (a bit fewer bytes will be included in practice), but it is
        // close enough and practically will always result in the same compact length.
        - Compact::compact_len(&SEGMENT_SIZE)
        // We leave two bytes at the end intentionally
        - 2;
    assert_eq!(
        Archiver::new(RECORD_SIZE, SEGMENT_SIZE, kzg.clone())
            .unwrap()
            .add_block(vec![0u8; block_size], BlockObjectMapping::default())
            .len(),
        1
    );
    // Cutting just one byte more is not sufficient to produce a segment, this is a protection
    // against code regressions
    assert!(Archiver::new(RECORD_SIZE, SEGMENT_SIZE, kzg)
        .unwrap()
        .add_block(vec![0u8; block_size - 1], BlockObjectMapping::default())
        .is_empty());
}

#[test]
fn spill_over_edge_case() {
    let kzg = Kzg::random(PIECES_IN_SEGMENT).unwrap();
    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE, kzg).unwrap();

    // Carefully compute the block size such that there is just 2 bytes left to fill the segment,
    // but this should already produce archived segment since just enum variant and smallest compact
    // vector length encoding will take 2 bytes to encode, thus it will be impossible to slice
    // internal bytes of the segment item anyway
    let block_size = SEGMENT_SIZE as usize
        // Segment enum variant
        - 1
        // Block continuation segment item enum variant
        - 1
        // This is a rough number (a bit fewer bytes will be included in practice), but it is
        // close enough and practically will always result in the same compact length.
        - Compact::compact_len(&SEGMENT_SIZE)
        // We leave three bytes at the end intentionally
        - 3;
    assert!(archiver
        .add_block(vec![0u8; block_size], BlockObjectMapping::default())
        .is_empty());

    // Here we add one more block with internal length that takes 4 bytes in compact length
    // encoding + one more for enum variant, this should result in new segment being created, but
    // the very first segment item will not include newly added block because it would result in
    // subtracting with overflow when trying to slice internal bytes of the segment item
    let archived_segments = archiver.add_block(
        vec![0u8; SEGMENT_SIZE as usize],
        BlockObjectMapping {
            objects: vec![BlockObject::V0 {
                hash: Blake2b256Hash::default(),
                offset: 0,
            }],
        },
    );
    assert_eq!(archived_segments.len(), 2);
    // If spill over actually happened, we'll not find object mapping in the first segment
    assert_eq!(
        archived_segments[0]
            .object_mapping
            .iter()
            .filter(|o| !o.objects.is_empty())
            .count(),
        0
    );
    assert_eq!(
        archived_segments[1]
            .object_mapping
            .iter()
            .filter(|o| !o.objects.is_empty())
            .count(),
        1
    );
}

#[test]
fn object_on_the_edge_of_segment() {
    let kzg = Kzg::random(PIECES_IN_SEGMENT).unwrap();
    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE, kzg).unwrap();
    let first_block = vec![0u8; SEGMENT_SIZE as usize];
    let archived_segments = archiver.add_block(first_block.clone(), BlockObjectMapping::default());
    assert_eq!(archived_segments.len(), 1);
    let archived_segment = archived_segments.into_iter().next().unwrap();
    let left_unarchived_from_first_block = first_block.len() as u32
        - archived_segment
            .root_block
            .last_archived_block()
            .archived_progress
            .partial()
            .unwrap();

    let mut second_block = vec![0u8; SEGMENT_SIZE as usize * 2];
    let object_mapping = BlockObject::V0 {
        hash: Blake2b256Hash::default(),
        // Offset is designed to fall exactly on the edge of the segment
        offset: SEGMENT_SIZE
            // Segment enum variant
            - 1
            // Root block segment item
            - SegmentItem::RootBlock(RootBlock::V0 {
                segment_index: 0,
                records_root: Default::default(),
                prev_root_block_hash: Default::default(),
                last_archived_block: LastArchivedBlock {
                    number: 0,
                    // Bytes will not fit all into the first segment, so it will be archived
                    // partially, but exact value doesn't matter here as encoding length of
                    // `ArchivedBlockProgress` enum variant will be the same either way
                    archived_progress: ArchivedBlockProgress::Partial(0),
                },
            })
                .encoded_size() as u32
            // Block continuation segment item enum variant
            - 1
            // Compact length of block continuation segment item bytes length.
            - Compact::compact_len(&left_unarchived_from_first_block) as u32
            // Block continuation segment item bytes (that didn't fit into the very first segment)
            - left_unarchived_from_first_block
            // One byte for block start segment item enum variant
            - 1
            // Compact encoding of bytes length.
            // This is a rough number (a bit fewer bytes will be included in practice), but it is
            // close enough and practically will always result in the same compact length.
            - Compact::compact_len(&SEGMENT_SIZE) as u32,
    };
    let mapped_bytes = rand::random::<[u8; 32]>().to_vec().encode();
    // Write mapped bytes at expected offset in source data
    second_block[object_mapping.offset() as usize..][..mapped_bytes.len()]
        .copy_from_slice(&mapped_bytes);

    // First ensure that any smaller offset will get translated into the first archived segment,
    // this is a protection against code regressions
    {
        let archived_segments = archiver.clone().add_block(
            second_block.clone(),
            BlockObjectMapping {
                objects: vec![BlockObject::V0 {
                    hash: object_mapping.hash(),
                    offset: object_mapping.offset() - 1,
                }],
            },
        );

        assert_eq!(archived_segments.len(), 2);
        assert_eq!(
            archived_segments[0]
                .object_mapping
                .iter()
                .filter(|o| !o.objects.is_empty())
                .count(),
            1
        );
    }

    let archived_segments = archiver.add_block(
        second_block,
        BlockObjectMapping {
            objects: vec![object_mapping],
        },
    );

    assert_eq!(archived_segments.len(), 2);
    assert_eq!(
        archived_segments[0]
            .object_mapping
            .iter()
            .filter(|o| !o.objects.is_empty())
            .count(),
        0
    );
    // Object should fall in the next archived segment
    assert_eq!(
        archived_segments[1]
            .object_mapping
            .iter()
            .filter(|o| !o.objects.is_empty())
            .count(),
        1
    );
    assert_eq!(archived_segments[1].object_mapping[0].objects.len(), 1);

    // Ensure bytes are mapped correctly
    assert_eq!(
        &archived_segments[1].pieces
            [archived_segments[1].object_mapping[0].objects[0].offset() as usize..]
            [..mapped_bytes.len()],
        mapped_bytes.as_slice()
    );
}
