use parity_scale_codec::{Compact, CompactLen, Decode, Encode};
use rand::{thread_rng, Rng};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::assert_matches::assert_matches;
use std::io::Write;
use std::iter;
use std::num::NonZeroUsize;
use subspace_archiving::archiver::{Archiver, ArchiverInstantiationError, SegmentItem};
use subspace_core_primitives::hashes::Blake3Hash;
use subspace_core_primitives::objects::{BlockObject, BlockObjectMapping, GlobalObject};
use subspace_core_primitives::pieces::{Piece, Record};
use subspace_core_primitives::segments::{
    ArchivedBlockProgress, ArchivedHistorySegment, LastArchivedBlock, RecordedHistorySegment,
    SegmentCommitment, SegmentHeader, SegmentIndex,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_kzg::Kzg;
use subspace_verification::is_piece_valid;

fn extract_data<O: Into<u64>>(data: &[u8], offset: O) -> &[u8] {
    let offset: u64 = offset.into();
    let Compact(size) = Compact::<u64>::decode(&mut &data[offset as usize..]).unwrap();
    &data[offset as usize + Compact::compact_len(&size)..][..size as usize]
}

fn extract_data_from_source_record<O: Into<u64>>(record: &Record, offset: O) -> Vec<u8> {
    let offset: u64 = offset.into();
    let Compact(size) = Compact::<u64>::decode(
        &mut record
            .to_raw_record_chunks()
            .flatten()
            .copied()
            .skip(offset as usize)
            .take(8)
            .collect::<Vec<_>>()
            .as_slice(),
    )
    .unwrap();
    record
        .to_raw_record_chunks()
        .flatten()
        .copied()
        .skip(offset as usize + Compact::compact_len(&size))
        .take(size as usize)
        .collect()
}

#[track_caller]
fn compare_block_objects_to_global_objects<'a>(
    block_objects: impl Iterator<Item = (&'a [u8], &'a BlockObject)>,
    global_objects: impl Iterator<Item = (Piece, GlobalObject)>,
) {
    block_objects.zip(global_objects).for_each(
        |((block, block_object_mapping), (piece, global_object_mapping))| {
            assert_eq!(
                extract_data_from_source_record(piece.record(), global_object_mapping.offset),
                extract_data(block, block_object_mapping.offset)
            );
        },
    );
}

#[test]
fn archiver() {
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg.clone(), erasure_coding.clone());

    let (block_0, block_0_object_mapping) = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE / 2];
        thread_rng().fill(block.as_mut_slice());

        block[0..]
            .as_mut()
            .write_all(&Compact(100_u64).encode())
            .unwrap();
        block[RecordedHistorySegment::SIZE / 3..]
            .as_mut()
            .write_all(&Compact(128_u64).encode())
            .unwrap();
        let object_mapping = BlockObjectMapping::V0 {
            objects: vec![
                BlockObject {
                    hash: Blake3Hash::default(),
                    offset: 0u32,
                },
                BlockObject {
                    hash: Blake3Hash::default(),
                    offset: RecordedHistorySegment::SIZE as u32 / 3,
                },
            ],
        };

        (block, object_mapping)
    };
    let block_0_outcome = archiver.add_block(block_0.clone(), block_0_object_mapping.clone(), true);
    let archived_segments = block_0_outcome.archived_segments;
    // There is not enough data to produce archived segment yet
    assert!(archived_segments.is_empty());

    let (block_1, block_1_object_mapping) = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE / 3 * 2];
        thread_rng().fill(block.as_mut_slice());

        block[RecordedHistorySegment::SIZE / 6..]
            .as_mut()
            .write_all(&Compact(100_u64).encode())
            .unwrap();
        block[RecordedHistorySegment::SIZE / 5..]
            .as_mut()
            .write_all(&Compact(2048_u64).encode())
            .unwrap();
        block[RecordedHistorySegment::SIZE / 3 * 2 - 200..]
            .as_mut()
            .write_all(&Compact(100_u64).encode())
            .unwrap();
        let object_mapping = BlockObjectMapping::V0 {
            objects: vec![
                BlockObject {
                    hash: Blake3Hash::default(),
                    offset: RecordedHistorySegment::SIZE as u32 / 6,
                },
                BlockObject {
                    hash: Blake3Hash::default(),
                    offset: RecordedHistorySegment::SIZE as u32 / 5,
                },
                BlockObject {
                    hash: Blake3Hash::default(),
                    offset: RecordedHistorySegment::SIZE as u32 / 3 * 2 - 200,
                },
            ],
        };
        (block, object_mapping)
    };
    // This should produce 1 archived segment
    let block_1_outcome = archiver.add_block(block_1.clone(), block_1_object_mapping.clone(), true);
    let archived_segments = block_1_outcome.archived_segments;
    let object_mapping = block_1_outcome.object_mapping;
    assert_eq!(archived_segments.len(), 1);

    let first_archived_segment = archived_segments.first().cloned().unwrap();
    assert_eq!(
        first_archived_segment.pieces.len(),
        ArchivedHistorySegment::NUM_PIECES
    );
    assert_eq!(
        first_archived_segment.segment_header.segment_index(),
        SegmentIndex::ZERO
    );
    assert_eq!(
        first_archived_segment
            .segment_header
            .prev_segment_header_hash(),
        Blake3Hash::default(),
    );
    {
        let last_archived_block = first_archived_segment.segment_header.last_archived_block();
        assert_eq!(last_archived_block.number, 1);
        assert_eq!(last_archived_block.partial_archived(), Some(65011701));
    }

    // 4 objects fit into the first segment
    assert_eq!(object_mapping.len(), 4);
    {
        let block_objects = iter::repeat(block_0.as_ref())
            .zip(block_0_object_mapping.objects())
            .chain(iter::repeat(block_1.as_ref()).zip(block_1_object_mapping.objects()));
        let global_objects = object_mapping.into_iter().map(|object_mapping| {
            (
                Piece::from(
                    &first_archived_segment.pieces[object_mapping.piece_index.position() as usize],
                ),
                object_mapping,
            )
        });

        compare_block_objects_to_global_objects(block_objects, global_objects);
    }

    #[cfg(not(feature = "parallel"))]
    let iter = first_archived_segment.pieces.iter().enumerate();
    #[cfg(feature = "parallel")]
    let iter = first_archived_segment.pieces.par_iter().enumerate();
    let results = iter
        .map(|(position, piece)| {
            (
                position,
                is_piece_valid(
                    &kzg,
                    piece,
                    &first_archived_segment.segment_header.segment_commitment(),
                    position as u32,
                ),
            )
        })
        .collect::<Vec<_>>();
    for (position, valid) in results {
        assert!(valid, "Piece at position {position} is valid");
    }

    let block_2 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE * 2];
        thread_rng().fill(block.as_mut_slice());
        block
    };
    // This should be big enough to produce two archived segments in one go
    let block_2_outcome = archiver.add_block(block_2.clone(), BlockObjectMapping::default(), true);
    let archived_segments = block_2_outcome.archived_segments.clone();
    let object_mapping = block_2_outcome.object_mapping.clone();
    assert_eq!(archived_segments.len(), 2);

    // Check that initializing archiver with initial state before last block results in the same
    // archived segments and mappings once last block is added
    {
        let mut archiver_with_initial_state = Archiver::with_initial_state(
            kzg.clone(),
            erasure_coding.clone(),
            first_archived_segment.segment_header,
            &block_1,
            block_1_object_mapping.clone(),
        )
        .unwrap();

        assert_eq!(
            archiver_with_initial_state.add_block(
                block_2.clone(),
                BlockObjectMapping::default(),
                true
            ),
            block_2_outcome,
        );
    }

    // 1 object fits into the second segment
    // There are no objects left for the third segment
    assert_eq!(object_mapping.len(), 1);
    assert_eq!(
        object_mapping[0].piece_index.segment_index(),
        archived_segments[0].segment_header.segment_index(),
    );
    {
        let block_objects =
            iter::repeat(block_1.as_ref()).zip(block_1_object_mapping.objects().iter().skip(2));
        let global_objects = object_mapping.into_iter().map(|object_mapping| {
            (
                Piece::from(
                    &archived_segments[0].pieces[object_mapping.piece_index.position() as usize],
                ),
                object_mapping,
            )
        });

        compare_block_objects_to_global_objects(block_objects, global_objects);
    }

    // Check archived bytes for block with index `2` in each archived segment
    {
        let archived_segment = archived_segments.first().unwrap();
        let last_archived_block = archived_segment.segment_header.last_archived_block();
        assert_eq!(last_archived_block.number, 2);
        assert_eq!(last_archived_block.partial_archived(), Some(108352733));
    }
    {
        let archived_segment = archived_segments.get(1).unwrap();
        let last_archived_block = archived_segment.segment_header.last_archived_block();
        assert_eq!(last_archived_block.number, 2);
        assert_eq!(last_archived_block.partial_archived(), Some(238376052));
    }

    // Check that both archived segments have expected content and valid pieces in them
    let mut expected_segment_index = SegmentIndex::ONE;
    let mut previous_segment_header_hash = first_archived_segment.segment_header.hash();
    let last_segment_header = archived_segments.iter().last().unwrap().segment_header;
    for archived_segment in archived_segments {
        assert_eq!(
            archived_segment.pieces.len(),
            ArchivedHistorySegment::NUM_PIECES
        );
        assert_eq!(
            archived_segment.segment_header.segment_index(),
            expected_segment_index
        );
        assert_eq!(
            archived_segment.segment_header.prev_segment_header_hash(),
            previous_segment_header_hash
        );

        #[cfg(not(feature = "parallel"))]
        let iter = archived_segment.pieces.iter().enumerate();
        #[cfg(feature = "parallel")]
        let iter = archived_segment.pieces.par_iter().enumerate();
        let results = iter
            .map(|(position, piece)| {
                (
                    position,
                    is_piece_valid(
                        &kzg,
                        piece,
                        &archived_segment.segment_header.segment_commitment(),
                        position as u32,
                    ),
                )
            })
            .collect::<Vec<_>>();
        for (position, valid) in results {
            assert!(valid, "Piece at position {position} is valid");
        }

        expected_segment_index += SegmentIndex::ONE;
        previous_segment_header_hash = archived_segment.segment_header.hash();
    }

    // Add a block such that it fits in the next segment exactly
    let block_3 = {
        let mut block = vec![0u8; RecordedHistorySegment::SIZE - 21670908];
        thread_rng().fill(block.as_mut_slice());
        block
    };
    let block_3_outcome = archiver.add_block(block_3.clone(), BlockObjectMapping::default(), true);
    let archived_segments = block_3_outcome.archived_segments.clone();
    let object_mapping = block_3_outcome.object_mapping.clone();
    assert_eq!(archived_segments.len(), 1);

    // There are no objects left for the fourth segment
    assert_eq!(object_mapping.len(), 0);

    // Check that initializing archiver with initial state before last block results in the same
    // archived segments and mappings once last block is added
    {
        let mut archiver_with_initial_state = Archiver::with_initial_state(
            kzg.clone(),
            erasure_coding.clone(),
            last_segment_header,
            &block_2,
            BlockObjectMapping::default(),
        )
        .unwrap();

        assert_eq!(
            archiver_with_initial_state.add_block(block_3, BlockObjectMapping::default(), true),
            block_3_outcome,
        );
    }

    // Block should fit exactly into the last archived segment (rare case)
    {
        let archived_segment = archived_segments.first().unwrap();
        let last_archived_block = archived_segment.segment_header.last_archived_block();
        assert_eq!(last_archived_block.number, 3);
        assert_eq!(last_archived_block.partial_archived(), None);

        #[cfg(not(feature = "parallel"))]
        let iter = archived_segment.pieces.iter().enumerate();
        #[cfg(feature = "parallel")]
        let iter = archived_segment.pieces.par_iter().enumerate();
        let results = iter
            .map(|(position, piece)| {
                (
                    position,
                    is_piece_valid(
                        &kzg,
                        piece,
                        &archived_segment.segment_header.segment_commitment(),
                        position as u32,
                    ),
                )
            })
            .collect::<Vec<_>>();
        for (position, valid) in results {
            assert!(valid, "Piece at position {position} is valid");
        }
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
    {
        let result = Archiver::with_initial_state(
            kzg.clone(),
            erasure_coding.clone(),
            SegmentHeader::V0 {
                segment_index: SegmentIndex::ZERO,
                segment_commitment: SegmentCommitment::default(),
                prev_segment_header_hash: Blake3Hash::default(),
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
            kzg,
            erasure_coding.clone(),
            SegmentHeader::V0 {
                segment_index: SegmentIndex::ZERO,
                segment_commitment: SegmentCommitment::default(),
                prev_segment_header_hash: Blake3Hash::default(),
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
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();

    // Carefully compute the block size such that there is just 2 bytes left to fill the segment,
    // but this should already produce archived segment since just enum variant and smallest compact
    // vector length encoding will take 2 bytes to encode, thus it will be impossible to slice
    // internal bytes of the segment item anyway
    let block_size = RecordedHistorySegment::SIZE
        // Segment enum variant
        - 1
        - 1
        // This is a rough number (a bit fewer bytes will be included in practice), but it is
        // close enough and practically will always result in the same compact length.
        - Compact::compact_len(&(RecordedHistorySegment::SIZE as u32))
        // We leave two bytes at the end intentionally
        - 2;
    assert_eq!(
        Archiver::new(kzg.clone(), erasure_coding.clone())
            .add_block(vec![0u8; block_size], BlockObjectMapping::default(), true)
            .archived_segments
            .len(),
        1
    );
    // Cutting just one byte more is not sufficient to produce a segment, this is a protection
    // against code regressions
    assert!(Archiver::new(kzg, erasure_coding)
        .add_block(
            vec![0u8; block_size - 1],
            BlockObjectMapping::default(),
            true
        )
        .archived_segments
        .is_empty());
}

#[test]
fn spill_over_edge_case() {
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg, erasure_coding);

    // Carefully compute the block size such that there is just 2 bytes left to fill the segment,
    // but this should already produce archived segment since just enum variant and smallest compact
    // vector length encoding will take 2 bytes to encode, thus it will be impossible to slice
    // internal bytes of the segment item anyway
    let block_size = RecordedHistorySegment::SIZE
        // Segment enum variant
        - 1
        // Block continuation segment item enum variant
        - 1
        // This is a rough number (a bit fewer bytes will be included in practice), but it is
        // close enough and practically will always result in the same compact length.
        - Compact::compact_len(&(RecordedHistorySegment::SIZE as u32))
        // We leave three bytes at the end intentionally
        - 3;
    assert!(archiver
        .add_block(vec![0u8; block_size], BlockObjectMapping::default(), true)
        .archived_segments
        .is_empty());

    // Here we add one more block with internal length that takes 4 bytes in compact length
    // encoding + one more for enum variant, this should result in new segment being created, but
    // the very first segment item will not include newly added block because it would result in
    // subtracting with overflow when trying to slice internal bytes of the segment item
    let block_outcome = archiver.add_block(
        vec![0u8; RecordedHistorySegment::SIZE],
        BlockObjectMapping::V0 {
            objects: vec![BlockObject {
                hash: Blake3Hash::default(),
                offset: 0,
            }],
        },
        true,
    );
    let archived_segments = block_outcome.archived_segments;
    let object_mapping = block_outcome.object_mapping;
    assert_eq!(archived_segments.len(), 2);

    // If spill over actually happened, we'll not find object mapping in the first segment
    assert_eq!(object_mapping.len(), 1);
    assert_eq!(
        object_mapping[0].piece_index.segment_index(),
        archived_segments[1].segment_header.segment_index(),
    );
}

#[test]
fn object_on_the_edge_of_segment() {
    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();
    let mut archiver = Archiver::new(kzg, erasure_coding);
    let first_block = vec![0u8; RecordedHistorySegment::SIZE];
    let block_1_outcome =
        archiver.add_block(first_block.clone(), BlockObjectMapping::default(), true);
    let archived_segments = block_1_outcome.archived_segments;
    let object_mapping = block_1_outcome.object_mapping;
    assert_eq!(archived_segments.len(), 1);
    assert_eq!(object_mapping.len(), 0);

    let archived_segment = archived_segments.into_iter().next().unwrap();
    let left_unarchived_from_first_block = first_block.len() as u32
        - archived_segment
            .segment_header
            .last_archived_block()
            .archived_progress
            .partial()
            .unwrap();

    let mut second_block = vec![0u8; RecordedHistorySegment::SIZE * 2];
    let object_mapping = BlockObject {
        hash: Blake3Hash::default(),
        // Offset is designed to fall exactly on the edge of the segment
        offset: RecordedHistorySegment::SIZE as u32
            // Segment enum variant
            - 1
            // Segment header segment item
            - SegmentItem::ParentSegmentHeader(SegmentHeader::V0 {
                segment_index: SegmentIndex::ZERO,
                segment_commitment: Default::default(),
                prev_segment_header_hash: Default::default(),
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
            - Compact::compact_len(&(RecordedHistorySegment::SIZE as u32)) as u32,
    };
    let mapped_bytes = rand::random::<[u8; 32]>().to_vec().encode();
    // Write mapped bytes at expected offset in source data
    second_block[object_mapping.offset as usize..][..mapped_bytes.len()]
        .copy_from_slice(&mapped_bytes);

    // First ensure that any smaller offset will get translated into the first archived segment,
    // this is a protection against code regressions
    {
        let block_2_outcome = archiver.clone().add_block(
            second_block.clone(),
            BlockObjectMapping::V0 {
                objects: vec![BlockObject {
                    hash: object_mapping.hash,
                    offset: object_mapping.offset - 1,
                }],
            },
            true,
        );
        let archived_segments = block_2_outcome.archived_segments;
        let object_mapping = block_2_outcome.object_mapping;

        assert_eq!(archived_segments.len(), 2);
        assert_eq!(object_mapping.len(), 1);
        assert_eq!(
            object_mapping[0].piece_index.segment_index(),
            archived_segments[0].segment_header.segment_index(),
        );
    }

    let block_2_outcome = archiver.add_block(
        second_block,
        BlockObjectMapping::V0 {
            objects: vec![object_mapping],
        },
        true,
    );
    let archived_segments = block_2_outcome.archived_segments;
    let object_mapping = block_2_outcome.object_mapping;

    assert_eq!(archived_segments.len(), 2);
    // Object should fall in the next archived segment
    assert_eq!(object_mapping.len(), 1);
    assert_eq!(
        object_mapping[0].piece_index.segment_index(),
        archived_segments[1].segment_header.segment_index(),
    );

    // Ensure bytes are mapped correctly
    assert_eq!(
        archived_segments[1].pieces[0]
            .record()
            .to_raw_record_chunks()
            .flatten()
            .copied()
            .skip(object_mapping[0].offset as usize)
            .take(mapped_bytes.len())
            .collect::<Vec<_>>(),
        mapped_bytes
    );
}
