use crate::pieces::PieceIndex;
use crate::segments::{ArchivedHistorySegment, RecordedHistorySegment, SegmentIndex};
use crate::U256;

#[test]
fn piece_distance_middle() {
    assert_eq!(U256::MIDDLE, U256::MAX / 2);
}

/// piece index, piece position, source position, segment index, next source index
const SOURCE_PIECE_INDEX_TEST_CASES: &[(u64, u32, u32, u64, u64)] = &[
    (0, 0, 0, 0, 2),
    (2, 2, 1, 0, 4),
    (126, 126, 63, 0, 128),
    (128, 128, 64, 0, 130),
    (252, 252, 126, 0, 254),
    (254, 254, 127, 0, 256),
    (256, 0, 0, 1, 258),
    (510, 254, 127, 1, 512),
    (512, 0, 0, 2, 514),
    // Extreme values
    (
        u64::MAX / 4 - 1,
        254,
        127,
        u64::MAX / 1024,
        u64::MAX / 4 + 1,
    ),
    // Overflows
    //(u64::MAX - 3, 252, 126, u64::MAX / 256, u64::MAX - 1),
    //(u64::MAX - 1, 254, 127, u64::MAX/256, overflows),
];

/// piece index, piece position, segment index
const PARITY_PIECE_INDEX_TEST_CASES: &[(u64, u32, u64)] = &[
    (1, 1, 0),
    (3, 3, 0),
    (127, 127, 0),
    (129, 129, 0),
    (253, 253, 0),
    (255, 255, 0),
    (257, 1, 1),
    (511, 255, 1),
    (513, 1, 2),
    // Extreme values
    (u64::MAX / 4, 255, u64::MAX / 1024),
    // Overflows
    //(u64::MAX - 2, 253, u64::MAX / 256),
    //(u64::MAX, 255, u64::MAX / 256),
];

#[test]
fn source_piece_index_conversion() {
    for &(piece_index, piece_position, source_position, segment_index, next_source_piece_index) in
        SOURCE_PIECE_INDEX_TEST_CASES
    {
        let piece_index = PieceIndex::new(piece_index);
        let segment_index = SegmentIndex::new(segment_index);
        let next_source_piece_index = PieceIndex::new(next_source_piece_index);

        println!(
            "{piece_index:?} {piece_position:?} {source_position:?} {segment_index:?} {next_source_piece_index:?}"
        );

        assert_eq!(piece_index.position(), piece_position);

        assert_eq!(piece_index.source_position(), source_position);
        assert_eq!(
            PieceIndex::from_source_position(source_position, segment_index),
            piece_index
        );

        assert_eq!(piece_index.segment_index(), segment_index);
        assert_eq!(piece_index.next_source_index(), next_source_piece_index);
        assert!(piece_index.is_source(), "{piece_index:?}");

        if piece_position == 0 {
            assert_eq!(segment_index.first_piece_index(), piece_index);
        }

        // Is at piece_position index in SegmentIndex::segment_piece_indexes()
        assert_eq!(
            segment_index
                .segment_piece_indexes()
                .get(piece_position as usize),
            Some(&piece_index)
        );

        // Is at source_position index in SegmentIndex::segment_piece_indexes_source_first()
        assert_eq!(
            segment_index
                .segment_piece_indexes_source_first()
                .get(source_position as usize),
            Some(&piece_index)
        );
    }
}

#[test]
fn parity_piece_index_conversion() {
    for &(piece_index, piece_position, segment_index) in PARITY_PIECE_INDEX_TEST_CASES {
        let piece_index = PieceIndex::new(piece_index);
        let segment_index = SegmentIndex::new(segment_index);

        println!("{piece_index:?} {piece_position:?} {segment_index:?}",);

        assert_eq!(piece_index.position(), piece_position);

        assert_eq!(piece_index.segment_index(), segment_index);
        assert!(!piece_index.is_source(), "{piece_index:?}");

        if piece_position as usize == ArchivedHistorySegment::NUM_PIECES - 1 {
            assert_eq!(segment_index.last_piece_index(), piece_index);
        }

        // Is at piece_position index in SegmentIndex::segment_piece_indexes()
        assert_eq!(
            segment_index
                .segment_piece_indexes()
                .get(piece_position as usize),
            Some(&piece_index)
        );

        // Is at the corresponding index in the second half of SegmentIndex::segment_piece_indexes_source_first()
        assert_eq!(
            segment_index
                .segment_piece_indexes_source_first()
                .get(piece_position as usize / 2 + RecordedHistorySegment::NUM_RAW_RECORDS),
            Some(&piece_index)
        );
    }
}

#[test]
#[should_panic]
fn parity_piece_index_position_panic() {
    for &(piece_index, piece_position, segment_index) in PARITY_PIECE_INDEX_TEST_CASES {
        let piece_index = PieceIndex::new(piece_index);

        println!("{piece_index:?} {piece_position:?} {segment_index:?}");

        // Always panics
        piece_index.source_position();
    }
}

#[test]
#[should_panic]
fn parity_piece_index_next_source_panic() {
    for &(piece_index, piece_position, segment_index) in PARITY_PIECE_INDEX_TEST_CASES {
        let piece_index = PieceIndex::new(piece_index);

        println!("{piece_index:?} {piece_position:?} {segment_index:?}");

        // Always panics
        piece_index.next_source_index();
    }
}
