use crate::plot::{PieceDistance, Plot};
use rand::prelude::*;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, Piece, PieceIndexHash, PIECE_SIZE, U256};
use tempfile::TempDir;

fn init() {
    let _ = tracing_subscriber::fmt::try_init();
}

fn generate_random_piece() -> Piece {
    let mut piece = Piece::default();
    rand::thread_rng().fill(&mut piece[..]);
    piece
}

fn generate_random_pieces(n: usize) -> FlatPieces {
    let mut pieces = FlatPieces::new(n);
    rand::thread_rng().fill(pieces.as_mut());
    pieces
}

#[test]
fn read_write() {
    init();
    let base_directory = TempDir::new().unwrap();

    let pieces = Arc::<FlatPieces>::new(generate_random_piece().to_vec().try_into().unwrap());
    let piece_index_start = 0;

    let plot = Plot::open_or_create(
        &0usize.into(),
        base_directory.as_ref(),
        base_directory.as_ref(),
        [0; 32].into(),
        u64::MAX,
    )
    .unwrap();
    assert!(plot.is_empty());
    let piece_indexes = (piece_index_start..).take(pieces.count()).collect();
    plot.write_many(Arc::clone(&pieces), piece_indexes).unwrap();
    assert!(!plot.is_empty());
    let extracted_piece = plot
        .read_piece(PieceIndexHash::from_index(piece_index_start))
        .unwrap();

    assert_eq!(pieces[..], extracted_piece[..]);

    drop(plot);

    // Make sure it is still not empty on reopen
    let plot = Plot::open_or_create(
        &0usize.into(),
        base_directory.as_ref(),
        base_directory.as_ref(),
        [0; 32].into(),
        u64::MAX,
    )
    .unwrap();
    assert!(!plot.is_empty());
}

#[test]
fn piece_retrievable() {
    init();
    let base_directory = TempDir::new().unwrap();

    let plot = Plot::open_or_create(
        &0usize.into(),
        base_directory.as_ref(),
        base_directory.as_ref(),
        [0; 32].into(),
        u64::MAX,
    )
    .unwrap();
    assert!(plot.is_empty());

    let pieces = Arc::new(generate_random_pieces(10));
    let piece_indexes = (0..).take(pieces.count()).collect();
    plot.write_many(Arc::clone(&pieces), piece_indexes).unwrap();
    assert!(!plot.is_empty());

    for (original_piece, piece_index) in pieces.chunks_exact(PIECE_SIZE).zip(0..) {
        let piece = plot
            .read_piece(PieceIndexHash::from_index(piece_index))
            .unwrap();
        assert_eq!(piece.as_ref(), original_piece)
    }

    let pieces = Arc::new(generate_random_pieces(2));
    let piece_indexes = (2..).take(pieces.count()).collect();
    plot.write_many(Arc::clone(&pieces), piece_indexes).unwrap();
    assert!(!plot.is_empty());

    for (original_piece, piece_index) in pieces.chunks_exact(PIECE_SIZE).zip(2..) {
        let piece = plot
            .read_piece(PieceIndexHash::from_index(piece_index))
            .unwrap();
        assert_eq!(piece.as_ref(), original_piece)
    }
}

#[test]
fn partial_plot() {
    init();
    let base_directory = TempDir::new().unwrap();

    let max_plot_pieces = 10;
    let public_key = random::<[u8; 32]>().into();

    let plot = Plot::open_or_create(
        &0usize.into(),
        base_directory.as_ref(),
        base_directory.as_ref(),
        public_key,
        max_plot_pieces * PIECE_SIZE as u64,
    )
    .unwrap();
    assert!(plot.is_empty());

    let pieces_to_plot = max_plot_pieces * 2;

    let pieces = Arc::new(generate_random_pieces(pieces_to_plot as usize));
    let piece_indexes = (0..).take(pieces.count()).collect();
    plot.write_many(Arc::clone(&pieces), piece_indexes).unwrap();
    assert!(!plot.is_empty());

    let mut piece_indexes = (0..pieces_to_plot).collect::<Vec<_>>();
    let public_key_as_number = U256::from_be_bytes(public_key.into());
    piece_indexes.sort_by_key(|i| {
        subspace_core_primitives::bidirectional_distance(
            &U256::from(PieceIndexHash::from_index(*i)),
            &public_key_as_number,
        )
    });

    // First pieces should be present and equal
    for &piece_index in &piece_indexes[..max_plot_pieces as usize] {
        let piece = plot
            .read_piece(PieceIndexHash::from_index(piece_index))
            .unwrap();
        let original_piece = pieces
            .chunks_exact(PIECE_SIZE)
            .nth(piece_index as usize)
            .unwrap();
        assert_eq!(piece.as_ref(), original_piece);
    }
    // Last pieces should not be present at all
    for &piece_index in &piece_indexes[max_plot_pieces as usize..] {
        assert!(plot
            .read_piece(PieceIndexHash::from_index(piece_index))
            .is_err());
    }
}

#[test]
fn sequential_pieces_iterator() {
    init();
    let base_directory = TempDir::new().unwrap();

    let public_key = random::<[u8; 32]>().into();

    let plot = Plot::open_or_create(
        &0usize.into(),
        base_directory.as_ref(),
        base_directory.as_ref(),
        public_key,
        u64::MAX,
    )
    .unwrap();
    let pieces_to_plot = 1000;

    let pieces = Arc::new(FlatPieces::new(pieces_to_plot as usize));
    let mut piece_indexes = (0..pieces_to_plot).collect::<Vec<_>>();
    plot.write_many(Arc::clone(&pieces), piece_indexes.clone())
        .unwrap();

    piece_indexes.sort_by_key(|i| PieceIndexHash::from_index(*i));

    let got_indexes = plot
        .get_sequential_pieces(PieceIndexHash::from([0; 32]), 100)
        .unwrap()
        .into_iter()
        .map(|(index, _)| index)
        .take(100)
        .collect::<Vec<_>>();
    assert_eq!(got_indexes, piece_indexes[..got_indexes.len()]);
}

#[test]
fn test_read_sequential_pieces() {
    init();
    let base_directory = TempDir::new().unwrap();

    let n_pieces = 6;
    let pieces = Arc::new(FlatPieces::new(n_pieces));

    let piece_indexes = (0..).take(n_pieces).collect::<Vec<_>>();
    let mut piece_index_hashes = piece_indexes
        .iter()
        .map(|&index| (PieceIndexHash::from_index(index), index))
        .collect::<Vec<_>>();
    piece_index_hashes.sort_by(|a, b| a.0.cmp(&b.0));

    // 6 piece index hashes, sorted as big endian numbers
    let expected_piece_index_hashes: Vec<(PieceIndexHash, u64)> = vec![
        (
            PieceIndexHash::from([
                53, 190, 50, 45, 9, 79, 157, 21, 74, 138, 186, 71, 51, 184, 73, 127, 24, 3, 83,
                189, 122, 231, 176, 161, 95, 144, 181, 134, 181, 73, 242, 139,
            ]),
            3,
        ),
        (
            PieceIndexHash::from([
                124, 159, 161, 54, 212, 65, 63, 166, 23, 54, 55, 232, 131, 182, 153, 141, 50, 225,
                214, 117, 248, 140, 221, 255, 157, 203, 207, 51, 24, 32, 244, 184,
            ]),
            1,
        ),
        (
            PieceIndexHash::from([
                175, 85, 112, 245, 161, 129, 11, 122, 247, 140, 175, 75, 199, 10, 102, 15, 13, 245,
                30, 66, 186, 249, 29, 77, 229, 178, 50, 141, 224, 232, 61, 252,
            ]),
            0,
        ),
        (
            PieceIndexHash::from([
                216, 110, 129, 18, 243, 196, 196, 68, 33, 38, 248, 233, 244, 79, 22, 134, 125, 164,
                135, 242, 144, 82, 191, 145, 184, 16, 69, 125, 179, 66, 9, 164,
            ]),
            2,
        ),
        (
            PieceIndexHash::from([
                240, 160, 39, 142, 67, 114, 69, 156, 202, 97, 89, 205, 94, 113, 207, 238, 99, 131,
                2, 167, 185, 202, 155, 5, 195, 65, 129, 172, 10, 101, 172, 93,
            ]),
            4,
        ),
        (
            PieceIndexHash::from([
                241, 62, 230, 237, 84, 234, 42, 174, 159, 196, 154, 159, 174, 181, 218, 110, 141,
                222, 240, 225, 46, 213, 211, 13, 53, 166, 36, 174, 129, 62, 4, 133,
            ]),
            5,
        ),
    ];
    assert_eq!(piece_index_hashes, expected_piece_index_hashes);

    // Public key in the middle of piece index hashes, so we can test all necessary edge-cases
    let public_key_bytes = {
        // Just after second out of four hashes
        (PieceDistance::from(piece_index_hashes[1].0) + PieceDistance::one()).to_be_bytes()
    };
    let plot = Plot::open_or_create(
        &0usize.into(),
        base_directory.as_ref(),
        base_directory.as_ref(),
        public_key_bytes.into(),
        u64::MAX,
    )
    .unwrap();
    plot.write_many(Arc::clone(&pieces), piece_indexes).unwrap();

    // Zero count should return no indexes
    {
        let indexes = plot
            .get_sequential_pieces(PieceIndexHash::from([0; 32]), 0)
            .unwrap();
        assert_eq!(indexes, vec![]);
    }

    // Non-wrapping simple case start at the left side of number line
    {
        let indexes = plot
            .get_sequential_pieces(piece_index_hashes[1].0, 2)
            .unwrap()
            .into_iter()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        let expected_indexes = piece_index_hashes
            .iter()
            .skip(1)
            .take(2)
            .map(|(_, index)| *index)
            .collect::<Vec<_>>();
        assert_eq!(indexes, expected_indexes);
    }

    // Non-wrapping simple case start at the right side of number line
    {
        let indexes = plot
            .get_sequential_pieces(piece_index_hashes[3].0, 2)
            .unwrap()
            .into_iter()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        let expected_indexes = piece_index_hashes
            .iter()
            .skip(3)
            .take(2)
            .map(|(_, index)| *index)
            .collect::<Vec<_>>();
        assert_eq!(indexes, expected_indexes);
    }

    // Wrapping before reaching `max`
    {
        let indexes = plot
            .get_sequential_pieces(piece_index_hashes[3].0, 2)
            .unwrap()
            .into_iter()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        // This will wrap around number line, but will not reach the last pieces index hash
        let expected_indexes = piece_index_hashes
            .iter()
            .skip(3)
            .take(2)
            .map(|(_, index)| *index)
            .collect::<Vec<_>>();
        assert_eq!(indexes, expected_indexes);
    }

    // Wrapping that crosses `max`, but doesn't reach `min`
    {
        let indexes = plot
            .get_sequential_pieces(piece_index_hashes[4].0, 2)
            .unwrap()
            .into_iter()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        // This will wrap around number line and capture `max`, but will not go any further
        let expected_indexes = piece_index_hashes
            .iter()
            .skip(4)
            .take(2)
            .map(|(_, index)| *index)
            .collect::<Vec<_>>();
        assert_eq!(indexes, expected_indexes);
    }

    // Wrapping that crosses `max`, and crosses `min`
    {
        let indexes = plot
            .get_sequential_pieces(piece_index_hashes[4].0, 2)
            .unwrap()
            .into_iter()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        // This will wrap around number line, capture `max` and crosses `min`, but will not
        // capture it because it crosses public key itself
        let expected_indexes = piece_index_hashes
            .iter()
            .skip(4)
            .take(2)
            .map(|(_, index)| *index)
            .collect::<Vec<_>>();
        assert_eq!(indexes, expected_indexes);
    }

    // Wrapping case, read more than there is pieces from zero
    {
        let indexes = plot
            .get_sequential_pieces(PieceIndexHash::from([0; 32]), 10)
            .unwrap()
            .into_iter()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        // This should read all piece indexes and nothing else
        let expected_indexes = piece_index_hashes
            .iter()
            .map(|(_, index)| *index)
            .collect::<Vec<_>>();
        assert_eq!(indexes, expected_indexes);
    }
}
