use crate::plot::{PieceDistance, Plot};
use crate::single_plot_farm::SinglePlotFarmId;
use num_traits::WrappingSub;
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
        &SinglePlotFarmId::new(),
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
        &SinglePlotFarmId::new(),
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
        &SinglePlotFarmId::new(),
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
        &SinglePlotFarmId::new(),
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
        &SinglePlotFarmId::new(),
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
                29, 189, 125, 11, 86, 26, 65, 210, 60, 42, 70, 154, 212, 47, 189, 112, 213, 67,
                139, 174, 130, 111, 111, 214, 7, 65, 49, 144, 195, 124, 54, 59,
            ]),
            1,
        ),
        (
            PieceIndexHash::from([
                108, 221, 179, 103, 175, 189, 88, 59, 180, 143, 155, 189, 125, 91, 163, 177, 208,
                115, 139, 72, 129, 177, 205, 221, 56, 22, 149, 38, 216, 21, 129, 55,
            ]),
            3,
        ),
        (
            PieceIndexHash::from([
                129, 228, 122, 25, 230, 178, 155, 10, 101, 185, 89, 23, 98, 206, 81, 67, 237, 48,
                208, 38, 30, 93, 36, 163, 32, 23, 82, 80, 107, 32, 241, 92,
            ]),
            0,
        ),
        (
            PieceIndexHash::from([
                232, 139, 67, 253, 237, 99, 35, 239, 2, 255, 239, 251, 216, 196, 8, 70, 238, 9,
                191, 49, 98, 113, 189, 34, 54, 150, 89, 201, 89, 221, 115, 58,
            ]),
            2,
        ),
        (
            PieceIndexHash::from([
                233, 103, 96, 210, 116, 101, 58, 57, 180, 41, 168, 126, 186, 174, 157, 58, 164,
                253, 245, 139, 144, 150, 207, 11, 235, 199, 196, 229, 164, 194, 237, 141,
            ]),
            4,
        ),
        (
            PieceIndexHash::from([
                239, 251, 114, 137, 67, 25, 127, 209, 46, 105, 76, 191, 63, 62, 222, 40, 251, 247,
                73, 139, 3, 112, 198, 223, 160, 1, 56, 116, 180, 23, 193, 120,
            ]),
            5,
        ),
    ];
    assert_eq!(piece_index_hashes, expected_piece_index_hashes);

    // Public key in the middle of piece index hashes, so we can test all necessary edge-cases
    let public_key_bytes = {
        // Just after third out of six hashes
        (PieceDistance::from(expected_piece_index_hashes[2].0) + PieceDistance::one()).to_be_bytes()
    };
    let plot = Plot::open_or_create(
        &SinglePlotFarmId::new(),
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
            .get_sequential_pieces(expected_piece_index_hashes[1].0, 2)
            .unwrap()
            .into_iter()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        let expected_indexes = expected_piece_index_hashes
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
            .get_sequential_pieces(expected_piece_index_hashes[3].0, 2)
            .unwrap()
            .into_iter()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        let expected_indexes = expected_piece_index_hashes
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
            .get_sequential_pieces(expected_piece_index_hashes[3].0, 2)
            .unwrap()
            .into_iter()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        // This will wrap around number line, but will not reach the last pieces index hash
        let expected_indexes = expected_piece_index_hashes
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
            .get_sequential_pieces(expected_piece_index_hashes[4].0, 2)
            .unwrap()
            .into_iter()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        // This will wrap around number line and capture `max`, but will not go any further
        let expected_indexes = expected_piece_index_hashes
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
            .get_sequential_pieces(expected_piece_index_hashes[4].0, 2)
            .unwrap()
            .into_iter()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        // This will wrap around number line, capture `max` and crosses `min`, but will not
        // capture it because it crosses public key itself
        let expected_indexes = expected_piece_index_hashes
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
            .get_sequential_pieces(
                PieceDistance::from_be_bytes(public_key_bytes)
                    .wrapping_sub(&PieceDistance::MIDDLE)
                    .into(),
                10,
            )
            .unwrap()
            .into_iter()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        // This should read all piece indexes and nothing else
        let expected_indexes = expected_piece_index_hashes
            .iter()
            .map(|(_, index)| *index)
            .collect::<Vec<_>>();
        assert_eq!(indexes, expected_indexes);
    }
}
