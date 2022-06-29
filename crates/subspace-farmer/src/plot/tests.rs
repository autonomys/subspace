use crate::plot::{PieceDistance, Plot};
use rand::prelude::*;
use std::collections::BTreeMap;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, Piece, PieceIndexHash, PIECE_SIZE};
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

#[tokio::test(flavor = "multi_thread")]
async fn read_write() {
    init();
    let base_directory = TempDir::new().unwrap();

    let pieces = Arc::<FlatPieces>::new(generate_random_piece().to_vec().try_into().unwrap());
    let offset = 0;

    let plot = Plot::open_or_create(&base_directory, [0; 32].into(), u64::MAX).unwrap();
    assert!(plot.is_empty());
    let piece_indexes = (offset..).take(pieces.count()).collect();
    plot.write_many(Arc::clone(&pieces), piece_indexes).unwrap();
    assert!(!plot.is_empty());
    let extracted_piece = plot.read(offset).unwrap();

    assert_eq!(pieces[..], extracted_piece[..]);

    drop(plot);

    // Make sure it is still not empty on reopen
    let plot = Plot::open_or_create(&base_directory, [0; 32].into(), u64::MAX).unwrap();
    assert!(!plot.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn piece_retrievable() {
    init();
    let base_directory = TempDir::new().unwrap();

    let plot = Plot::open_or_create(&base_directory, [0; 32].into(), u64::MAX).unwrap();
    assert!(plot.is_empty());

    let pieces = Arc::new(generate_random_pieces(10));
    let piece_indexes = (0..).take(pieces.count()).collect();
    plot.write_many(Arc::clone(&pieces), piece_indexes).unwrap();
    assert!(!plot.is_empty());

    for (original_piece, offset) in pieces.chunks_exact(PIECE_SIZE).zip(0..) {
        let piece = plot.read(offset).unwrap();
        assert_eq!(piece.as_ref(), original_piece)
    }

    let pieces = Arc::new(generate_random_pieces(2));
    let piece_indexes = (2..).take(pieces.count()).collect();
    plot.write_many(Arc::clone(&pieces), piece_indexes).unwrap();
    assert!(!plot.is_empty());

    for (original_piece, offset) in pieces.chunks_exact(PIECE_SIZE).zip(2..) {
        let piece = plot.read(offset).unwrap();
        assert_eq!(piece.as_ref(), original_piece)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn partial_plot() {
    init();
    let base_directory = TempDir::new().unwrap();

    let max_plot_pieces = 10;
    let address = rand::random::<[u8; 32]>().into();

    let plot = Plot::open_or_create(&base_directory, address, max_plot_pieces).unwrap();
    assert!(plot.is_empty());

    let pieces_to_plot = max_plot_pieces * 2;

    let pieces = Arc::new(generate_random_pieces(pieces_to_plot as usize));
    let piece_indexes = (0..).take(pieces.count()).collect();
    plot.write_many(Arc::clone(&pieces), piece_indexes).unwrap();
    assert!(!plot.is_empty());

    let mut piece_indexes = (0..pieces_to_plot).collect::<Vec<_>>();
    piece_indexes.sort_by_key(|i| PieceDistance::distance(&(*i).into(), &address));

    // First pieces should be present and equal
    for &i in &piece_indexes[..max_plot_pieces as usize] {
        let piece = plot.read(i).unwrap();
        let original_piece = pieces.chunks_exact(PIECE_SIZE).nth(i as usize).unwrap();
        assert_eq!(piece.as_ref(), original_piece);
    }
    // Last pieces should not be present at all
    for &i in &piece_indexes[max_plot_pieces as usize..] {
        assert!(plot.read(i).is_err());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sequential_pieces_iterator() {
    init();
    let base_directory = TempDir::new().unwrap();

    let address = rand::random::<[u8; 32]>().into();

    let plot = Plot::open_or_create(&base_directory, address, u64::MAX).unwrap();
    let pieces_to_plot = 1000;

    let pieces = Arc::new(generate_random_pieces(pieces_to_plot as _));
    let mut piece_indexes = (0..pieces_to_plot).collect::<Vec<_>>();
    plot.write_many(Arc::clone(&pieces), piece_indexes.clone())
        .unwrap();

    piece_indexes.sort_by_key(|i| PieceIndexHash::from(*i));

    let got_indexes = plot
        .get_sequential_pieces(PieceIndexHash([0; 32]), 100)
        .unwrap()
        .into_iter()
        .map(|(index, _)| index)
        .take(100)
        .collect::<Vec<_>>();
    assert_eq!(got_indexes, piece_indexes[..got_indexes.len()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn indexes_retrievable() {
    init();
    let base_directory = TempDir::new().unwrap();

    let pieces = Arc::new(generate_random_pieces(10_000));
    let offset = 0;

    let plot = Plot::open_or_create(&base_directory, [0; 32].into(), u64::MAX).unwrap();
    let count = pieces.count();
    let piece_indexes = (offset..).take(count).collect::<Vec<_>>();
    plot.write_many(Arc::clone(&pieces), piece_indexes).unwrap();
    let piece_indexes = (offset..)
        .take(pieces.count())
        .map(|index| (PieceIndexHash::from(index), index))
        .collect::<BTreeMap<_, _>>();

    for _ in 0..10000 {
        let from = PieceIndexHash(rand::random());
        let take = rand::thread_rng().gen_range(0..12000);
        let indexes = plot.read_sequential_piece_indexes(from, take).unwrap();
        let expected_indexes = piece_indexes
            .range(from..)
            .take(take as _)
            .map(|(_, index)| *index)
            .collect::<Vec<_>>();
        assert_eq!(indexes, expected_indexes);
    }
}
