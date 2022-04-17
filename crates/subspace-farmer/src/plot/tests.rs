use crate::plot::Plot;
use rand::prelude::*;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, Piece, PIECE_SIZE};
use subspace_solving::PieceDistance;
use tempfile::TempDir;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn generate_random_piece() -> Piece {
    let mut piece = Piece::default();
    rand::thread_rng().fill(&mut piece[..]);
    piece
}

fn generate_random_pieces(n: usize) -> FlatPieces {
    std::iter::from_fn(|| Some(generate_random_piece().to_vec().into_iter()))
        .take(n)
        .flatten()
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
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
