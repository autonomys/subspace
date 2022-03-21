use crate::plot::Plot;
use rand::prelude::*;
use std::sync::Arc;
use subspace_core_primitives::{
    ArchivedBlockProgress, FlatPieces, LastArchivedBlock, Piece, RootBlock, PIECE_SIZE,
};
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

    let pieces = Arc::new(generate_random_piece().to_vec().try_into().unwrap());
    let offset = 0;

    let plot = Plot::open_or_create(&base_directory, [0; 32].into(), None).unwrap();
    assert!(plot.is_empty());
    plot.write_many(Arc::clone(&pieces), offset).unwrap();
    assert!(!plot.is_empty());
    let extracted_piece = plot.read(offset).unwrap();

    assert_eq!(pieces[..], extracted_piece[..]);

    drop(plot);

    // Make sure it is still not empty on reopen
    let plot = Plot::open_or_create(&base_directory, [0; 32].into(), None).unwrap();
    assert!(!plot.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn last_root_block() {
    init();
    let base_directory = TempDir::new().unwrap();

    let plot = Plot::open_or_create(&base_directory, [0; 32].into(), None).unwrap();

    assert!(plot.get_last_root_block().unwrap().is_none());

    let root_block = RootBlock::V0 {
        segment_index: rand::random(),
        records_root: rand::random(),
        prev_root_block_hash: rand::random(),
        last_archived_block: LastArchivedBlock {
            number: rand::random(),
            archived_progress: ArchivedBlockProgress::Partial(rand::random()),
        },
    };

    plot.set_last_root_block(&root_block).unwrap();

    assert_eq!(plot.get_last_root_block().unwrap(), Some(root_block));
}

#[tokio::test(flavor = "multi_thread")]
async fn piece_retrivable() {
    init();
    let base_directory = TempDir::new().unwrap();

    let plot = Plot::open_or_create(&base_directory, [0; 32].into(), None).unwrap();
    assert!(plot.is_empty());

    let pieces = Arc::new(generate_random_pieces(10));
    plot.write_many(Arc::clone(&pieces), 0).unwrap();
    assert!(!plot.is_empty());

    for (original_piece, offset) in pieces.chunks_exact(PIECE_SIZE).zip(0..) {
        let piece = plot.read(offset).unwrap();
        assert_eq!(piece.as_ref(), original_piece)
    }

    let pieces = Arc::new(generate_random_pieces(2));
    plot.write_many(Arc::clone(&pieces), 2).unwrap();
    assert!(!plot.is_empty());

    for (original_piece, offset) in pieces.chunks_exact(PIECE_SIZE).zip(2..) {
        let piece = plot.read(offset).unwrap();
        assert_eq!(piece.as_ref(), original_piece)
    }
}
