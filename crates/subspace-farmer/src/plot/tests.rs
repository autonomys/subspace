use crate::plot::Plot;
use rand::prelude::*;
use std::sync::Arc;
use subspace_core_primitives::{ArchivedBlockProgress, LastArchivedBlock, Piece, RootBlock};
use tempfile::TempDir;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn generate_random_piece() -> Piece {
    let mut piece = Piece::default();
    rand::thread_rng().fill(&mut piece[..]);
    piece
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = r#"
    TODO: Fix test

    Plot for now has a background worker which has rocksdb in it. We need to synchronize
    dropping plot and its background worker for the following reason:

    If we open the same plot while background worker of dropped plot is still alive and
    tries to close everything, we will have a rocksdb error (trying to acquire the taken file lock).
"#]
async fn read_write() {
    init();
    let base_directory = TempDir::new().unwrap();

    let pieces = Arc::new(generate_random_piece().to_vec().try_into().unwrap());
    let index = 0;

    let plot = Plot::open_or_create(&base_directory).unwrap();
    assert!(plot.is_empty());
    plot.write_many(Arc::clone(&pieces), index).unwrap();
    assert!(!plot.is_empty());
    let extracted_piece = plot.read(index).unwrap();

    assert_eq!(pieces[..], extracted_piece[..]);

    drop(plot);

    // Make sure it is still not empty on reopen
    let plot = Plot::open_or_create(&base_directory).unwrap();
    assert!(!plot.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn last_root_block() {
    init();
    let base_directory = TempDir::new().unwrap();

    let plot = Plot::open_or_create(&base_directory).unwrap();

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
