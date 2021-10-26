use crate::plot::Plot;
use rand::prelude::*;
use std::sync::Arc;
use subspace_core_primitives::{LastArchivedBlock, Piece, RootBlock, PIECE_SIZE};
use tempfile::TempDir;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn generate_random_piece() -> Piece {
    let mut bytes = [0u8; PIECE_SIZE];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

#[tokio::test(flavor = "multi_thread")]
async fn read_write() {
    init();
    let base_directory = TempDir::new().unwrap();

    let piece = generate_random_piece();
    let index = 0;

    let plot = Plot::open_or_create(&base_directory.path().to_path_buf().into())
        .await
        .unwrap();
    assert_eq!(true, plot.is_empty());
    plot.write_many(Arc::new(vec![piece]), index).await.unwrap();
    assert_eq!(false, plot.is_empty());
    let extracted_piece = plot.read(index).await.unwrap();

    assert_eq!(piece[..], extracted_piece[..]);

    drop(plot);

    // Make sure it is still not empty on reopen
    let plot = Plot::open_or_create(&base_directory.path().to_path_buf().into())
        .await
        .unwrap();
    assert_eq!(false, plot.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn last_root_block() {
    init();
    let base_directory = TempDir::new().unwrap();

    let plot = Plot::open_or_create(&base_directory.path().to_path_buf().into())
        .await
        .unwrap();

    assert!(plot.get_last_root_block().await.unwrap().is_none());

    let root_block = RootBlock::V0 {
        segment_index: rand::random(),
        record_root: rand::random(),
        prev_root_block_hash: rand::random(),
        last_archived_block: LastArchivedBlock {
            number: rand::random(),
            partial_archived: Some(rand::random()),
        },
    };

    plot.set_last_root_block(&root_block).await.unwrap();

    assert_eq!(plot.get_last_root_block().await.unwrap(), Some(root_block));
}
