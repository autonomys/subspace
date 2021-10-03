use crate::plot::Plot;
use crate::{Salt, Tag};
use rand::prelude::*;
use subspace_core_primitives::{LastArchivedBlock, Piece, RootBlock};
use tempfile::TempDir;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn generate_random_piece() -> Piece {
    let mut bytes = [0u8; crate::PIECE_SIZE];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

#[tokio::test(flavor = "multi_thread")]
async fn read_write() {
    init();
    let base_directory = TempDir::new().unwrap();

    let piece = generate_random_piece();
    let salt: Salt = [1u8; 8];
    let index = 0;

    let plot = Plot::open_or_create(&base_directory.path().to_path_buf().into())
        .await
        .unwrap();
    assert_eq!(true, plot.is_empty().await);
    plot.write_many(vec![piece], index).await.unwrap();
    plot.create_commitment(salt).await.unwrap();
    assert_eq!(false, plot.is_empty().await);
    let extracted_piece = plot.read(index).await.unwrap();

    assert_eq!(piece[..], extracted_piece[..]);

    drop(plot);

    // Make sure it is still not empty on reopen
    let plot = Plot::open_or_create(&base_directory.path().to_path_buf().into())
        .await
        .unwrap();
    assert_eq!(false, plot.is_empty().await);
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
        merkle_tree_root: rand::random(),
        prev_root_block_hash: rand::random(),
        last_archived_block: LastArchivedBlock {
            number: rand::random(),
            bytes: Some(rand::random()),
        },
    };

    plot.set_last_root_block(&root_block).await.unwrap();

    assert_eq!(plot.get_last_root_block().await.unwrap(), Some(root_block));
}

#[tokio::test(flavor = "multi_thread")]
async fn commitment() {
    init();
    let base_directory = TempDir::new().unwrap();

    let piece: Piece = [9u8; 4096];
    let salt: Salt = [1u8; 8];
    let correct_tag: Tag = [23, 245, 162, 52, 107, 135, 192, 210];
    let solution_range = u64::from_be_bytes([0xff_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    let index = 0;

    let plot = Plot::open_or_create(&base_directory.path().to_path_buf().into())
        .await
        .unwrap();
    plot.write_many(vec![piece], index).await.unwrap();
    plot.create_commitment(salt).await.unwrap();

    let (tag, _index) = plot
        .find_by_range(correct_tag, solution_range, salt)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(correct_tag, tag);
}

#[tokio::test(flavor = "multi_thread")]
async fn find_by_tag() {
    init();
    let base_directory = TempDir::new().unwrap();
    let salt: Salt = [1u8; 8];

    let plot = Plot::open_or_create(&base_directory.path().to_path_buf().into())
        .await
        .unwrap();

    plot.write_many(
        (0..1024_usize).map(|_| generate_random_piece()).collect(),
        0,
    )
    .await
    .unwrap();

    plot.create_commitment(salt).await.unwrap();

    {
        let target = [0u8, 0, 0, 0, 0, 0, 0, 1];
        let solution_range = u64::from_be_bytes([0u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // This is probabilistic, but should be fine most of the time
        let (solution, _) = plot
            .find_by_range(target, solution_range, salt)
            .await
            .unwrap()
            .unwrap();
        // Wraps around
        let lower = u64::from_be_bytes(target).wrapping_sub(solution_range / 2);
        let upper = u64::from_be_bytes(target) + solution_range / 2;
        let solution = u64::from_be_bytes(solution);
        assert!(
            solution >= lower || solution <= upper,
            "Solution {:?} must be over wrapped lower edge {:?} or under upper edge {:?}",
            solution.to_be_bytes(),
            lower.to_be_bytes(),
            upper.to_be_bytes(),
        );
    }

    {
        let target = [0xff_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe];
        let solution_range = u64::from_be_bytes([0u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // This is probabilistic, but should be fine most of the time
        let (solution, _) = plot
            .find_by_range(target, solution_range, salt)
            .await
            .unwrap()
            .unwrap();
        // Wraps around
        let lower = u64::from_be_bytes(target) - solution_range / 2;
        let upper = u64::from_be_bytes(target).wrapping_add(solution_range / 2);
        let solution = u64::from_be_bytes(solution);
        assert!(
            solution >= lower || solution <= upper,
            "Solution {:?} must be over lower edge {:?} or under wrapped upper edge {:?}",
            solution.to_be_bytes(),
            lower.to_be_bytes(),
            upper.to_be_bytes(),
        );
    }

    {
        let target = [0xef_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let solution_range = u64::from_be_bytes([0u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // This is probabilistic, but should be fine most of the time
        let (solution, _) = plot
            .find_by_range(target, solution_range, salt)
            .await
            .unwrap()
            .unwrap();
        let lower = u64::from_be_bytes(target) - solution_range / 2;
        let upper = u64::from_be_bytes(target) + solution_range / 2;
        let solution = u64::from_be_bytes(solution);
        assert!(
            solution >= lower && solution <= upper,
            "Solution {:?} must be over lower edge {:?} and under upper edge {:?}",
            solution.to_be_bytes(),
            lower.to_be_bytes(),
            upper.to_be_bytes(),
        );
    }
}
