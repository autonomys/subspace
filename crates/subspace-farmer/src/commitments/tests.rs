use crate::commitments::Commitments;
use crate::plot::Plot;
use rand::prelude::*;
use rand::rngs::StdRng;
use std::sync::Arc;
use subspace_core_primitives::{Piece, Salt, Tag};
use tempfile::TempDir;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[tokio::test(flavor = "multi_thread")]
async fn create() {
    init();
    let base_directory = TempDir::new().unwrap();

    let piece: Piece = [9u8; 4096].into();
    let salt: Salt = [1u8; 8];
    let correct_tag: Tag = [23, 245, 162, 52, 107, 135, 192, 210];
    let solution_range = u64::from_be_bytes([0xff_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    let index = 0;

    let plot = Plot::open_or_create(&base_directory.path().to_path_buf().into())
        .await
        .unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments").into())
        .await
        .unwrap();
    plot.write_many(Arc::new(vec![piece]), index).await.unwrap();
    commitments.create(salt, plot).await.unwrap();

    let (tag, _) = commitments
        .find_by_range(correct_tag, solution_range, salt)
        .await
        .unwrap();
    assert_eq!(correct_tag, tag);
}

// TODO: Tests for recommitting in background

#[tokio::test(flavor = "multi_thread")]
async fn find_by_tag() {
    init();
    let base_directory = TempDir::new().unwrap();
    let salt: Salt = [1u8; 8];

    let plot = Plot::open_or_create(&base_directory.path().to_path_buf().into())
        .await
        .unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments").into())
        .await
        .unwrap();

    // Generate deterministic pieces, such that we don't have random errors in CI
    let mut rng = StdRng::seed_from_u64(0);
    plot.write_many(
        Arc::new(
            (0..1024_usize)
                .map(|_| {
                    let mut piece = Piece::default();
                    rng.fill(&mut piece[..]);
                    piece
                })
                .collect(),
        ),
        0,
    )
    .await
    .unwrap();

    commitments.create(salt, plot).await.unwrap();

    {
        let target = [0u8, 0, 0, 0, 0, 0, 0, 1];
        let solution_range = u64::from_be_bytes([0u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // This is probabilistic, but should be fine most of the time
        let (solution, _) = commitments
            .find_by_range(target, solution_range, salt)
            .await
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
        let (solution, _) = commitments
            .find_by_range(target, solution_range, salt)
            .await
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
        let (solution, _) = commitments
            .find_by_range(target, solution_range, salt)
            .await
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
