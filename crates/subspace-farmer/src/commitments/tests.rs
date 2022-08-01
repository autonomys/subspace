use crate::commitments::Commitments;
use crate::plot::Plot;
use rand::prelude::*;
use rand::rngs::StdRng;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, Salt, Tag, PIECE_SIZE};
use tempfile::TempDir;

const TAGS_SEARCH_LIMIT: usize = 10;

fn init() {
    let _ = tracing_subscriber::fmt::try_init();
}

#[test]
fn create() {
    init();
    let base_directory = TempDir::new().unwrap();

    let pieces: FlatPieces = vec![9u8; 4096].try_into().unwrap();
    let salt: Salt = [1u8; 8];
    let correct_tag: Tag = [23, 245, 162, 52, 107, 135, 192, 210];
    let solution_range = u64::from_be_bytes([0xff_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

    let plot = Plot::open_or_create(
        &0usize.into(),
        base_directory.as_ref(),
        base_directory.as_ref(),
        [0; 32].into(),
        u64::MAX,
    )
    .unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments")).unwrap();
    let piece_indexes = (0..).take(pieces.count()).collect();
    plot.write_many(Arc::new(pieces), piece_indexes).unwrap();
    commitments.create(salt, plot, || false).unwrap();

    let (tag, _) = commitments
        .find_by_range(correct_tag, solution_range, salt, TAGS_SEARCH_LIMIT)
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(correct_tag, tag);
}

// TODO: Tests for recommitting in background

#[test]
fn find_by_tag() {
    init();
    let base_directory = TempDir::new().unwrap();
    let salt: Salt = [1u8; 8];

    let plot = Plot::open_or_create(
        &0usize.into(),
        base_directory.as_ref(),
        base_directory.as_ref(),
        [0; 32].into(),
        u64::MAX,
    )
    .unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments")).unwrap();

    // Generate deterministic pieces, such that we don't have random errors in CI
    let mut rng = StdRng::seed_from_u64(0);
    let mut pieces: FlatPieces = vec![0u8; 1024 * PIECE_SIZE].try_into().unwrap();
    rng.fill(pieces.as_mut());
    let piece_indexes = (0..).take(pieces.count()).collect();
    plot.write_many(Arc::new(pieces), piece_indexes).unwrap();

    commitments.create(salt, plot, || false).unwrap();

    {
        let target = [0u8, 0, 0, 0, 0, 0, 0, 1];
        let solution_range = u64::from_be_bytes([0u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // This is probabilistic, but should be fine most of the time
        let (solution, _) = commitments
            .find_by_range(target, solution_range, salt, TAGS_SEARCH_LIMIT)
            .into_iter()
            .next()
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
            .find_by_range(target, solution_range, salt, TAGS_SEARCH_LIMIT)
            .into_iter()
            .next()
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
            .find_by_range(target, solution_range, salt, TAGS_SEARCH_LIMIT)
            .into_iter()
            .next()
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

#[test]
fn remove_commitments() {
    init();
    let base_directory = TempDir::new().unwrap();

    let pieces: FlatPieces = vec![9u8; 4096].try_into().unwrap();
    let salt: Salt = [1u8; 8];
    let correct_tag: Tag = [23, 245, 162, 52, 107, 135, 192, 210];
    let solution_range = u64::from_be_bytes([0xff_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

    let plot = Plot::open_or_create(
        &0usize.into(),
        base_directory.as_ref(),
        base_directory.as_ref(),
        [0; 32].into(),
        u64::MAX,
    )
    .unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments")).unwrap();
    let piece_indexes = (0..).take(pieces.count()).collect();
    plot.write_many(Arc::new(pieces), piece_indexes).unwrap();
    commitments.create(salt, plot.clone(), || false).unwrap();

    let (_, offset) = commitments
        .find_by_range(correct_tag, solution_range, salt, TAGS_SEARCH_LIMIT)
        .into_iter()
        .next()
        .unwrap();

    commitments
        .remove_pieces(&[plot.read_piece_with_index(offset).unwrap().0])
        .unwrap();

    assert!(commitments
        .find_by_range(correct_tag, solution_range, salt, TAGS_SEARCH_LIMIT)
        .into_iter()
        .next()
        .is_none());
}
