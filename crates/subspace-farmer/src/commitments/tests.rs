use crate::plot::{xor_distance, Plot};
use crate::{commitments::Commitments, plot::PieceOffset};
use rand::prelude::*;
use rand::rngs::StdRng;
use std::{collections::BTreeMap, sync::Arc};
use subspace_core_primitives::{FlatPieces, PieceIndex, Salt, Tag, PIECE_SIZE};
use tempfile::TempDir;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[tokio::test(flavor = "multi_thread")]
async fn create() {
    init();
    let base_directory = TempDir::new().unwrap();

    let pieces: FlatPieces = vec![9u8; 4096].try_into().unwrap();
    let salt: Salt = [1u8; 8];
    let correct_tag: Tag = [23, 245, 162, 52, 107, 135, 192, 210];
    let solution_range = u64::from_be_bytes([0xff_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    let index = 0;

    let plot = Plot::open_or_create(&base_directory, [0; 32].into(), None).unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments")).unwrap();
    plot.write_many(Arc::new(pieces), index).unwrap();
    commitments.create(salt, plot).unwrap();

    let (tag, _) = commitments
        .find_by_range(correct_tag, solution_range, salt)
        .unwrap();
    assert_eq!(correct_tag, tag);
}

// TODO: Tests for recommitting in background

#[tokio::test(flavor = "multi_thread")]
async fn find_by_tag() {
    init();
    let base_directory = TempDir::new().unwrap();
    let salt: Salt = [1u8; 8];

    let plot = Plot::open_or_create(&base_directory, [0; 32].into(), None).unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments")).unwrap();

    // Generate deterministic pieces, such that we don't have random errors in CI
    let mut rng = StdRng::seed_from_u64(0);
    let mut pieces: FlatPieces = vec![0u8; 1024 * PIECE_SIZE].try_into().unwrap();
    rng.fill(pieces.as_mut());
    plot.write_many(Arc::new(pieces), 0).unwrap();

    commitments.create(salt, plot).unwrap();

    {
        let target = [0u8, 0, 0, 0, 0, 0, 0, 1];
        let solution_range = u64::from_be_bytes([0u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // This is probabilistic, but should be fine most of the time
        let (solution, _) = commitments
            .find_by_range(target, solution_range, salt)
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

#[tokio::test(flavor = "multi_thread")]
async fn partial_replica_commitments() {
    init();
    let base_directory = TempDir::new().unwrap();
    let salt: Salt = [1u8; 8];

    let max_pieces = 64;

    let address = rand::random::<[u8; 32]>().into();
    let plot = Plot::open_or_create(
        &base_directory,
        address,
        Some(max_pieces * PIECE_SIZE as u64),
    )
    .unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments")).unwrap();

    let mut pieces: FlatPieces = vec![0u8; 1024 * PIECE_SIZE].try_into().unwrap();
    // Generate deterministic pieces, such that we don't have random errors in CI
    StdRng::seed_from_u64(0).fill(pieces.as_mut());

    let mut piece_indexes = (0..1024).collect::<Vec<_>>();
    piece_indexes.sort_by_key(|i| xor_distance((*i).into(), address));

    let expected_commitments = piece_indexes[..max_pieces as usize]
        .iter()
        .map(|&i| (i, pieces.chunks(PIECE_SIZE).nth(i as usize).unwrap()))
        .map(|(i, piece)| (i, *<&[u8; PIECE_SIZE]>::try_from(piece).unwrap()))
        .map(|(i, piece)| (subspace_solving::create_tag(piece, salt), i as PieceIndex))
        .collect::<BTreeMap<Tag, PieceIndex>>();

    plot.write_many(Arc::new(pieces), 0).unwrap();
    assert_eq!(plot.piece_count(), max_pieces);

    commitments.create(salt, plot.clone()).unwrap();

    let get_solutions = |target, solution_range, salt| {
        commitments
            .find_by_range_many::<BTreeMap<_, PieceOffset>>(target, solution_range, salt)
            .unwrap()
            .into_iter()
            .map(|(tag, offset)| (tag, plot.read_piece_with_index(offset).unwrap().1))
    };

    // Check all commitments
    let target = rand::random();
    let all_commitmens = get_solutions(target, u64::MAX, salt).collect::<BTreeMap<_, _>>();
    assert_eq!(all_commitmens, expected_commitments);

    // make random queries
    for _ in 0..10 {
        let target = rand::random();
        let range = rand::random();

        let (lower, lower_overflow) = u64::from_be_bytes(target).overflowing_sub(range / 2);
        let (upper, upper_overflow) = u64::from_be_bytes(target).overflowing_add(range / 2);
        let expected = if lower_overflow || upper_overflow {
            expected_commitments
                .range(..upper.to_be_bytes())
                .chain(expected_commitments.range(lower.to_be_bytes()..))
                .map(|(&key, &val)| (key, val))
                .collect()
        } else {
            expected_commitments
                .range(lower.to_be_bytes()..upper.to_be_bytes())
                .map(|(&key, &val)| (key, val))
                .collect::<BTreeMap<_, _>>()
        };

        let got = get_solutions(target, range, salt).collect::<BTreeMap<_, _>>();

        assert_eq!(expected, got);
    }
}
