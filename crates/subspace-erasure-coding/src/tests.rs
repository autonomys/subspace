use crate::ErasureCoding;
use kzg::G1;
use rust_kzg_blst::types::g1::FsG1;
use std::iter;
use std::num::NonZeroUsize;
use subspace_core_primitives::ScalarBytes;
use subspace_kzg::{Commitment, Scalar};

// TODO: This could have been done in-place, once implemented can be exposed as a utility
fn concatenated_to_interleaved<T>(input: Vec<T>) -> Vec<T>
where
    T: Clone,
{
    if input.len() <= 1 {
        return input;
    }

    let (first_half, second_half) = input.split_at(input.len() / 2);

    first_half
        .iter()
        .zip(second_half)
        .flat_map(|(a, b)| [a, b])
        .cloned()
        .collect()
}

// TODO: This could have been done in-place, once implemented can be exposed as a utility
fn interleaved_to_concatenated<T>(input: Vec<T>) -> Vec<T>
where
    T: Clone,
{
    let first_half = input.iter().step_by(2);
    let second_half = input.iter().skip(1).step_by(2);

    first_half.chain(second_half).cloned().collect()
}

#[test]
fn basic_data() {
    let scale = NonZeroUsize::new(8).unwrap();
    let num_shards = 2usize.pow(scale.get() as u32);
    let ec = ErasureCoding::new(scale).unwrap();

    let source_shards = (0..num_shards / 2)
        .map(|_| rand::random::<[u8; ScalarBytes::SAFE_BYTES]>())
        .map(Scalar::from)
        .collect::<Vec<_>>();

    let parity_shards = ec.extend(&source_shards).unwrap();

    assert_ne!(source_shards, parity_shards);

    let partial_shards = concatenated_to_interleaved(
        iter::repeat(None)
            .take(num_shards / 4)
            .chain(source_shards.iter().skip(num_shards / 4).copied().map(Some))
            .chain(parity_shards.iter().take(num_shards / 4).copied().map(Some))
            .chain(iter::repeat(None).take(num_shards / 4))
            .collect::<Vec<_>>(),
    );

    let recovered = interleaved_to_concatenated(ec.recover(&partial_shards).unwrap());

    assert_eq!(
        recovered,
        source_shards
            .iter()
            .chain(&parity_shards)
            .copied()
            .collect::<Vec<_>>()
    );
}

#[test]
fn basic_commitments() {
    let scale = NonZeroUsize::new(7).unwrap();
    let num_shards = 2usize.pow(scale.get() as u32);
    let ec = ErasureCoding::new(scale).unwrap();

    let source_commitments = (0..num_shards / 2)
        .map(|_| Commitment::from(FsG1::rand()))
        .collect::<Vec<_>>();

    let parity_commitments = ec.extend_commitments(&source_commitments).unwrap();

    assert_eq!(source_commitments.len() * 2, parity_commitments.len());

    // Even indices must be source
    assert_eq!(
        source_commitments,
        parity_commitments
            .iter()
            .step_by(2)
            .copied()
            .collect::<Vec<_>>()
    );
}

#[test]
fn bad_shards_number() {
    let scale = NonZeroUsize::new(8).unwrap();
    let num_shards = 2usize.pow(scale.get() as u32);
    let ec = ErasureCoding::new(scale).unwrap();

    let source_shards = vec![Default::default(); num_shards - 1];

    assert!(ec.extend(&source_shards).is_err());

    let partial_shards = vec![Default::default(); num_shards - 1];
    assert!(ec.recover(&partial_shards).is_err());
}

#[test]
fn not_enough_partial() {
    let scale = NonZeroUsize::new(8).unwrap();
    let num_shards = 2usize.pow(scale.get() as u32);
    let ec = ErasureCoding::new(scale).unwrap();

    let mut partial_shards = vec![None; num_shards];

    // Less than half is not sufficient
    partial_shards
        .iter_mut()
        .take(num_shards / 2 - 1)
        .for_each(|maybe_scalar| {
            maybe_scalar.replace(Scalar::default());
        });
    assert!(ec.recover(&partial_shards).is_err());

    // Any half is sufficient
    partial_shards
        .last_mut()
        .unwrap()
        .replace(Scalar::default());
    assert!(ec.recover(&partial_shards).is_ok());
}
