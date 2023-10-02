use super::CollectionBatcher;
use std::num::NonZeroUsize;

#[test]
fn test_empty_collection() {
    let collection = vec![];
    let mut batcher = CollectionBatcher::<u64>::new(
        NonZeroUsize::new(3).expect("Manual non-zero initialization failed."),
    );

    assert_eq!(batcher.next_batch(collection.clone()), Vec::<u64>::new());
    assert_eq!(batcher.next_batch(collection), Vec::<u64>::new());
}

#[test]
fn test_short_collection() {
    let collection = vec![1, 2];
    let mut batcher = CollectionBatcher::<u64>::new(
        NonZeroUsize::new(3).expect("Manual non-zero initialization failed."),
    );

    assert_eq!(batcher.next_batch(collection.clone()), vec![1, 2]);
    assert_eq!(batcher.next_batch(collection), vec![1, 2]);
}

#[test]
fn test_exact_collection_size() {
    let collection = vec![1, 2, 3];
    let mut batcher = CollectionBatcher::<u64>::new(
        NonZeroUsize::new(3).expect("Manual non-zero initialization failed."),
    );

    assert_eq!(batcher.next_batch(collection.clone()), vec![1, 2, 3]);
    assert_eq!(batcher.next_batch(collection), vec![1, 2, 3]);
}

#[test]
fn test_batching_with_round_batch_size() {
    let collection = vec![1, 2, 3, 4, 5, 6];
    let mut batcher = CollectionBatcher::<u64>::new(
        NonZeroUsize::new(3).expect("Manual non-zero initialization failed."),
    );

    assert_eq!(batcher.next_batch(collection.clone()), vec![1, 2, 3]);
    assert_eq!(batcher.next_batch(collection.clone()), vec![4, 5, 6]);
    assert_eq!(batcher.next_batch(collection), vec![1, 2, 3]);
}

#[test]
fn test_batching() {
    let collection = vec![1, 2, 3, 4, 5, 6, 7];
    let mut batcher = CollectionBatcher::<u64>::new(
        NonZeroUsize::new(4).expect("Manual non-zero initialization failed."),
    );

    assert_eq!(batcher.next_batch(collection.clone()), vec![1, 2, 3, 4]);
    assert_eq!(batcher.next_batch(collection.clone()), vec![5, 6, 7, 1]);
    assert_eq!(batcher.next_batch(collection.clone()), vec![2, 3, 4, 5]);
    assert_eq!(batcher.next_batch(collection.clone()), vec![6, 7, 1, 2]);
    assert_eq!(batcher.next_batch(collection.clone()), vec![3, 4, 5, 6]);
    assert_eq!(batcher.next_batch(collection), vec![7, 1, 2, 3]);
}
