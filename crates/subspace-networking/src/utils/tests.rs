use super::{CollectionBatcher, ResizableSemaphore};
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

#[test]
fn test_resizable_semaphore_alloc() {
    // Capacity = 3. We should be able to alloc only three permits.
    let sem = ResizableSemaphore::new("test".to_string(), NonZeroUsize::new(3).unwrap());
    let _permit_1 = sem.try_acquire().unwrap();
    let _permit_2 = sem.try_acquire().unwrap();
    let _permit_3 = sem.try_acquire().unwrap();
    assert!(sem.try_acquire().is_none());
}

#[test]
fn test_resizable_semaphore_expand() {
    // Initial capacity = 3.
    let sem = ResizableSemaphore::new("test".to_string(), NonZeroUsize::new(3).unwrap());
    let _permit_1 = sem.try_acquire().unwrap();
    let _permit_2 = sem.try_acquire().unwrap();
    let _permit_3 = sem.try_acquire().unwrap();
    assert!(sem.try_acquire().is_none());

    // Increase capacity of semaphore by 2, we should be able to alloc two more permits.
    sem.expand(2);
    let _permit_4 = sem.try_acquire().unwrap();
    let _permit_5 = sem.try_acquire().unwrap();
    assert!(sem.try_acquire().is_none());
}

#[test]
fn test_resizable_semaphore_shrink() {
    // Initial capacity = 4, alloc 4 outstanding permits.
    let sem = ResizableSemaphore::new("test".to_string(), NonZeroUsize::new(4).unwrap());
    let permit_1 = sem.try_acquire().unwrap();
    let permit_2 = sem.try_acquire().unwrap();
    let permit_3 = sem.try_acquire().unwrap();
    let _permit_4 = sem.try_acquire().unwrap();
    assert!(sem.try_acquire().is_none());

    // Shrink the capacity by 2, new capacity = 2.
    sem.shrink(2);

    // Alloc should fail as outstanding permits(4) >= capacity(2).
    assert!(sem.try_acquire().is_none());

    // Free a permit, alloc should fail as outstanding permits(3) >= capacity(2).
    std::mem::drop(permit_2);
    assert!(sem.try_acquire().is_none());

    // Free another permit, alloc should fail as outstanding permits(2) >= capacity(2).
    std::mem::drop(permit_3);
    assert!(sem.try_acquire().is_none());

    // Free another permit, alloc should succeed as outstanding permits(1) < capacity(2).
    std::mem::drop(permit_1);
    assert!(sem.try_acquire().is_some());
}
