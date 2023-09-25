use crate::utils::rate_limiter::resizable_semaphore::ResizableSemaphore;
use std::num::NonZeroUsize;

#[test]
fn test_resizable_semaphore_alloc() {
    // Capacity = 3. We should be able to alloc only three permits.
    let sem = ResizableSemaphore::new(NonZeroUsize::new(3).unwrap());
    let _permit_1 = sem.try_acquire().unwrap();
    let _permit_2 = sem.try_acquire().unwrap();
    let _permit_3 = sem.try_acquire().unwrap();
    assert!(sem.try_acquire().is_none());
}

#[test]
fn test_resizable_semaphore_expand() {
    // Initial capacity = 3.
    let sem = ResizableSemaphore::new(NonZeroUsize::new(3).unwrap());
    let _permit_1 = sem.try_acquire().unwrap();
    let _permit_2 = sem.try_acquire().unwrap();
    let _permit_3 = sem.try_acquire().unwrap();
    assert!(sem.try_acquire().is_none());

    // Increase capacity of semaphore by 2, we should be able to alloc two more permits.
    sem.expand(2).unwrap();
    // Can't expand with overflow
    assert!(sem.expand(usize::MAX).is_err());
    let _permit_4 = sem.try_acquire().unwrap();
    let _permit_5 = sem.try_acquire().unwrap();
    assert!(sem.try_acquire().is_none());
}

#[test]
fn test_resizable_semaphore_shrink() {
    // Initial capacity = 4, alloc 4 outstanding permits.
    let sem = ResizableSemaphore::new(NonZeroUsize::new(4).unwrap());
    let permit_1 = sem.try_acquire().unwrap();
    let permit_2 = sem.try_acquire().unwrap();
    let permit_3 = sem.try_acquire().unwrap();
    let _permit_4 = sem.try_acquire().unwrap();
    assert!(sem.try_acquire().is_none());

    // Shrink the capacity by 2, new capacity = 2.
    sem.shrink(2).unwrap();
    // Can't shrink by more than capacity
    assert!(sem.shrink(usize::MAX).is_err());

    // Alloc should fail as outstanding permits(4) >= capacity(2).
    assert!(sem.try_acquire().is_none());

    // Free a permit, alloc should fail as outstanding permits(3) >= capacity(2).
    drop(permit_2);
    assert!(sem.try_acquire().is_none());

    // Free another permit, alloc should fail as outstanding permits(2) >= capacity(2).
    drop(permit_3);
    assert!(sem.try_acquire().is_none());

    // Free another permit, alloc should succeed as outstanding permits(1) < capacity(2).
    drop(permit_1);
    assert!(sem.try_acquire().is_some());
}
