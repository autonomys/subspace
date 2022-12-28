use futures::future::{select, Either};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::sleep;

#[tokio::test]
async fn maintain_semaphore_permits_capacity() {
    let base_tasks = 2;
    let boost_per_peer = 1;
    let boost_peers_threshold = NonZeroUsize::new(1).unwrap();
    let interval = Duration::from_micros(1);
    let connected_peers_count = Arc::new(AtomicUsize::new(0));
    let tasks_semaphore = Arc::new(Semaphore::new(base_tasks));

    tokio::spawn({
        let tasks_semaphore = Arc::clone(&tasks_semaphore);
        let connected_peers_count_weak = Arc::downgrade(&connected_peers_count);

        async move {
            super::maintain_semaphore_permits_capacity(
                &tasks_semaphore,
                interval,
                connected_peers_count_weak,
                boost_per_peer,
                boost_peers_threshold,
            )
            .await;
        }
    });

    let timeout = Duration::from_millis(100);

    // Let above function time to run at least one loop
    sleep(timeout).await;

    let permit_1_result = select(
        Box::pin(tasks_semaphore.acquire()),
        Box::pin(sleep(timeout)),
    )
    .await;
    if !matches!(permit_1_result, Either::Left(_)) {
        panic!("Must be able to acquire the permit");
    }

    let permit_2_result = select(
        Box::pin(tasks_semaphore.acquire()),
        Box::pin(sleep(timeout)),
    )
    .await;
    if !matches!(permit_2_result, Either::Left(_)) {
        panic!("Must be able to acquire the second permit");
    }

    {
        let permit_3_result = select(
            Box::pin(tasks_semaphore.acquire()),
            Box::pin(sleep(timeout)),
        )
        .await;
        if !matches!(permit_3_result, Either::Right(_)) {
            panic!("Must not be able to acquire the third permit due to capacity");
        }
    }

    // Increase capacity
    connected_peers_count.fetch_add(1, Ordering::SeqCst);

    {
        let permit_3_result = select(
            Box::pin(tasks_semaphore.acquire()),
            Box::pin(sleep(timeout)),
        )
        .await;
        if !matches!(permit_3_result, Either::Right(_)) {
            panic!("Must not be able to acquire the third permit due to capacity");
        }
    }

    // Increase capacity more
    connected_peers_count.fetch_add(1, Ordering::SeqCst);

    let permit_3_result = select(
        Box::pin(tasks_semaphore.acquire()),
        Box::pin(sleep(timeout)),
    )
    .await;
    if !matches!(permit_3_result, Either::Left(_)) {
        panic!("Must be able to acquire the third permit due to increased capacity");
    }

    {
        let permit_4_result = select(
            Box::pin(tasks_semaphore.acquire()),
            Box::pin(sleep(timeout)),
        )
        .await;
        if !matches!(permit_4_result, Either::Right(_)) {
            panic!("Must not be able to acquire the fourth permit due to capacity");
        }
    }

    // Decrease capacity capacity
    connected_peers_count.fetch_sub(1, Ordering::SeqCst);

    drop(permit_3_result);

    sleep(timeout).await;

    {
        let permit_3_result = select(
            Box::pin(tasks_semaphore.acquire()),
            Box::pin(sleep(timeout)),
        )
        .await;
        if !matches!(permit_3_result, Either::Right(_)) {
            panic!("Must not be able to acquire the third permit again due to capacity anymore");
        }
    }
}
