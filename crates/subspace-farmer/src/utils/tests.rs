use crate::utils::run_future_in_dedicated_thread;
use std::future;

#[tokio::test]
async fn run_future_in_dedicated_thread_ready() {
    let value = run_future_in_dedicated_thread(
        Box::pin(async { future::ready(1).await }),
        "ready".to_string(),
    )
    .unwrap()
    .await
    .unwrap();

    assert_eq!(value, 1);
}

#[tokio::test]
async fn run_future_in_dedicated_thread_cancellation() {
    // This may hang if not implemented correctly
    drop(
        run_future_in_dedicated_thread(
            Box::pin(async { future::pending::<()>().await }),
            "cancellation".to_string(),
        )
        .unwrap(),
    );
}
