//! Tests for process utilities.

use crate::run_future_in_dedicated_thread;
use std::future;
use tokio::sync::oneshot;

#[tokio::test]
async fn run_future_in_dedicated_thread_ready() {
    let value = run_future_in_dedicated_thread(|| future::ready(1), "ready".to_string())
        .unwrap()
        .await
        .unwrap();

    assert_eq!(value, 1);
}

#[tokio::test]
async fn run_future_in_dedicated_thread_cancellation() {
    // This may hang if not implemented correctly
    drop(
        run_future_in_dedicated_thread(future::pending::<()>, "cancellation".to_string()).unwrap(),
    );
}

#[test]
fn run_future_in_dedicated_thread_tokio_on_drop() {
    struct S;

    impl Drop for S {
        fn drop(&mut self) {
            // This will panic only if called from non-tokio thread
            tokio::task::spawn_blocking(|| {
                // Nothing
            });
        }
    }

    let (_sender, receiver) = oneshot::channel::<()>();

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        drop(run_future_in_dedicated_thread(
            move || async move {
                let s = S;
                let _ = receiver.await;
                drop(s);
            },
            "tokio_on_drop".to_string(),
        ));
    });
}
