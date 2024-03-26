use crate::utils::{parse_cpu_cores_sets, run_future_in_dedicated_thread};
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

#[test]
fn test_parse_cpu_cores_sets() {
    {
        let cores = parse_cpu_cores_sets("0").unwrap();
        assert_eq!(cores.len(), 1);
        assert_eq!(cores[0].cores, vec![0]);
    }
    {
        let cores = parse_cpu_cores_sets("0,1,2").unwrap();
        assert_eq!(cores.len(), 1);
        assert_eq!(cores[0].cores, vec![0, 1, 2]);
    }
    {
        let cores = parse_cpu_cores_sets("0,1,2 4,5,6").unwrap();
        assert_eq!(cores.len(), 2);
        assert_eq!(cores[0].cores, vec![0, 1, 2]);
        assert_eq!(cores[1].cores, vec![4, 5, 6]);
    }
    {
        let cores = parse_cpu_cores_sets("0-2 4-6,7").unwrap();
        assert_eq!(cores.len(), 2);
        assert_eq!(cores[0].cores, vec![0, 1, 2]);
        assert_eq!(cores[1].cores, vec![4, 5, 6, 7]);
    }

    assert!(parse_cpu_cores_sets("").is_err());
    assert!(parse_cpu_cores_sets("a").is_err());
    assert!(parse_cpu_cores_sets("0,").is_err());
    assert!(parse_cpu_cores_sets("0,a").is_err());
    assert!(parse_cpu_cores_sets("0 a").is_err());
}
