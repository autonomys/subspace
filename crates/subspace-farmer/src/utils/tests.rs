use crate::utils::{
    parse_cpu_cores_sets, run_future_in_dedicated_thread, thread_pool_core_indices_internal,
    CpuCoreSet,
};
use std::future;
use std::num::NonZeroUsize;
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

#[test]
fn test_thread_pool_core_indices() {
    let all_cpu_cores = vec![
        CpuCoreSet {
            cores: vec![0, 1],
            #[cfg(feature = "numa")]
            topology: None,
        },
        CpuCoreSet {
            cores: vec![4, 5],
            #[cfg(feature = "numa")]
            topology: None,
        },
        CpuCoreSet {
            cores: vec![2, 3],
            #[cfg(feature = "numa")]
            topology: None,
        },
        CpuCoreSet {
            cores: vec![6, 7],
            #[cfg(feature = "numa")]
            topology: None,
        },
    ];

    // Default behavior
    assert_eq!(
        thread_pool_core_indices_internal(all_cpu_cores.clone(), None, None)
            .into_iter()
            .map(|cpu_core_set| cpu_core_set.cores)
            .collect::<Vec<_>>(),
        vec![vec![0, 1], vec![4, 5], vec![2, 3], vec![6, 7]]
    );

    // Custom number of thread pools
    assert_eq!(
        thread_pool_core_indices_internal(
            all_cpu_cores.clone(),
            None,
            Some(NonZeroUsize::new(1).unwrap())
        )
        .into_iter()
        .map(|cpu_core_set| cpu_core_set.cores)
        .collect::<Vec<_>>(),
        vec![vec![0, 1, 4, 5, 2, 3, 6, 7]]
    );
    assert_eq!(
        thread_pool_core_indices_internal(
            all_cpu_cores.clone(),
            None,
            Some(NonZeroUsize::new(2).unwrap())
        )
        .into_iter()
        .map(|cpu_core_set| cpu_core_set.cores)
        .collect::<Vec<_>>(),
        vec![vec![0, 1, 4, 5], vec![2, 3, 6, 7]]
    );
    assert_eq!(
        thread_pool_core_indices_internal(
            all_cpu_cores.clone(),
            None,
            Some(NonZeroUsize::new(3).unwrap())
        )
        .into_iter()
        .map(|cpu_core_set| cpu_core_set.cores)
        .collect::<Vec<_>>(),
        vec![vec![0, 1, 4,], vec![5, 2, 3], vec![6, 7]]
    );
    assert_eq!(
        thread_pool_core_indices_internal(
            all_cpu_cores.clone(),
            None,
            Some(NonZeroUsize::new(4).unwrap())
        )
        .into_iter()
        .map(|cpu_core_set| cpu_core_set.cores)
        .collect::<Vec<_>>(),
        vec![vec![0, 1], vec![4, 5], vec![2, 3], vec![6, 7]]
    );

    // Custom thread pool size
    assert_eq!(
        thread_pool_core_indices_internal(
            all_cpu_cores.clone(),
            Some(NonZeroUsize::new(1).unwrap()),
            None,
        )
        .into_iter()
        .map(|cpu_core_set| cpu_core_set.cores)
        .collect::<Vec<_>>(),
        vec![vec![0], vec![1], vec![4], vec![5]]
    );
    assert_eq!(
        thread_pool_core_indices_internal(
            all_cpu_cores.clone(),
            Some(NonZeroUsize::new(2).unwrap()),
            None,
        )
        .into_iter()
        .map(|cpu_core_set| cpu_core_set.cores)
        .collect::<Vec<_>>(),
        vec![vec![0, 1], vec![4, 5], vec![2, 3], vec![6, 7]]
    );
    assert_eq!(
        thread_pool_core_indices_internal(
            all_cpu_cores.clone(),
            Some(NonZeroUsize::new(3).unwrap()),
            None,
        )
        .into_iter()
        .map(|cpu_core_set| cpu_core_set.cores)
        .collect::<Vec<_>>(),
        vec![vec![0, 1, 4], vec![5, 2, 3], vec![6, 7, 0], vec![1, 4, 5]]
    );
    assert_eq!(
        thread_pool_core_indices_internal(
            all_cpu_cores.clone(),
            Some(NonZeroUsize::new(4).unwrap()),
            None,
        )
        .into_iter()
        .map(|cpu_core_set| cpu_core_set.cores)
        .collect::<Vec<_>>(),
        vec![
            vec![0, 1, 4, 5],
            vec![2, 3, 6, 7],
            vec![0, 1, 4, 5],
            vec![2, 3, 6, 7]
        ]
    );

    // Custom number of thread pools and thread pool size
    assert_eq!(
        thread_pool_core_indices_internal(
            all_cpu_cores.clone(),
            Some(NonZeroUsize::new(1).unwrap()),
            Some(NonZeroUsize::new(1).unwrap()),
        )
        .into_iter()
        .map(|cpu_core_set| cpu_core_set.cores)
        .collect::<Vec<_>>(),
        vec![vec![0]]
    );
    assert_eq!(
        thread_pool_core_indices_internal(
            all_cpu_cores.clone(),
            Some(NonZeroUsize::new(2).unwrap()),
            Some(NonZeroUsize::new(4).unwrap()),
        )
        .into_iter()
        .map(|cpu_core_set| cpu_core_set.cores)
        .collect::<Vec<_>>(),
        vec![vec![0, 1], vec![4, 5], vec![2, 3], vec![6, 7]]
    );
    assert_eq!(
        thread_pool_core_indices_internal(
            all_cpu_cores.clone(),
            Some(NonZeroUsize::new(8).unwrap()),
            Some(NonZeroUsize::new(1).unwrap()),
        )
        .into_iter()
        .map(|cpu_core_set| cpu_core_set.cores)
        .collect::<Vec<_>>(),
        vec![vec![0, 1, 4, 5, 2, 3, 6, 7]]
    );
    assert_eq!(
        thread_pool_core_indices_internal(
            all_cpu_cores.clone(),
            Some(NonZeroUsize::new(1).unwrap()),
            Some(NonZeroUsize::new(8).unwrap()),
        )
        .into_iter()
        .map(|cpu_core_set| cpu_core_set.cores)
        .collect::<Vec<_>>(),
        vec![
            vec![0],
            vec![1],
            vec![4],
            vec![5],
            vec![2],
            vec![3],
            vec![6],
            vec![7]
        ]
    );
}
