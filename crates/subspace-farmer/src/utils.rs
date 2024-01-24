pub mod farmer_piece_getter;
pub mod piece_validator;
pub mod readers_and_pieces;
pub mod ss58;
#[cfg(test)]
mod tests;

use crate::thread_pool_manager::{PlottingThreadPoolManager, PlottingThreadPoolPair};
use futures::channel::oneshot;
use futures::channel::oneshot::Canceled;
use futures::future::Either;
use rayon::{ThreadBuilder, ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};
use std::future::Future;
use std::num::{NonZeroUsize, ParseIntError};
use std::ops::Deref;
use std::pin::{pin, Pin};
use std::str::FromStr;
use std::task::{Context, Poll};
use std::{io, thread};
use tokio::runtime::Handle;
use tokio::task;
use tracing::{debug, warn};

/// Joins async join handle on drop
pub struct AsyncJoinOnDrop<T> {
    handle: Option<task::JoinHandle<T>>,
    abort_on_drop: bool,
}

impl<T> Drop for AsyncJoinOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            if self.abort_on_drop {
                handle.abort();
            }

            if !handle.is_finished() {
                task::block_in_place(move || {
                    let _ = Handle::current().block_on(handle);
                });
            }
        }
    }
}

impl<T> AsyncJoinOnDrop<T> {
    /// Create new instance.
    pub fn new(handle: task::JoinHandle<T>, abort_on_drop: bool) -> Self {
        Self {
            handle: Some(handle),
            abort_on_drop,
        }
    }
}

impl<T> Future for AsyncJoinOnDrop<T> {
    type Output = Result<T, task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(
            self.handle
                .as_mut()
                .expect("Only dropped in Drop impl; qed"),
        )
        .poll(cx)
    }
}

/// Joins synchronous join handle on drop
pub(crate) struct JoinOnDrop(Option<thread::JoinHandle<()>>);

impl Drop for JoinOnDrop {
    fn drop(&mut self) {
        self.0
            .take()
            .expect("Always called exactly once; qed")
            .join()
            .expect("Panic if background thread panicked");
    }
}

impl JoinOnDrop {
    // Create new instance
    pub(crate) fn new(handle: thread::JoinHandle<()>) -> Self {
        Self(Some(handle))
    }
}

impl Deref for JoinOnDrop {
    type Target = thread::JoinHandle<()>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("Only dropped in Drop impl; qed")
    }
}

/// Runs future on a dedicated thread with the specified name, will block on drop until background
/// thread with future is stopped too, ensuring nothing is left in memory
pub fn run_future_in_dedicated_thread<CreateFut, Fut, T>(
    create_future: CreateFut,
    thread_name: String,
) -> io::Result<impl Future<Output = Result<T, Canceled>> + Send>
where
    CreateFut: (FnOnce() -> Fut) + Send + 'static,
    Fut: Future<Output = T> + 'static,
    T: Send + 'static,
{
    let (drop_tx, drop_rx) = oneshot::channel::<()>();
    let (result_tx, result_rx) = oneshot::channel();
    let handle = Handle::current();
    let join_handle = thread::Builder::new().name(thread_name).spawn(move || {
        let _tokio_handle_guard = handle.enter();

        let future = pin!(create_future());

        let result = match handle.block_on(futures::future::select(future, drop_rx)) {
            Either::Left((result, _)) => result,
            Either::Right(_) => {
                // Outer future was dropped, nothing left to do
                return;
            }
        };
        if let Err(_error) = result_tx.send(result) {
            debug!(
                thread_name = ?thread::current().name(),
                "Future finished, but receiver was already dropped",
            );
        }
    })?;
    // Ensure thread will not be left hanging forever
    let join_on_drop = JoinOnDrop::new(join_handle);

    Ok(async move {
        let result = result_rx.await;
        drop(drop_tx);
        drop(join_on_drop);
        result
    })
}

/// Abstraction for CPU core set
#[derive(Debug, Clone)]
pub struct CpuCoreSet {
    /// CPU cores that belong to this set
    cores: Vec<usize>,
    #[cfg(feature = "numa")]
    topology: Option<std::sync::Arc<hwlocality::Topology>>,
}

impl CpuCoreSet {
    pub fn cpu_cores(&self) -> &[usize] {
        &self.cores
    }

    /// Will truncate list of CPU cores to this number.
    ///
    /// If `cores` is zero, call will do nothing since zero number of cores is not allowed.
    pub fn truncate(&mut self, cores: usize) {
        self.cores.truncate(cores.max(1));
    }

    /// Pin current thread to this NUMA node (not just one CPU core)
    pub fn pin_current_thread(&self) {
        #[cfg(feature = "numa")]
        if let Some(topology) = &self.topology {
            use hwlocality::cpu::binding::CpuBindingFlags;
            use hwlocality::cpu::cpuset::CpuSet;
            use hwlocality::ffi::PositiveInt;

            #[cfg(not(windows))]
            let thread_id = unsafe { libc::pthread_self() };
            #[cfg(windows)]
            let thread_id = unsafe { windows_sys::Win32::System::Threading::GetCurrentThread() };

            // load the cpuset for the given core index.
            let cpu_cores = CpuSet::from_iter(
                self.cores
                    .iter()
                    .map(|&core| PositiveInt::try_from(core).expect("Valid CPU core")),
            );

            if let Err(error) =
                topology.bind_thread_cpu(thread_id, &cpu_cores, CpuBindingFlags::empty())
            {
                warn!(%error, ?cpu_cores, "Failed to pin thread to CPU cores")
            }
        }
    }
}

/// Get all cpu cores, grouped into sets according to NUMA nodes.
///
/// Returned vector is guaranteed to have at least one element and have non-zero number of CPU cores
/// in each set.
pub fn all_cpu_cores() -> Vec<CpuCoreSet> {
    #[cfg(feature = "numa")]
    match hwlocality::Topology::new().map(std::sync::Arc::new) {
        Ok(topology) => {
            let cpu_cores = topology
                // Iterate over NUMA nodes
                .objects_at_depth(hwlocality::object::depth::Depth::NUMANode)
                // For each NUMA nodes get CPU set
                .filter_map(|node| node.cpuset())
                // For each CPU set extract individual cores
                .map(|cpuset| cpuset.iter_set().map(usize::from).collect::<Vec<_>>())
                .filter(|cores| !cores.is_empty())
                .map(|cores| CpuCoreSet {
                    cores,
                    topology: Some(std::sync::Arc::clone(&topology)),
                })
                .collect::<Vec<_>>();

            if !cpu_cores.is_empty() {
                return cpu_cores;
            }
        }
        Err(error) => {
            warn!(%error, "Failed to get CPU topology");
        }
    }
    vec![CpuCoreSet {
        cores: (0..num_cpus::get()).collect(),
        #[cfg(feature = "numa")]
        topology: None,
    }]
}

/// Parse space-separated set of groups of CPU cores (individual cores are coma-separated) into
/// vector of CPU core sets that can be used for creation of plotting/replotting thread pools.
pub fn parse_cpu_cores_sets(s: &str) -> Result<Vec<CpuCoreSet>, ParseIntError> {
    s.split(' ')
        .map(|s| {
            let cores = s
                .split(',')
                .map(usize::from_str)
                .collect::<Result<Vec<usize>, _>>()?;

            Ok(CpuCoreSet {
                cores,
                #[cfg(feature = "numa")]
                topology: hwlocality::Topology::new().map(std::sync::Arc::new).ok(),
            })
        })
        .collect()
}

/// Thread indices for each thread pool
pub fn thread_pool_core_indices(
    thread_pool_size: Option<NonZeroUsize>,
    thread_pools: Option<NonZeroUsize>,
) -> Vec<CpuCoreSet> {
    let all_numa_nodes = all_cpu_cores();
    #[cfg(feature = "numa")]
    let topology = &all_numa_nodes
        .first()
        .expect("Not empty according to function description; qed")
        .topology;

    if let Some(thread_pools) = thread_pools {
        let mut thread_pool_core_indices = Vec::<CpuCoreSet>::with_capacity(thread_pools.get());

        let total_cpu_cores = all_numa_nodes
            .iter()
            .flat_map(|set| set.cpu_cores())
            .count();

        if let Some(thread_pool_size) = thread_pool_size {
            // If thread pool size is fixed, loop over all CPU cores as many times as necessary and
            // assign contiguous ranges of CPU cores to corresponding thread pools

            for _ in 0..thread_pools.get() {
                let cpu_cores_range = if let Some(last_cpu_index) = thread_pool_core_indices
                    .last()
                    .and_then(|thread_indices| thread_indices.cpu_cores().last())
                    .copied()
                {
                    last_cpu_index + 1..
                } else {
                    0..
                };

                let cpu_cores = cpu_cores_range
                    .take(thread_pool_size.get())
                    // To loop over all CPU cores multiple times, modulo naively obtained CPU
                    // cores by the total available number of CPU cores
                    .map(|core_index| core_index % total_cpu_cores)
                    .collect();

                thread_pool_core_indices.push(CpuCoreSet {
                    cores: cpu_cores,
                    #[cfg(feature = "numa")]
                    topology: topology.clone(),
                });
            }
        } else {
            // If thread pool size is not fixed, create threads pools with `total_cpu_cores/thread_pools` threads

            let all_cpu_cores = all_numa_nodes
                .iter()
                .flat_map(|cpu_core_set| cpu_core_set.cores.iter())
                .copied()
                .collect::<Vec<_>>();

            thread_pool_core_indices = all_cpu_cores
                .chunks_exact(total_cpu_cores / thread_pools)
                .map(|cpu_cores| CpuCoreSet {
                    cores: cpu_cores.to_vec(),
                    #[cfg(feature = "numa")]
                    topology: topology.clone(),
                })
                .collect();
        }
        thread_pool_core_indices
    } else {
        // If everything is set to defaults, use physical layout of CPUs
        all_numa_nodes
    }
}

fn create_plotting_thread_pool_manager_thread_pool_pair(
    thread_prefix: &'static str,
    thread_pool_index: usize,
    cpu_core_set: CpuCoreSet,
) -> Result<ThreadPool, ThreadPoolBuildError> {
    ThreadPoolBuilder::new()
        .thread_name(move |thread_index| {
            format!("{thread_prefix}-{thread_pool_index}.{thread_index}")
        })
        .num_threads(cpu_core_set.cpu_cores().len())
        .spawn_handler({
            let handle = Handle::current();

            rayon_custom_spawn_handler(move |thread| {
                let cpu_core_set = cpu_core_set.clone();
                let handle = handle.clone();

                move || {
                    cpu_core_set.pin_current_thread();
                    drop(cpu_core_set);

                    let _guard = handle.enter();

                    task::block_in_place(|| thread.run())
                }
            })
        })
        .build()
}

/// Creates thread pool pairs for each of CPU core set pair with number of plotting and replotting threads corresponding
/// to number of cores in each set and pins threads to all of those CPU cores (each thread to all cors in a set, not
/// thread per core). Each thread will also have Tokio context available.
///
/// The easiest way to obtain CPUs is using [`all_cpu_cores`], but [`thread_pool_core_indices`] in case
/// support for user customizations is desired. They will then have to be composed into pairs for this function.
pub fn create_plotting_thread_pool_manager<I>(
    mut cpu_core_sets: I,
) -> Result<PlottingThreadPoolManager, ThreadPoolBuildError>
where
    I: ExactSizeIterator<Item = (CpuCoreSet, CpuCoreSet)>,
{
    let total_thread_pools = cpu_core_sets.len();

    PlottingThreadPoolManager::new(
        |thread_pool_index| {
            let (plotting_cpu_core_set, replotting_cpu_core_set) = cpu_core_sets
                .next()
                .expect("Number of thread pools is the same as cpu core sets; qed");

            Ok(PlottingThreadPoolPair {
                plotting: create_plotting_thread_pool_manager_thread_pool_pair(
                    "plotting",
                    thread_pool_index,
                    plotting_cpu_core_set,
                )?,
                replotting: create_plotting_thread_pool_manager_thread_pool_pair(
                    "replotting",
                    thread_pool_index,
                    replotting_cpu_core_set,
                )?,
            })
        },
        NonZeroUsize::new(total_thread_pools)
            .expect("Thread pool is guaranteed to be non-empty; qed"),
    )
}

/// This function is supposed to be used with [`rayon::ThreadPoolBuilder::spawn_handler()`] to
/// spawn handler with a custom logic defined by `spawn_hook_builder`.
///
/// `spawn_hook_builder` is called with thread builder to create `spawn_handler` that in turn will
/// be spawn rayon's thread with desired environment.
pub fn rayon_custom_spawn_handler<SpawnHandlerBuilder, SpawnHandler, SpawnHandlerResult>(
    mut spawn_handler_builder: SpawnHandlerBuilder,
) -> impl FnMut(ThreadBuilder) -> io::Result<()>
where
    SpawnHandlerBuilder: (FnMut(ThreadBuilder) -> SpawnHandler) + Clone,
    SpawnHandler: (FnOnce() -> SpawnHandlerResult) + Send + 'static,
    SpawnHandlerResult: Send + 'static,
{
    move |thread: ThreadBuilder| {
        let mut b = thread::Builder::new();
        if let Some(name) = thread.name() {
            b = b.name(name.to_owned());
        }
        if let Some(stack_size) = thread.stack_size() {
            b = b.stack_size(stack_size);
        }

        b.spawn(spawn_handler_builder(thread))?;
        Ok(())
    }
}

/// This function is supposed to be used with [`rayon::ThreadPoolBuilder::spawn_handler()`] to
/// inherit current tokio runtime.
pub fn tokio_rayon_spawn_handler() -> impl FnMut(ThreadBuilder) -> io::Result<()> {
    let handle = Handle::current();

    rayon_custom_spawn_handler(move |thread| {
        let handle = handle.clone();

        move || {
            let _guard = handle.enter();

            task::block_in_place(|| thread.run())
        }
    })
}
