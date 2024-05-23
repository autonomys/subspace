pub mod farmer_piece_getter;
pub mod piece_validator;
pub mod plotted_pieces;
pub mod ss58;
#[cfg(test)]
mod tests;

use crate::thread_pool_manager::{PlottingThreadPoolManager, PlottingThreadPoolPair};
use futures::channel::oneshot;
use futures::channel::oneshot::Canceled;
use futures::future::Either;
use rayon::{ThreadBuilder, ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};
use std::future::Future;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::pin::{pin, Pin};
use std::task::{Context, Poll};
use std::{fmt, io, iter, thread};
use thread_priority::{set_current_thread_priority, ThreadPriority};
use tokio::runtime::Handle;
use tokio::task;
use tracing::{debug, warn};

/// It doesn't make a lot of sense to have a huge number of farming threads, 32 is plenty
const MAX_DEFAULT_FARMING_THREADS: usize = 32;

/// Joins async join handle on drop
#[derive(Debug)]
pub struct AsyncJoinOnDrop<T> {
    handle: Option<task::JoinHandle<T>>,
    abort_on_drop: bool,
}

impl<T> Drop for AsyncJoinOnDrop<T> {
    #[inline]
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
    #[inline]
    pub fn new(handle: task::JoinHandle<T>, abort_on_drop: bool) -> Self {
        Self {
            handle: Some(handle),
            abort_on_drop,
        }
    }
}

impl<T> Future for AsyncJoinOnDrop<T> {
    type Output = Result<T, task::JoinError>;

    #[inline]
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
    #[inline]
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
    #[inline]
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
#[derive(Clone)]
pub struct CpuCoreSet {
    /// CPU cores that belong to this set
    cores: Vec<usize>,
    #[cfg(feature = "numa")]
    topology: Option<std::sync::Arc<hwlocality::Topology>>,
}

impl fmt::Debug for CpuCoreSet {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = f.debug_struct("CpuCoreSet");
        #[cfg(not(feature = "numa"))]
        if self.cores.array_windows::<2>().all(|&[a, b]| a + 1 == b) {
            s.field(
                "cores",
                &format!(
                    "{}-{}",
                    self.cores.first().expect("List of cores is not empty; qed"),
                    self.cores.last().expect("List of cores is not empty; qed")
                ),
            );
        } else {
            s.field(
                "cores",
                &self
                    .cores
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        #[cfg(feature = "numa")]
        {
            use hwlocality::cpu::cpuset::CpuSet;
            use hwlocality::ffi::PositiveInt;

            s.field(
                "cores",
                &CpuSet::from_iter(
                    self.cores.iter().map(|&core| {
                        PositiveInt::try_from(core).expect("Valid CPU core index; qed")
                    }),
                ),
            );
        }
        s.finish_non_exhaustive()
    }
}

impl CpuCoreSet {
    /// Regroup CPU core sets to contain at most `target_sets` sets, useful when there are many L3
    /// cache groups and not as many farms
    pub fn regroup(cpu_core_sets: &[Self], target_sets: usize) -> Vec<Self> {
        cpu_core_sets
            // Chunk CPU core sets
            .chunks(cpu_core_sets.len().div_ceil(target_sets))
            .map(|sets| Self {
                // Combine CPU cores
                cores: sets
                    .iter()
                    .flat_map(|set| set.cores.iter())
                    .copied()
                    .collect(),
                // Preserve topology object
                #[cfg(feature = "numa")]
                topology: sets[0].topology.clone(),
            })
            .collect()
    }

    /// Get cpu core numbers in this set
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
            use hwlocality::current_thread_id;
            use hwlocality::ffi::PositiveInt;

            // load the cpuset for the given core index.
            let cpu_cores = CpuSet::from_iter(
                self.cores
                    .iter()
                    .map(|&core| PositiveInt::try_from(core).expect("Valid CPU core index; qed")),
            );

            if let Err(error) =
                topology.bind_thread_cpu(current_thread_id(), &cpu_cores, CpuBindingFlags::empty())
            {
                warn!(%error, ?cpu_cores, "Failed to pin thread to CPU cores")
            }
        }
    }
}

/// Recommended number of thread pool size for farming, equal to number of CPU cores in the first
/// NUMA node
pub fn recommended_number_of_farming_threads() -> usize {
    #[cfg(feature = "numa")]
    match hwlocality::Topology::new().map(std::sync::Arc::new) {
        Ok(topology) => {
            return topology
                // Iterate over NUMA nodes
                .objects_at_depth(hwlocality::object::depth::Depth::NUMANode)
                // For each NUMA nodes get CPU set
                .filter_map(|node| node.cpuset())
                // Get number of CPU cores
                .map(|cpuset| cpuset.iter_set().count())
                .find(|&count| count > 0)
                .unwrap_or_else(num_cpus::get)
                .min(MAX_DEFAULT_FARMING_THREADS);
        }
        Err(error) => {
            warn!(%error, "Failed to get NUMA topology");
        }
    }
    num_cpus::get().min(MAX_DEFAULT_FARMING_THREADS)
}

/// Get all cpu cores, grouped into sets according to NUMA nodes or L3 cache groups on large CPUs.
///
/// Returned vector is guaranteed to have at least one element and have non-zero number of CPU cores
/// in each set.
pub fn all_cpu_cores() -> Vec<CpuCoreSet> {
    #[cfg(feature = "numa")]
    match hwlocality::Topology::new().map(std::sync::Arc::new) {
        Ok(topology) => {
            let cpu_cores = topology
                // Iterate over groups of L3 caches
                .objects_with_type(hwlocality::object::types::ObjectType::L3Cache)
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
            warn!(%error, "Failed to get L3 cache topology");
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
pub fn parse_cpu_cores_sets(
    s: &str,
) -> Result<Vec<CpuCoreSet>, Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(feature = "numa")]
    let topology = hwlocality::Topology::new().map(std::sync::Arc::new).ok();

    s.split(' ')
        .map(|s| {
            let mut cores = Vec::new();
            for s in s.split(',') {
                let mut parts = s.split('-');
                let range_start = parts
                    .next()
                    .ok_or(
                        "Bad string format, must be comma separated list of CPU cores or ranges",
                    )?
                    .parse()?;

                if let Some(range_end) = parts.next() {
                    let range_end = range_end.parse()?;

                    cores.extend(range_start..=range_end);
                } else {
                    cores.push(range_start);
                }
            }

            Ok(CpuCoreSet {
                cores,
                #[cfg(feature = "numa")]
                topology: topology.clone(),
            })
        })
        .collect()
}

/// Thread indices for each thread pool
pub fn thread_pool_core_indices(
    thread_pool_size: Option<NonZeroUsize>,
    thread_pools: Option<NonZeroUsize>,
) -> Vec<CpuCoreSet> {
    thread_pool_core_indices_internal(all_cpu_cores(), thread_pool_size, thread_pools)
}

fn thread_pool_core_indices_internal(
    all_cpu_cores: Vec<CpuCoreSet>,
    thread_pool_size: Option<NonZeroUsize>,
    thread_pools: Option<NonZeroUsize>,
) -> Vec<CpuCoreSet> {
    #[cfg(feature = "numa")]
    let topology = &all_cpu_cores
        .first()
        .expect("Not empty according to function description; qed")
        .topology;

    // In case number of thread pools is not specified, but user did customize thread pool size,
    // default to auto-detected number of thread pools
    let thread_pools = thread_pools
        .map(|thread_pools| thread_pools.get())
        .or_else(|| thread_pool_size.map(|_| all_cpu_cores.len()));

    if let Some(thread_pools) = thread_pools {
        let mut thread_pool_core_indices = Vec::<CpuCoreSet>::with_capacity(thread_pools);

        let total_cpu_cores = all_cpu_cores.iter().flat_map(|set| set.cpu_cores()).count();

        if let Some(thread_pool_size) = thread_pool_size {
            // If thread pool size is fixed, loop over all CPU cores as many times as necessary and
            // assign contiguous ranges of CPU cores to corresponding thread pools
            let mut cpu_cores_iterator = iter::repeat(
                all_cpu_cores
                    .iter()
                    .flat_map(|cpu_core_set| cpu_core_set.cores.iter())
                    .copied(),
            )
            .flatten();

            for _ in 0..thread_pools {
                let cpu_cores = cpu_cores_iterator
                    .by_ref()
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

            let all_cpu_cores = all_cpu_cores
                .iter()
                .flat_map(|cpu_core_set| cpu_core_set.cores.iter())
                .copied()
                .collect::<Vec<_>>();

            thread_pool_core_indices = all_cpu_cores
                .chunks(total_cpu_cores.div_ceil(thread_pools))
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
        all_cpu_cores
    }
}

fn create_plotting_thread_pool_manager_thread_pool_pair(
    thread_prefix: &'static str,
    thread_pool_index: usize,
    cpu_core_set: CpuCoreSet,
    thread_priority: Option<ThreadPriority>,
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
                    if let Some(thread_priority) = thread_priority {
                        if let Err(error) = set_current_thread_priority(thread_priority) {
                            warn!(%error, "Failed to set thread priority");
                        }
                    }
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
    thread_priority: Option<ThreadPriority>,
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
                    thread_priority,
                )?,
                replotting: create_plotting_thread_pool_manager_thread_pool_pair(
                    "replotting",
                    thread_pool_index,
                    replotting_cpu_core_set,
                    thread_priority,
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
