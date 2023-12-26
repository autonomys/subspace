pub mod farmer_piece_getter;
pub mod piece_validator;
pub mod readers_and_pieces;
pub mod ss58;
#[cfg(test)]
mod tests;

use crate::thread_pool_manager::ThreadPoolManager;
use futures::channel::oneshot;
use futures::channel::oneshot::Canceled;
use futures::future::Either;
use rayon::{ThreadBuilder, ThreadPoolBuildError, ThreadPoolBuilder};
use std::future::Future;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::pin::{pin, Pin};
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

/// All CPU cores as numbers, grouped by NUMA nodes.
///
/// Returned vector is guaranteed to have at least one non-empty element.
pub fn all_cpus() -> Vec<Vec<usize>> {
    #[cfg(feature = "numa")]
    match hwlocality::Topology::new() {
        Ok(topology) => {
            let cpus = topology
                // Iterate over NUMA nodes
                .objects_at_depth(hwlocality::object::depth::Depth::NUMANode)
                // For each NUMA nodes get CPU set
                .filter_map(|node| node.cpuset())
                // For each CPU set extract individual cores
                .map(|cpuset| cpuset.iter_set().map(usize::from).collect::<Vec<_>>())
                .filter(|cores| !cores.is_empty())
                .collect::<Vec<_>>();

            if !cpus.is_empty() {
                return cpus;
            } else {
                warn!("No CPU cores found in NUMA nodes");
            }
        }
        Err(error) => {
            warn!(%error, "Failed to get CPU topology");
        }
    }
    vec![(0..num_cpus::get()).collect()]
}

/// Thread indices for each thread pool
pub fn thread_pool_core_indices(
    thread_pool_size: Option<NonZeroUsize>,
    thread_pools: Option<NonZeroUsize>,
) -> Vec<Vec<usize>> {
    let all_cpus = all_cpus();

    if let Some(thread_pools) = thread_pools {
        let mut thread_pool_core_indices = Vec::<Vec<usize>>::with_capacity(thread_pools.get());

        if let Some(thread_pool_size) = thread_pool_size {
            // If thread pool size is fixed, loop over all CPU cores as many times as necessary and
            // assign contiguous ranges of CPU cores to corresponding thread pools

            let total_cpu_cores = all_cpus
                .into_iter()
                .flat_map(|cores| cores.into_iter())
                .count();
            for _ in 0..thread_pools.get() {
                let cpu_cores_range = if let Some(last_cpu_index) = thread_pool_core_indices
                    .last()
                    .and_then(|thread_indices| thread_indices.last())
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

                thread_pool_core_indices.push(cpu_cores);
            }
        } else {
            // If thread pool size is not fixed, we iterate over all NUMA nodes as many times as
            // necessary

            for thread_pool_index in 0..thread_pools.get() {
                thread_pool_core_indices.push(all_cpus[thread_pool_index % all_cpus.len()].clone());
            }
        }
        thread_pool_core_indices
    } else {
        // If everything is set to defaults, use physical layout of CPUs
        all_cpus
    }
}

#[inline(never)]
fn pin_to_cpu_core(
    thread_prefix: &'static str,
    thread_pool_index: usize,
    thread_index: usize,
    core: usize,
) {
    if !core_affinity::set_for_current(core_affinity::CoreId { id: core }) {
        warn!(
            %thread_prefix,
            %thread_pool_index,
            %thread_index,
            %core,
            "Failed to set core affinity, timekeeper will run on random \
            CPU core",
        );
    }
}

/// Creates thread pools for each of CPUs with number of threads corresponding to number of cores in
/// each CPU and pins threads to those CPU cores. Each thread will have Tokio context available.
///
/// The easiest way to obtain CPUs is using [`all_cpus`], but [`thread_pool_core_indices`] in case
/// support for user customizations is desired.
pub fn create_tokio_thread_pool_manager_for_pinned_cores(
    thread_prefix: &'static str,
    cpus: Vec<Vec<usize>>,
) -> Result<ThreadPoolManager, ThreadPoolBuildError> {
    let total_thread_pools = cpus.len();

    ThreadPoolManager::new(
        |thread_pool_index| {
            let cores = cpus[thread_pool_index].clone();

            ThreadPoolBuilder::new()
                .thread_name(move |thread_index| {
                    format!("{thread_prefix}-{thread_pool_index}.{thread_index}")
                })
                .num_threads(cores.len())
                .spawn_handler({
                    let handle = Handle::current();

                    rayon_custom_spawn_handler(move |thread| {
                        let core = cores[thread.index()];
                        let handle = handle.clone();

                        move || {
                            pin_to_cpu_core(thread_prefix, thread_pool_index, thread.index(), core);

                            let _guard = handle.enter();

                            task::block_in_place(|| thread.run())
                        }
                    })
                })
                .build()
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
