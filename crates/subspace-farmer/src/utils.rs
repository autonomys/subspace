//! Various utilities used by farmer or with farmer

pub mod ss58;
#[cfg(test)]
mod tests;

use crate::thread_pool_manager::{PlottingThreadPoolManager, PlottingThreadPoolPair};
use rayon::{
    ThreadBuilder, ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder, current_thread_index,
};
use std::num::NonZeroUsize;
use std::process::exit;
use std::{fmt, io, iter, thread};
use thread_priority::{ThreadPriority, set_current_thread_priority};
use tokio::runtime::Handle;
use tokio::task;
use tracing::warn;

/// It doesn't make a lot of sense to have a huge number of farming threads, 32 is plenty
const MAX_DEFAULT_FARMING_THREADS: usize = 32;

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    /// Get cpu core numbers in this set
    pub fn cpu_cores(&self) -> &[usize] {
        &self.cores
    }

    /// Will truncate list of CPU cores to this number.
    ///
    /// Truncation will take into account L2 and L3 cache topology in order to use half of the
    /// actual physical cores and half of each core type in case of heterogeneous CPUs.
    ///
    /// If `cores` is zero, call will do nothing since zero number of cores is not allowed.
    pub fn truncate(&mut self, num_cores: usize) {
        let num_cores = num_cores.clamp(1, self.cores.len());

        #[cfg(feature = "numa")]
        if let Some(topology) = &self.topology {
            use hwlocality::object::attributes::ObjectAttributes;
            use hwlocality::object::types::ObjectType;

            let mut grouped_by_l2_cache_size_and_core_count =
                std::collections::HashMap::<(usize, usize), Vec<usize>>::new();
            topology
                .objects_with_type(ObjectType::L2Cache)
                .for_each(|object| {
                    let l2_cache_size =
                        if let Some(ObjectAttributes::Cache(cache)) = object.attributes() {
                            cache
                                .size()
                                .map(|size| size.get() as usize)
                                .unwrap_or_default()
                        } else {
                            0
                        };
                    if let Some(cpuset) = object.complete_cpuset() {
                        let cpuset = cpuset
                            .into_iter()
                            .map(usize::from)
                            .filter(|core| self.cores.contains(core))
                            .collect::<Vec<_>>();
                        let cpuset_len = cpuset.len();

                        if !cpuset.is_empty() {
                            grouped_by_l2_cache_size_and_core_count
                                .entry((l2_cache_size, cpuset_len))
                                .or_default()
                                .extend(cpuset);
                        }
                    }
                });

            // Make sure all CPU cores in this set were found
            if grouped_by_l2_cache_size_and_core_count
                .values()
                .flatten()
                .count()
                == self.cores.len()
            {
                // Walk through groups of cores for each (L2 cache size + number of cores in set)
                // tuple and pull number of CPU cores proportional to the fraction of the cores that
                // should be returned according to function argument
                self.cores = grouped_by_l2_cache_size_and_core_count
                    .into_values()
                    .flat_map(|cores| {
                        let limit = cores.len() * num_cores / self.cores.len();
                        // At least 1 CPU core is needed
                        cores.into_iter().take(limit.max(1))
                    })
                    .collect();

                self.cores.sort();

                return;
            }
        }
        self.cores.truncate(num_cores);
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
    // On Linux, thread names are limited to 15 characters.
    let thread_name =
        move |thread_index| format!("{thread_prefix:9}-{thread_pool_index:02}.{thread_index:02}");
    // TODO: remove this panic handler when rayon logs panic_info
    // https://github.com/rayon-rs/rayon/issues/1208
    // (we'll lose the thread name, because it's not stored within rayon's WorkerThread)
    let panic_handler = move |panic_info| {
        if let Some(index) = current_thread_index() {
            eprintln!("panic on thread {}: {:?}", thread_name(index), panic_info);
        } else {
            // We want to guarantee exit, rather than panicking in a panic handler.
            eprintln!("rayon panic handler called on non-rayon thread: {panic_info:?}");
        }
        exit(1);
    };

    ThreadPoolBuilder::new()
        .thread_name(thread_name)
        .num_threads(cpu_core_set.cpu_cores().len())
        .panic_handler(panic_handler)
        .spawn_handler({
            let handle = Handle::current();

            rayon_custom_spawn_handler(move |thread| {
                let cpu_core_set = cpu_core_set.clone();
                let handle = handle.clone();

                move || {
                    cpu_core_set.pin_current_thread();
                    if let Some(thread_priority) = thread_priority
                        && let Err(error) = set_current_thread_priority(thread_priority)
                    {
                        warn!(%error, "Failed to set thread priority");
                    }
                    drop(cpu_core_set);

                    let _guard = handle.enter();

                    task::block_in_place(|| thread.run())
                }
            })
        })
        .build()
}

/// Create thread pools manager.
///
/// Creates thread pool pairs for each of CPU core set pair with number of plotting and replotting
/// threads corresponding to number of cores in each set and pins threads to all of those CPU cores
/// (each thread to all cors in a set, not thread per core). Each thread will also have Tokio
/// context available.
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
