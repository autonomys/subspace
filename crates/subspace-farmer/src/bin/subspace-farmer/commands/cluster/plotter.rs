use crate::commands::shared::PlottingThreadPriority;
use anyhow::anyhow;
use async_lock::Mutex as AsyncMutex;
use clap::Parser;
use prometheus_client::registry::Registry;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::pieces::Record;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::cluster::controller::ClusterPieceGetter;
use subspace_farmer::cluster::nats_client::NatsClient;
use subspace_farmer::cluster::plotter::plotter_service;
use subspace_farmer::plotter::cpu::CpuPlotter;
#[cfg(feature = "cuda")]
use subspace_farmer::plotter::gpu::cuda::CudaRecordsEncoder;
#[cfg(feature = "rocm")]
use subspace_farmer::plotter::gpu::rocm::RocmRecordsEncoder;
#[cfg(feature = "_gpu")]
use subspace_farmer::plotter::gpu::GpuPlotter;
use subspace_farmer::plotter::pool::PoolPlotter;
use subspace_farmer::plotter::Plotter;
use subspace_farmer::utils::{
    create_plotting_thread_pool_manager, parse_cpu_cores_sets, thread_pool_core_indices,
};
use subspace_farmer_components::PieceGetter;
use subspace_kzg::Kzg;
use subspace_proof_of_space::Table;
use tokio::sync::Semaphore;
use tracing::info;

const PLOTTING_RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
struct CpuPlottingOptions {
    /// How many sectors the farmer will download concurrently. Limits the memory usage of
    /// the plotting process. Defaults to `--cpu-sector-encoding-concurrency` + 1 to download future
    /// sector ahead of time.
    ///
    /// Increasing this value will cause higher memory usage.
    #[arg(long)]
    cpu_sector_downloading_concurrency: Option<NonZeroUsize>,
    /// How many sectors the farmer will encode concurrently. Defaults to 1 on UMA system and the
    /// number of NUMA nodes on NUMA system or L3 cache groups on large CPUs. It is further
    /// restricted by
    /// `--cpu-sector-downloading-concurrency` and setting this option higher than
    /// `--cpu-sector-downloading-concurrency` will have no effect.
    ///
    /// CPU plotting is disabled by default if GPU plotting is detected.
    ///
    /// Increasing this value will cause higher memory usage. Set to 0 to disable CPU plotting.
    #[arg(long)]
    cpu_sector_encoding_concurrency: Option<usize>,
    /// How many records the farmer will encode in a single sector concurrently. Defaults to one
    /// record per 2 cores, but not more than 8 in total. Higher concurrency means higher memory
    /// usage, and typically more efficient CPU utilization.
    #[arg(long)]
    cpu_record_encoding_concurrency: Option<NonZeroUsize>,
    /// Size of one thread pool used for plotting. Defaults to number of logical CPUs available
    /// on UMA system and number of logical CPUs available in NUMA node on NUMA system or L3 cache
    /// groups on large CPUs.
    ///
    /// The number of thread pools is defined by `--cpu-sector-encoding-concurrency` option. Different
    /// thread pools might have different numbers of threads if NUMA nodes do not have the same size.
    ///
    /// Threads will be pinned to corresponding CPU cores at creation.
    #[arg(long)]
    cpu_plotting_thread_pool_size: Option<NonZeroUsize>,
    /// Set the exact CPU cores to be used for plotting, bypassing any custom logic in the farmer.
    /// Replaces both `--cpu-sector-encoding-concurrency` and
    /// `--cpu-plotting-thread-pool-size` options.
    ///
    /// Cores are coma-separated, with whitespace separating different thread pools/encoding
    /// instances. For example "0,1 2,3" will result in two sectors being encoded at the same time,
    /// each with a pair of CPU cores.
    #[arg(long, conflicts_with_all = & ["cpu_sector_encoding_concurrency", "cpu_plotting_thread_pool_size"])]
    cpu_plotting_cores: Option<String>,
    /// Plotting thread priority, by default de-prioritizes plotting threads in order to make sure
    /// farming is successful and computer can be used comfortably for other things. Can be set to
    /// "min", "max" or "default".
    #[arg(long, default_value_t = PlottingThreadPriority::Min)]
    cpu_plotting_thread_priority: PlottingThreadPriority,
}

#[cfg(feature = "cuda")]
#[derive(Debug, Parser)]
struct CudaPlottingOptions {
    /// How many sectors farmer will download concurrently during plotting with CUDA GPUs.
    /// Limits memory usage of the plotting process. Defaults to the number of CUDA GPUs + 1,
    /// to download future sectors ahead of time.
    ///
    /// Increasing this value will cause higher memory usage.
    #[arg(long)]
    cuda_sector_downloading_concurrency: Option<NonZeroUsize>,
    /// Set the exact GPUs to be used for plotting, instead of using all GPUs (default behavior).
    ///
    /// GPUs are coma-separated: `--cuda-gpus 0,1,3`. Use an empty string to disable CUDA
    /// GPUs.
    #[arg(long)]
    cuda_gpus: Option<String>,
}

#[cfg(feature = "rocm")]
#[derive(Debug, Parser)]
struct RocmPlottingOptions {
    /// How many sectors the farmer will download concurrently during plotting with ROCm GPUs.
    /// Limits memory usage of the plotting process. Defaults to number of ROCm GPUs + 1,
    /// to download future sectors ahead of time.
    ///
    /// Increasing this value will cause higher memory usage.
    #[arg(long)]
    rocm_sector_downloading_concurrency: Option<NonZeroUsize>,
    /// Set the exact GPUs to be used for plotting, instead of using all GPUs (default behavior).
    ///
    /// GPUs are coma-separated: `--rocm-gpus 0,1,3`. Use an empty string to disable ROCm
    /// GPUs.
    #[arg(long)]
    rocm_gpus: Option<String>,
}

/// Arguments for plotter
#[derive(Debug, Parser)]
pub(super) struct PlotterArgs {
    /// Plotting options only used by CPU plotter
    #[clap(flatten)]
    cpu_plotting_options: CpuPlottingOptions,
    /// Plotting options only used by CUDA GPU plotter
    #[cfg(feature = "cuda")]
    #[clap(flatten)]
    cuda_plotting_options: CudaPlottingOptions,
    /// Plotting options only used by ROCm GPU plotter
    #[cfg(feature = "rocm")]
    #[clap(flatten)]
    rocm_plotting_options: RocmPlottingOptions,
    /// Additional cluster components
    #[clap(raw = true)]
    pub(super) additional_components: Vec<String>,
}

pub(super) async fn plotter<PosTable>(
    nats_client: NatsClient,
    registry: &mut Registry,
    plotter_args: PlotterArgs,
) -> anyhow::Result<Pin<Box<dyn Future<Output = anyhow::Result<()>>>>>
where
    PosTable: Table,
{
    let PlotterArgs {
        cpu_plotting_options,
        #[cfg(feature = "cuda")]
        cuda_plotting_options,
        #[cfg(feature = "rocm")]
        rocm_plotting_options,
        additional_components: _,
    } = plotter_args;

    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .map_err(|error| anyhow!("Failed to instantiate erasure coding: {error}"))?;
    let piece_getter = ClusterPieceGetter::new(nats_client.clone());

    let global_mutex = Arc::default();

    let mut plotters = Vec::<Box<dyn Plotter + Send + Sync>>::new();

    #[cfg(feature = "cuda")]
    {
        let maybe_cuda_plotter = init_cuda_plotter(
            cuda_plotting_options,
            piece_getter.clone(),
            Arc::clone(&global_mutex),
            kzg.clone(),
            erasure_coding.clone(),
            registry,
        )?;

        if let Some(cuda_plotter) = maybe_cuda_plotter {
            plotters.push(Box::new(cuda_plotter));
        }
    }
    #[cfg(feature = "rocm")]
    {
        let maybe_rocm_plotter = init_rocm_plotter(
            rocm_plotting_options,
            piece_getter.clone(),
            Arc::clone(&global_mutex),
            kzg.clone(),
            erasure_coding.clone(),
            registry,
        )?;

        if let Some(rocm_plotter) = maybe_rocm_plotter {
            plotters.push(Box::new(rocm_plotter));
        }
    }
    {
        let cpu_sector_encoding_concurrency = cpu_plotting_options.cpu_sector_encoding_concurrency;
        let maybe_cpu_plotter = init_cpu_plotter::<_, PosTable>(
            cpu_plotting_options,
            piece_getter,
            global_mutex,
            kzg,
            erasure_coding,
            registry,
        )?;

        if let Some(cpu_plotter) = maybe_cpu_plotter {
            if !plotters.is_empty() && cpu_sector_encoding_concurrency.is_none() {
                info!("CPU plotting was disabled due to detected faster plotting with GPU");
            } else {
                plotters.push(Box::new(cpu_plotter));
            }
        }
    }
    let plotter = Arc::new(PoolPlotter::new(plotters, PLOTTING_RETRY_INTERVAL));

    Ok(Box::pin(async move {
        plotter_service(&nats_client, &plotter)
            .await
            .map_err(|error| anyhow!("Plotter service failed: {error}"))
    }))
}

#[allow(clippy::type_complexity)]
fn init_cpu_plotter<PG, PosTable>(
    cpu_plotting_options: CpuPlottingOptions,
    piece_getter: PG,
    global_mutex: Arc<AsyncMutex<()>>,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    registry: &mut Registry,
) -> anyhow::Result<Option<CpuPlotter<PG, PosTable>>>
where
    PG: PieceGetter + Clone + Send + Sync + 'static,
    PosTable: Table,
{
    let CpuPlottingOptions {
        cpu_sector_downloading_concurrency,
        cpu_sector_encoding_concurrency,
        cpu_record_encoding_concurrency,
        cpu_plotting_thread_pool_size,
        cpu_plotting_cores,
        cpu_plotting_thread_priority,
    } = cpu_plotting_options;

    let cpu_sector_encoding_concurrency =
        if let Some(cpu_sector_encoding_concurrency) = cpu_sector_encoding_concurrency {
            match NonZeroUsize::new(cpu_sector_encoding_concurrency) {
                Some(cpu_sector_encoding_concurrency) => Some(cpu_sector_encoding_concurrency),
                None => {
                    info!("CPU plotting was explicitly disabled");
                    return Ok(None);
                }
            }
        } else {
            None
        };

    let plotting_thread_pool_core_indices;
    if let Some(cpu_plotting_cores) = cpu_plotting_cores {
        plotting_thread_pool_core_indices = parse_cpu_cores_sets(&cpu_plotting_cores)
            .map_err(|error| anyhow!("Failed to parse `--cpu-plotting-cpu-cores`: {error}"))?;
    } else {
        plotting_thread_pool_core_indices = thread_pool_core_indices(
            cpu_plotting_thread_pool_size,
            cpu_sector_encoding_concurrency,
        );

        if plotting_thread_pool_core_indices.len() > 1 {
            info!(
                l3_cache_groups = %plotting_thread_pool_core_indices.len(),
                "Multiple L3 cache groups detected"
            );
        }
    }

    let downloading_semaphore = Arc::new(Semaphore::new(
        cpu_sector_downloading_concurrency
            .map(|cpu_sector_downloading_concurrency| cpu_sector_downloading_concurrency.get())
            .unwrap_or(plotting_thread_pool_core_indices.len() + 1),
    ));

    let cpu_record_encoding_concurrency = cpu_record_encoding_concurrency.unwrap_or_else(|| {
        let cpu_cores = plotting_thread_pool_core_indices
            .first()
            .expect("Guaranteed to have some CPU cores; qed");

        NonZeroUsize::new((cpu_cores.cpu_cores().len() / 2).clamp(1, 8)).expect("Not zero; qed")
    });

    info!(
        ?plotting_thread_pool_core_indices,
        "Preparing plotting thread pools"
    );

    let replotting_thread_pool_core_indices = plotting_thread_pool_core_indices
        .clone()
        .into_iter()
        .map(|mut cpu_core_set| {
            // We'll not use replotting threads at all, so just limit them to 1 core so we don't
            // have too many threads hanging unnecessarily
            cpu_core_set.truncate(1);
            cpu_core_set
        });
    let plotting_thread_pool_manager = create_plotting_thread_pool_manager(
        plotting_thread_pool_core_indices
            .into_iter()
            .zip(replotting_thread_pool_core_indices),
        cpu_plotting_thread_priority.into(),
    )
    .map_err(|error| anyhow!("Failed to create thread pool manager: {error}"))?;

    let cpu_plotter = CpuPlotter::<_, PosTable>::new(
        piece_getter,
        downloading_semaphore,
        plotting_thread_pool_manager,
        cpu_record_encoding_concurrency,
        global_mutex,
        kzg,
        erasure_coding,
        Some(registry),
    );

    Ok(Some(cpu_plotter))
}

#[cfg(feature = "cuda")]
fn init_cuda_plotter<PG>(
    cuda_plotting_options: CudaPlottingOptions,
    piece_getter: PG,
    global_mutex: Arc<AsyncMutex<()>>,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    registry: &mut Registry,
) -> anyhow::Result<Option<GpuPlotter<PG, CudaRecordsEncoder>>>
where
    PG: PieceGetter + Clone + Send + Sync + 'static,
{
    use std::collections::BTreeSet;
    use subspace_proof_of_space_gpu::cuda::cuda_devices;
    use tracing::{debug, warn};

    let CudaPlottingOptions {
        cuda_sector_downloading_concurrency,
        cuda_gpus,
    } = cuda_plotting_options;

    let mut cuda_devices = cuda_devices();
    let mut used_cuda_devices = (0..cuda_devices.len()).collect::<Vec<_>>();

    if let Some(cuda_gpus) = cuda_gpus {
        if cuda_gpus.is_empty() {
            info!("CUDA GPU plotting was explicitly disabled");
            return Ok(None);
        }

        let mut cuda_gpus_to_use = cuda_gpus
            .split(',')
            .map(|gpu_index| gpu_index.parse())
            .collect::<Result<BTreeSet<usize>, _>>()?;

        (used_cuda_devices, cuda_devices) = cuda_devices
            .into_iter()
            .enumerate()
            .filter(|(index, _cuda_device)| cuda_gpus_to_use.remove(index))
            .unzip();

        if !cuda_gpus_to_use.is_empty() {
            warn!(
                ?cuda_gpus_to_use,
                "Some CUDA GPUs were not found on the system"
            );
        }
    }

    if cuda_devices.is_empty() {
        debug!("No CUDA GPU devices found");
        return Ok(None);
    }

    info!(?used_cuda_devices, "Using CUDA GPUs");

    let cuda_downloading_semaphore = Arc::new(Semaphore::new(
        cuda_sector_downloading_concurrency
            .map(|cuda_sector_downloading_concurrency| cuda_sector_downloading_concurrency.get())
            .unwrap_or(cuda_devices.len() + 1),
    ));

    Ok(Some(
        GpuPlotter::new(
            piece_getter,
            cuda_downloading_semaphore,
            cuda_devices
                .into_iter()
                .map(|cuda_device| CudaRecordsEncoder::new(cuda_device, Arc::clone(&global_mutex)))
                .collect::<Result<_, _>>()
                .map_err(|error| {
                    anyhow::anyhow!("Failed to create CUDA records encoder: {error}")
                })?,
            global_mutex,
            kzg,
            erasure_coding,
            Some(registry),
        )
        .map_err(|error| anyhow::anyhow!("Failed to initialize CUDA plotter: {error}"))?,
    ))
}

#[cfg(feature = "rocm")]
fn init_rocm_plotter<PG>(
    rocm_plotting_options: RocmPlottingOptions,
    piece_getter: PG,
    global_mutex: Arc<AsyncMutex<()>>,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    registry: &mut Registry,
) -> anyhow::Result<Option<GpuPlotter<PG, RocmRecordsEncoder>>>
where
    PG: PieceGetter + Clone + Send + Sync + 'static,
{
    use std::collections::BTreeSet;
    use subspace_proof_of_space_gpu::rocm::rocm_devices;
    use tracing::{debug, warn};

    let RocmPlottingOptions {
        rocm_sector_downloading_concurrency,
        rocm_gpus,
    } = rocm_plotting_options;

    let mut rocm_devices = rocm_devices();
    let mut used_rocm_devices = (0..rocm_devices.len()).collect::<Vec<_>>();

    if let Some(rocm_gpus) = rocm_gpus {
        if rocm_gpus.is_empty() {
            info!("ROCm GPU plotting was explicitly disabled");
            return Ok(None);
        }

        let mut rocm_gpus_to_use = rocm_gpus
            .split(',')
            .map(|gpu_index| gpu_index.parse())
            .collect::<Result<BTreeSet<usize>, _>>()?;

        (used_rocm_devices, rocm_devices) = rocm_devices
            .into_iter()
            .enumerate()
            .filter(|(index, _rocm_device)| rocm_gpus_to_use.remove(index))
            .unzip();

        if !rocm_gpus_to_use.is_empty() {
            warn!(
                ?rocm_gpus_to_use,
                "Some ROCm GPUs were not found on the system"
            );
        }
    }

    if rocm_devices.is_empty() {
        debug!("No ROCm GPU devices found");
        return Ok(None);
    }

    info!(?used_rocm_devices, "Using ROCm GPUs");

    let rocm_downloading_semaphore = Arc::new(Semaphore::new(
        rocm_sector_downloading_concurrency
            .map(|rocm_sector_downloading_concurrency| rocm_sector_downloading_concurrency.get())
            .unwrap_or(rocm_devices.len() + 1),
    ));

    Ok(Some(
        GpuPlotter::new(
            piece_getter,
            rocm_downloading_semaphore,
            rocm_devices
                .into_iter()
                .map(|rocm_device| RocmRecordsEncoder::new(rocm_device, Arc::clone(&global_mutex)))
                .collect::<Result<_, _>>()
                .map_err(|error| {
                    anyhow::anyhow!("Failed to create ROCm records encoder: {error}")
                })?,
            global_mutex,
            kzg,
            erasure_coding,
            Some(registry),
        )
        .map_err(|error| anyhow::anyhow!("Failed to initialize ROCm plotter: {error}"))?,
    ))
}
