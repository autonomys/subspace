use crate::commands::shared::PlottingThreadPriority;
use anyhow::anyhow;
use clap::Parser;
use prometheus_client::registry::Registry;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::Record;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::cluster::controller::ClusterPieceGetter;
use subspace_farmer::cluster::nats_client::NatsClient;
use subspace_farmer::cluster::plotter::plotter_service;
use subspace_farmer::plotter::cpu::CpuPlotter;
use subspace_farmer::utils::{
    create_plotting_thread_pool_manager, parse_cpu_cores_sets, thread_pool_core_indices,
};
use subspace_proof_of_space::Table;
use tokio::sync::Semaphore;
use tracing::info;

/// Arguments for plotter
#[derive(Debug, Parser)]
pub(super) struct PlotterArgs {
    /// Piece getter concurrency.
    ///
    /// Increase can result in NATS communication issues if too many messages arrive via NATS, but
    /// are not processed quickly enough for some reason and might require increasing cluster-level
    /// `--nats-pool-size` parameter.
    #[arg(long, default_value = "32")]
    piece_getter_concurrency: NonZeroUsize,
    /// Defines how many sectors farmer will download concurrently, allows to limit memory usage of
    /// the plotting process, defaults to `--sector-encoding-concurrency` + 1 to download future
    /// sector ahead of time.
    ///
    /// Increase will result in higher memory usage.
    #[arg(long)]
    sector_downloading_concurrency: Option<NonZeroUsize>,
    /// Defines how many sectors farmer will encode concurrently, defaults to 1 on UMA system and
    /// number of NUMA nodes on NUMA system or L3 cache groups on large CPUs. It is further
    /// restricted by
    /// `--sector-downloading-concurrency` and setting this option higher than
    /// `--sector-downloading-concurrency` will have no effect.
    ///
    /// Increase will result in higher memory usage.
    #[arg(long)]
    sector_encoding_concurrency: Option<NonZeroUsize>,
    /// Defines how many records farmer will encode in a single sector concurrently, defaults to one
    /// record per 2 cores, but not more than 8 in total. Higher concurrency means higher memory
    /// usage and typically more efficient CPU utilization.
    #[arg(long)]
    record_encoding_concurrency: Option<NonZeroUsize>,
    /// Size of one thread pool used for plotting, defaults to number of logical CPUs available
    /// on UMA system and number of logical CPUs available in NUMA node on NUMA system or L3 cache
    /// groups on large CPUs.
    ///
    /// Number of thread pools is defined by `--sector-encoding-concurrency` option, different
    /// thread pools might have different number of threads if NUMA nodes do not have the same size.
    ///
    /// Threads will be pinned to corresponding CPU cores at creation.
    #[arg(long)]
    plotting_thread_pool_size: Option<NonZeroUsize>,
    /// Specify exact CPU cores to be used for plotting bypassing any custom logic farmer might use
    /// otherwise. It replaces both `--sector-encoding-concurrency` and
    /// `--plotting-thread-pool-size` options if specified.
    ///
    /// Cores are coma-separated, with whitespace separating different thread pools/encoding
    /// instances. For example "0,1 2,3" will result in two sectors being encoded at the same time,
    /// each with a pair of CPU cores.
    #[arg(long, conflicts_with_all = & ["sector_encoding_concurrency", "plotting_thread_pool_size"])]
    plotting_cpu_cores: Option<String>,
    /// Plotting thread priority, by default de-prioritizes plotting threads in order to make sure
    /// farming is successful and computer can be used comfortably for other things. Can be set to
    /// "min", "max" or "default".
    #[arg(long, default_value_t = PlottingThreadPriority::Min)]
    plotting_thread_priority: PlottingThreadPriority,
    /// Additional cluster components
    #[clap(raw = true)]
    pub(super) additional_components: Vec<String>,
}

pub(super) async fn plotter<PosTable>(
    nats_client: NatsClient,
    _registry: &mut Registry,
    plotter_args: PlotterArgs,
) -> anyhow::Result<Pin<Box<dyn Future<Output = anyhow::Result<()>>>>>
where
    PosTable: Table,
{
    let PlotterArgs {
        piece_getter_concurrency,
        sector_downloading_concurrency,
        sector_encoding_concurrency,
        record_encoding_concurrency,
        plotting_thread_pool_size,
        plotting_cpu_cores,
        plotting_thread_priority,
        additional_components: _,
    } = plotter_args;

    let kzg = Kzg::new(embedded_kzg_settings());
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .map_err(|error| anyhow!("Failed to instantiate erasure coding: {error}"))?;
    let piece_getter = ClusterPieceGetter::new(nats_client.clone(), piece_getter_concurrency);

    let plotting_thread_pool_core_indices;
    if let Some(plotting_cpu_cores) = plotting_cpu_cores {
        plotting_thread_pool_core_indices = parse_cpu_cores_sets(&plotting_cpu_cores)
            .map_err(|error| anyhow!("Failed to parse `--plotting-cpu-cores`: {error}"))?;
    } else {
        plotting_thread_pool_core_indices =
            thread_pool_core_indices(plotting_thread_pool_size, sector_encoding_concurrency);

        if plotting_thread_pool_core_indices.len() > 1 {
            info!(
                l3_cache_groups = %plotting_thread_pool_core_indices.len(),
                "Multiple L3 cache groups detected"
            );
        }
    }

    let downloading_semaphore = Arc::new(Semaphore::new(
        sector_downloading_concurrency
            .map(|sector_downloading_concurrency| sector_downloading_concurrency.get())
            .unwrap_or(plotting_thread_pool_core_indices.len() + 1),
    ));

    let record_encoding_concurrency = record_encoding_concurrency.unwrap_or_else(|| {
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
        plotting_thread_priority.into(),
    )
    .map_err(|error| anyhow!("Failed to create thread pool manager: {error}"))?;
    let global_mutex = Arc::default();
    let cpu_plotter = Arc::new(CpuPlotter::<_, PosTable>::new(
        piece_getter,
        downloading_semaphore,
        plotting_thread_pool_manager,
        record_encoding_concurrency,
        Arc::clone(&global_mutex),
        kzg.clone(),
        erasure_coding.clone(),
    ));

    // TODO: Metrics

    Ok(Box::pin(async move {
        plotter_service(&nats_client, &cpu_plotter)
            .await
            .map_err(|error| anyhow!("Plotter service failed: {error}"))
    }))
}
