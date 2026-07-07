//! Shared wgpu GPU plotting options and setup, used by both the `farm` and cluster-plotter commands.

use async_lock::{Mutex as AsyncMutex, Semaphore};
use clap::Parser;
use prometheus_client::registry::Registry;
use std::num::NonZeroUsize;
use std::sync::Arc;
use subspace_data_retrieval::piece_getter::PieceGetter;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::plotter::gpu::GpuPlotter;
use subspace_farmer::plotter::gpu::wgpu::WgpuRecordsEncoder;
use subspace_kzg::Kzg;
use tracing::{info, warn};

/// Plotting options for the wgpu GPU plotter.
#[derive(Debug, Parser)]
pub(in super::super) struct WgpuPlottingOptions {
    /// How many sectors farmer will download concurrently during plotting with wgpu GPUs.
    /// Limits memory usage of the plotting process. Defaults to the number of wgpu GPUs * 3,
    /// to download future sectors ahead of time.
    ///
    /// Increasing this value will cause higher memory usage.
    #[arg(long)]
    wgpu_sector_downloading_concurrency: Option<NonZeroUsize>,
    /// Set the exact GPUs to be used for plotting instead of using all GPUs (default behavior).
    ///
    /// GPUs are coma-separated: `--wgpu-gpus 0,1,3`. Use an empty string to disable wgpu
    /// GPUs.
    #[arg(long)]
    wgpu_gpus: Option<String>,
    /// Plot on the CPU only, skipping GPU plotting even when GPUs are available.
    #[arg(long)]
    cpu_only: bool,
}

pub(in super::super) async fn init_wgpu_plotter<PG>(
    wgpu_plotting_options: WgpuPlottingOptions,
    piece_getter: PG,
    global_mutex: Arc<AsyncMutex<()>>,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    registry: &mut Registry,
) -> anyhow::Result<Option<GpuPlotter<PG, WgpuRecordsEncoder>>>
where
    PG: PieceGetter + Clone + Send + Sync + 'static,
{
    use std::collections::BTreeSet;
    use std::num::NonZeroU8;
    use subspace_proof_of_space_wgpu::{Device, DeviceType, WgpuDevice};
    use tracing::debug;

    let WgpuPlottingOptions {
        wgpu_sector_downloading_concurrency,
        wgpu_gpus,
        cpu_only,
    } = wgpu_plotting_options;

    if cpu_only {
        info!("GPU plotting disabled, plotting on the CPU only");
        return Ok(None);
    }

    // A couple of queues per device so downloads and encoding overlap on the GPU
    let number_of_queues = |_device_type: DeviceType| NonZeroU8::new(2).expect("Not zero; qed");
    let mut wgpu_devices = Device::enumerate(number_of_queues).await;
    let mut used_wgpu_devices = (0..wgpu_devices.len()).collect::<Vec<_>>();

    if let Some(wgpu_gpus) = wgpu_gpus {
        if wgpu_gpus.is_empty() {
            info!("wgpu GPU plotting was explicitly disabled");
            return Ok(None);
        }

        let mut wgpu_gpus_to_use = wgpu_gpus
            .split(',')
            .map(|gpu_index| gpu_index.parse())
            .collect::<Result<BTreeSet<usize>, _>>()?;

        (used_wgpu_devices, wgpu_devices) = wgpu_devices
            .into_iter()
            .enumerate()
            .filter(|(index, _wgpu_device)| wgpu_gpus_to_use.remove(index))
            .unzip();

        if !wgpu_gpus_to_use.is_empty() {
            warn!(
                ?wgpu_gpus_to_use,
                "Some wgpu GPUs were not found on the system"
            );
        }
    }

    if wgpu_devices.is_empty() {
        debug!("No wgpu GPU devices found");
        return Ok(None);
    }

    info!(?used_wgpu_devices, "Using wgpu GPUs");

    let wgpu_downloading_semaphore = Arc::new(Semaphore::new(
        wgpu_sector_downloading_concurrency
            .map(|wgpu_sector_downloading_concurrency| wgpu_sector_downloading_concurrency.get())
            .unwrap_or(wgpu_devices.len() * 3),
    ));

    Ok(Some(
        GpuPlotter::new(
            piece_getter,
            wgpu_downloading_semaphore,
            wgpu_devices
                .into_iter()
                .map(|wgpu_device| {
                    let id = wgpu_device.id();
                    let queue_devices = wgpu_device
                        .create_proofs_encoder_instances()
                        .into_iter()
                        .map(|instance| WgpuDevice::new(instance, erasure_coding.clone()))
                        .collect();
                    WgpuRecordsEncoder::new(id, queue_devices, Arc::clone(&global_mutex))
                })
                .collect::<Result<_, _>>()
                .map_err(|error| {
                    anyhow::anyhow!("Failed to create wgpu records encoder: {error}")
                })?,
            global_mutex,
            kzg,
            erasure_coding,
            Some(registry),
        )
        .map_err(|error| anyhow::anyhow!("Failed to initialize wgpu plotter: {error}"))?,
    ))
}
