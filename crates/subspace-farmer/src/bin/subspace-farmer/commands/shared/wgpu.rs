//! Shared wgpu GPU plotting options and setup, used by both the `farm` and cluster-plotter commands.

use async_lock::{Mutex as AsyncMutex, Semaphore};
use clap::Parser;
use prometheus_client::registry::Registry;
use std::collections::BTreeSet;
use std::num::{NonZeroU8, NonZeroUsize};
use std::sync::Arc;
use subspace_data_retrieval::piece_getter::PieceGetter;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer::plotter::gpu::GpuPlotter;
use subspace_farmer::plotter::gpu::wgpu::WgpuRecordsEncoder;
use subspace_kzg::Kzg;
use subspace_proof_of_space_wgpu::{Device, DeviceType, WgpuDevice};
use tracing::{debug, info, warn};

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
    /// Set the exact GPUs to be used for plotting instead of using recommended GPUs (default
    /// behavior).
    ///
    /// By default, dGPUs are used if available, if not, then iGPUs are used, if neither dGPU nor
    /// iGPU is found, a virtual GPU will be used as the last resort.
    ///
    /// GPUs are comma-separated: `--wgpu-gpus 0,1,3`. To disable GPU plotting entirely, use
    /// `--cpu-only`.
    #[arg(long)]
    wgpu_gpus: Option<String>,
    /// Plot on the CPU only, skipping GPU plotting even when GPUs are available.
    #[arg(long)]
    cpu_only: bool,
}

/// Choose which enumerated GPU devices to plot on: an explicit `--wgpu-gpus` set is honored
/// verbatim, otherwise discrete GPUs are preferred, then integrated, then a virtual GPU as a last
/// resort, while unknown and CPU-emulated adapters are never auto-selected.
fn select_gpu_devices(
    device_types: &[DeviceType],
    explicit_gpus: Option<&BTreeSet<usize>>,
) -> Vec<usize> {
    if let Some(explicit_gpus) = explicit_gpus {
        return explicit_gpus
            .iter()
            .copied()
            .filter(|&index| index < device_types.len())
            .collect();
    }

    let has_dgpu = device_types.contains(&DeviceType::DiscreteGpu);
    let has_igpu = device_types.contains(&DeviceType::IntegratedGpu);

    device_types
        .iter()
        .enumerate()
        .filter_map(|(index, &device_type)| {
            let use_device = match device_type {
                DeviceType::DiscreteGpu => true,
                DeviceType::IntegratedGpu => !has_dgpu,
                DeviceType::VirtualGpu => !has_dgpu && !has_igpu,
                DeviceType::Other | DeviceType::Cpu => false,
            };
            use_device.then_some(index)
        })
        .collect()
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
    let WgpuPlottingOptions {
        wgpu_sector_downloading_concurrency,
        wgpu_gpus,
        cpu_only,
    } = wgpu_plotting_options;

    if cpu_only {
        info!("GPU plotting disabled, plotting on the CPU only");
        return Ok(None);
    }

    let number_of_queues = |device_type: DeviceType| match device_type {
        DeviceType::DiscreteGpu => NonZeroU8::new(4).expect("Not zero; qed"),
        DeviceType::Other
        | DeviceType::IntegratedGpu
        | DeviceType::VirtualGpu
        | DeviceType::Cpu => NonZeroU8::new(2).expect("Not zero; qed"),
    };
    let all_gpu_devices = Device::enumerate(number_of_queues).await;

    let device_types = all_gpu_devices
        .iter()
        .map(Device::device_type)
        .collect::<Vec<_>>();

    let explicit_gpus = match wgpu_gpus {
        Some(wgpu_gpus) if !wgpu_gpus.is_empty() => {
            let mut gpus_to_use = wgpu_gpus
                .split(',')
                .map(str::parse)
                .collect::<Result<BTreeSet<u32>, _>>()?;

            let explicit_gpus = all_gpu_devices
                .iter()
                .enumerate()
                .filter_map(|(index, device)| gpus_to_use.remove(&device.id()).then_some(index))
                .collect::<BTreeSet<usize>>();

            if !gpus_to_use.is_empty() {
                warn!(?gpus_to_use, "Some wgpu GPUs were not found on the system");
            }

            Some(explicit_gpus)
        }
        _ => None,
    };

    let used_indices = select_gpu_devices(&device_types, explicit_gpus.as_ref())
        .into_iter()
        .collect::<BTreeSet<usize>>();

    // Explain skipped devices when relying on automatic selection
    if explicit_gpus.is_none() {
        for (index, device) in all_gpu_devices.iter().enumerate() {
            if used_indices.contains(&index) {
                continue;
            }
            match device.device_type() {
                DeviceType::Other => debug!(?device, "Skipping an unknown GPU device type"),
                DeviceType::IntegratedGpu => debug!(?device, "Skipping iGPU in presence of dGPU"),
                DeviceType::VirtualGpu => {
                    debug!(
                        ?device,
                        "Skipping virtualized GPU in presence of iGPU or dGPU"
                    )
                }
                DeviceType::Cpu => debug!(?device, "Skipping GPU device emulated by the CPU"),
                DeviceType::DiscreteGpu => {}
            }
        }
    }

    let used_gpu_devices = all_gpu_devices
        .into_iter()
        .enumerate()
        .filter_map(|(index, device)| used_indices.contains(&index).then_some(device))
        .collect::<Vec<_>>();

    if used_gpu_devices.is_empty() {
        debug!("No GPU devices were found or used");
        return Ok(None);
    }

    info!("Using GPUs:");
    for device in &used_gpu_devices {
        let device_type = match device.device_type() {
            DeviceType::Other => "other",
            DeviceType::IntegratedGpu => "Integrated GPU",
            DeviceType::DiscreteGpu => "Discrete GPU",
            DeviceType::VirtualGpu => "Virtual GPU",
            DeviceType::Cpu => "CPU emulation",
        };
        info!("{}: {} ({device_type})", device.id(), device.name());
    }

    let wgpu_downloading_semaphore = Arc::new(Semaphore::new(
        wgpu_sector_downloading_concurrency
            .map(|wgpu_sector_downloading_concurrency| wgpu_sector_downloading_concurrency.get())
            .unwrap_or(used_gpu_devices.len() * 3),
    ));

    Ok(Some(
        GpuPlotter::new(
            piece_getter,
            wgpu_downloading_semaphore,
            used_gpu_devices
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_device_selection() {
        use DeviceType::{Cpu, DiscreteGpu, IntegratedGpu, Other, VirtualGpu};

        // dGPU wins over iGPU
        assert_eq!(
            select_gpu_devices(&[DiscreteGpu, IntegratedGpu], None),
            vec![0]
        );
        // All iGPUs are used when there is no dGPU
        assert_eq!(
            select_gpu_devices(&[IntegratedGpu, IntegratedGpu], None),
            vec![0, 1]
        );
        // CPU emulation is never auto-selected
        assert_eq!(select_gpu_devices(&[Cpu], None), Vec::<usize>::new());
        // All dGPUs are used, iGPU skipped
        assert_eq!(
            select_gpu_devices(&[DiscreteGpu, DiscreteGpu, IntegratedGpu], None),
            vec![0, 1]
        );
        // Virtual GPU skipped while an iGPU is present
        assert_eq!(
            select_gpu_devices(&[IntegratedGpu, VirtualGpu], None),
            vec![0]
        );
        // Virtual GPU used as the last resort
        assert_eq!(select_gpu_devices(&[VirtualGpu], None), vec![0]);
        // Virtual GPU still wins over unknown/CPU adapters as the last resort
        assert_eq!(select_gpu_devices(&[Cpu, Other, VirtualGpu], None), vec![2]);
        // Unknown and CPU adapters alone select nothing
        assert_eq!(select_gpu_devices(&[Cpu, Other], None), Vec::<usize>::new());
        // Explicit override bypasses the tiering
        let explicit = BTreeSet::from([0, 2]);
        assert_eq!(
            select_gpu_devices(&[Cpu, DiscreteGpu, IntegratedGpu], Some(&explicit)),
            vec![0, 2]
        );
    }
}
