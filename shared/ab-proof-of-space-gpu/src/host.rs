use crate::shader::constants::{
    MAX_BUCKET_SIZE, MAX_TABLE_SIZE, NUM_BUCKETS, NUM_MATCH_BUCKETS, NUM_S_BUCKETS,
    REDUCED_MATCHES_COUNT,
};
use crate::shader::find_matches_and_compute_f7::{NUM_ELEMENTS_PER_S_BUCKET, ProofTargets};
use crate::shader::find_proofs::ProofsHost;
use crate::shader::types::{Metadata, Position, PositionR};
use crate::shader::{compute_f1, find_proofs, select_shader_features_limits};
use ab_chacha8::{ChaCha8Block, ChaCha8State, block_to_bytes};
use futures::stream::FuturesOrdered;
use futures::{StreamExt, TryStreamExt};
use parking_lot::Mutex;
use rclite::Arc;
use std::num::NonZeroU8;
use std::{fmt, iter};
use subspace_core_primitives::pos::PosSeed;
use tracing::{debug, warn};
use wgpu::{
    AdapterInfo, Backend, BackendOptions, Backends, BindGroup, BindGroupDescriptor, BindGroupEntry,
    BindGroupLayoutDescriptor, BindGroupLayoutEntry, BindingType, Buffer, BufferAddress,
    BufferAsyncError, BufferBindingType, BufferDescriptor, BufferUsages, CommandEncoderDescriptor,
    ComputePassDescriptor, ComputePipeline, ComputePipelineDescriptor, DeviceDescriptor,
    DeviceType, Instance, InstanceDescriptor, InstanceFlags, MapMode, MemoryBudgetThresholds,
    PipelineCompilationOptions, PipelineLayoutDescriptor, PollError, PollType, Queue,
    RequestDeviceError, ShaderModule, ShaderRuntimeChecks, ShaderStages,
};

/// Proof creation error
#[derive(Debug, thiserror::Error)]
pub enum RecordEncodingError {
    /// Proof creation failed previously and the device is now considered broken
    #[error("Proof creation failed previously and the device is now considered broken")]
    DeviceBroken,
    /// Failed to map buffer
    #[error("Failed to map buffer: {0}")]
    BufferMapping(#[from] BufferAsyncError),
    /// Poll error
    #[error("Poll error: {0}")]
    DevicePoll(#[from] PollError),
}

/// Handle to GPU-produced proofs; keeps the underlying buffer mapped until dropped.
pub struct ProofsHostWrapper<'a> {
    proofs: &'a ProofsHost,
    proofs_host: &'a Buffer,
}

impl ProofsHostWrapper<'_> {
    /// Proofs produced for a single seed.
    pub fn proofs(&self) -> &ProofsHost {
        self.proofs
    }
}

impl fmt::Debug for ProofsHostWrapper<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProofsHostWrapper").finish_non_exhaustive()
    }
}

impl Drop for ProofsHostWrapper<'_> {
    fn drop(&mut self) {
        self.proofs_host.unmap();
    }
}

/// Wrapper data structure encapsulating a single compatible device
#[derive(Clone)]
pub struct Device {
    id: u32,
    devices: Vec<(wgpu::Device, Queue, ShaderModule)>,
    adapter_info: AdapterInfo,
}

impl fmt::Debug for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Device")
            .field("id", &self.id)
            .field("name", &self.adapter_info.name)
            .field("device_type", &self.adapter_info.device_type)
            .field("driver", &self.adapter_info.driver)
            .field("driver_info", &self.adapter_info.driver_info)
            .field("backend", &self.adapter_info.backend)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// Returns [`Device`] for each available device
    pub async fn enumerate<NOQ>(number_of_queues: NOQ) -> Vec<Self>
    where
        NOQ: Fn(DeviceType) -> NonZeroU8,
    {
        let backends = Backends::from_env().unwrap_or(Backends::METAL | Backends::VULKAN);
        let instance = Instance::new(InstanceDescriptor {
            backends,
            flags: if cfg!(debug_assertions) {
                InstanceFlags::debugging().with_env()
            } else {
                InstanceFlags::from_env_or_default()
            },
            memory_budget_thresholds: MemoryBudgetThresholds::default(),
            backend_options: BackendOptions::from_env_or_default(),
            display: None,
        });

        let adapters = instance.enumerate_adapters(backends).await;
        let number_of_queues = &number_of_queues;

        adapters
            .into_iter()
            .zip(0..)
            .map(|(adapter, id)| async move {
                let adapter_info = adapter.get_info();

                let (shader, required_features, required_limits) =
                    if let Some((shader, required_features, required_limits)) =
                        select_shader_features_limits(&adapter)
                    {
                        debug!(
                            %id,
                            adapter_info = ?adapter_info,
                            "Compatible adapter found"
                        );

                        (shader, required_features, required_limits)
                    } else {
                        debug!(
                            %id,
                            adapter_info = ?adapter_info,
                            "Incompatible adapter found"
                        );

                        return None;
                    };

                // TODO: creation of multiple devices is a workaround for lack of support for
                //  multiple queues: https://github.com/gfx-rs/wgpu/issues/1066
                let devices = iter::repeat_with(|| async {
                    let (device, queue) = adapter
                        .request_device(&DeviceDescriptor {
                            label: None,
                            required_features,
                            required_limits: required_limits.clone(),
                            ..DeviceDescriptor::default()
                        })
                        .await
                        .inspect_err(|error| {
                            warn!(%id, ?adapter_info, %error, "Failed to request the device");
                        })?;
                    let module = if cfg!(debug_assertions) {
                        device.create_shader_module(shader.clone())
                    } else {
                        // SAFETY: The shader is trusted, individual tests include correctness
                        // checks and debug builds of this crate too only release version skips
                        // checks for better runtime performance
                        unsafe {
                            device.create_shader_module_trusted(
                                shader.clone(),
                                ShaderRuntimeChecks::unchecked(),
                            )
                        }
                    };

                    Ok::<_, RequestDeviceError>((device, queue, module))
                })
                .take(usize::from(
                    number_of_queues(adapter_info.device_type).get(),
                ))
                .collect::<FuturesOrdered<_>>()
                .try_collect::<Vec<_>>()
                .await
                .ok()?;

                Some(Self {
                    id,
                    devices,
                    adapter_info,
                })
            })
            .collect::<FuturesOrdered<_>>()
            .filter_map(|device| async move { device })
            .collect()
            .await
    }

    /// Gpu ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Device name
    pub fn name(&self) -> &str {
        &self.adapter_info.name
    }

    /// Device type
    pub fn device_type(&self) -> DeviceType {
        self.adapter_info.device_type
    }

    /// Driver
    pub fn driver(&self) -> &str {
        &self.adapter_info.driver
    }

    /// Driver info
    pub fn driver_info(&self) -> &str {
        &self.adapter_info.driver_info
    }

    /// Backend
    pub fn backend(&self) -> Backend {
        self.adapter_info.backend
    }

    /// One proof-producing encoder instance per queue. Consumers run their own record encoding
    /// (Subspace does its KZG encoding in `subspace-proof-of-space-wgpu`).
    pub fn create_proofs_encoder_instances(&self) -> Vec<GpuRecordsEncoderInstance> {
        self.devices
            .clone()
            .into_iter()
            .map(|(device, queue, module)| GpuRecordsEncoderInstance::new(device, queue, module))
            .collect()
    }
}

pub struct GpuRecordsEncoderInstance {
    device: wgpu::Device,
    queue: Queue,
    mapping_error: Arc<Mutex<Option<BufferAsyncError>>>,
    tainted: bool,
    initial_state_host: Buffer,
    initial_state_gpu: Buffer,
    proofs_host: Buffer,
    proofs_gpu: Buffer,
    bind_group_compute_f1: BindGroup,
    compute_pipeline_compute_f1: ComputePipeline,
    bind_group_sort_buckets_a: BindGroup,
    compute_pipeline_sort_buckets_a: ComputePipeline,
    bind_group_sort_buckets_b: BindGroup,
    compute_pipeline_sort_buckets_b: ComputePipeline,
    bind_group_find_matches_and_compute_f2: BindGroup,
    compute_pipeline_find_matches_and_compute_f2: ComputePipeline,
    bind_group_find_matches_and_compute_f3: BindGroup,
    compute_pipeline_find_matches_and_compute_f3: ComputePipeline,
    bind_group_find_matches_and_compute_f4: BindGroup,
    compute_pipeline_find_matches_and_compute_f4: ComputePipeline,
    bind_group_find_matches_and_compute_f5: BindGroup,
    compute_pipeline_find_matches_and_compute_f5: ComputePipeline,
    bind_group_find_matches_and_compute_f6: BindGroup,
    compute_pipeline_find_matches_and_compute_f6: ComputePipeline,
    bind_group_find_matches_and_compute_f7: BindGroup,
    compute_pipeline_find_matches_and_compute_f7: ComputePipeline,
    bind_group_find_proofs: BindGroup,
    compute_pipeline_find_proofs: ComputePipeline,
}

impl fmt::Debug for GpuRecordsEncoderInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GpuRecordsEncoderInstance")
            .finish_non_exhaustive()
    }
}

impl GpuRecordsEncoderInstance {
    fn new(device: wgpu::Device, queue: Queue, module: ShaderModule) -> Self {
        let initial_state_host = device.create_buffer(&BufferDescriptor {
            label: Some("initial_state_host"),
            size: size_of::<ChaCha8Block>() as BufferAddress,
            usage: BufferUsages::MAP_WRITE | BufferUsages::COPY_SRC,
            mapped_at_creation: true,
        });

        let initial_state_gpu = device.create_buffer(&BufferDescriptor {
            label: Some("initial_state_gpu"),
            size: initial_state_host.size(),
            usage: BufferUsages::UNIFORM | BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let bucket_sizes_gpu_buffer_size = size_of::<[u32; NUM_BUCKETS]>() as BufferAddress;
        let table_6_proof_targets_sizes_gpu_buffer_size =
            size_of::<[u32; NUM_S_BUCKETS]>() as BufferAddress;
        // TODO: Sizes are excessive, for `bucket_sizes_gpu` are less than `u16` and could use SWAR
        //  approach for storing bucket sizes. Similarly, `table_6_proof_targets_sizes_gpu` sizes
        //  are less than `u8` and could use SWAR too with even higher compression ratio
        let bucket_sizes_gpu = device.create_buffer(&BufferDescriptor {
            label: Some("bucket_sizes_gpu"),
            size: bucket_sizes_gpu_buffer_size.max(table_6_proof_targets_sizes_gpu_buffer_size),
            usage: BufferUsages::STORAGE,
            mapped_at_creation: false,
        });
        // Reuse the same buffer as `bucket_sizes_gpu`, they are not overlapping in use
        let table_6_proof_targets_sizes_gpu = bucket_sizes_gpu.clone();

        let buckets_a_gpu = device.create_buffer(&BufferDescriptor {
            label: Some("buckets_a_gpu"),
            size: size_of::<[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS]>() as BufferAddress,
            usage: BufferUsages::STORAGE,
            mapped_at_creation: false,
        });

        let buckets_b_gpu = device.create_buffer(&BufferDescriptor {
            label: Some("buckets_b_gpu"),
            size: buckets_a_gpu.size(),
            usage: BufferUsages::STORAGE,
            mapped_at_creation: false,
        });

        let positions_f2_gpu = device.create_buffer(&BufferDescriptor {
            label: Some("positions_f2_gpu"),
            size: size_of::<[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>()
                as BufferAddress,
            usage: BufferUsages::STORAGE,
            mapped_at_creation: false,
        });

        let positions_f3_gpu = device.create_buffer(&BufferDescriptor {
            label: Some("positions_f3_gpu"),
            size: positions_f2_gpu.size(),
            usage: BufferUsages::STORAGE,
            mapped_at_creation: false,
        });

        let positions_f4_gpu = device.create_buffer(&BufferDescriptor {
            label: Some("positions_f4_gpu"),
            size: positions_f2_gpu.size(),
            usage: BufferUsages::STORAGE,
            mapped_at_creation: false,
        });

        let positions_f5_gpu = device.create_buffer(&BufferDescriptor {
            label: Some("positions_f5_gpu"),
            size: positions_f2_gpu.size(),
            usage: BufferUsages::STORAGE,
            mapped_at_creation: false,
        });

        let positions_f6_gpu = device.create_buffer(&BufferDescriptor {
            label: Some("positions_f6_gpu"),
            size: positions_f2_gpu.size(),
            usage: BufferUsages::STORAGE,
            mapped_at_creation: false,
        });

        let metadatas_gpu_buffer_size =
            size_of::<[[Metadata; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>() as BufferAddress;
        let table_6_proof_targets_gpu_buffer_size = size_of::<
            [[ProofTargets; NUM_ELEMENTS_PER_S_BUCKET]; NUM_S_BUCKETS],
        >() as BufferAddress;
        let metadatas_a_gpu = device.create_buffer(&BufferDescriptor {
            label: Some("metadatas_a_gpu"),
            size: metadatas_gpu_buffer_size.max(table_6_proof_targets_gpu_buffer_size),
            usage: BufferUsages::STORAGE,
            mapped_at_creation: false,
        });
        // Reuse the same buffer as `metadatas_a_gpu`, they are not overlapping in use
        let table_6_proof_targets_gpu = metadatas_a_gpu.clone();

        let metadatas_b_gpu = device.create_buffer(&BufferDescriptor {
            label: Some("metadatas_b_gpu"),
            size: metadatas_gpu_buffer_size,
            usage: BufferUsages::STORAGE,
            mapped_at_creation: false,
        });

        let proofs_host = device.create_buffer(&BufferDescriptor {
            label: Some("proofs_host"),
            size: size_of::<ProofsHost>() as BufferAddress,
            usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let proofs_gpu = device.create_buffer(&BufferDescriptor {
            label: Some("proofs_gpu"),
            size: proofs_host.size(),
            usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });

        let (bind_group_compute_f1, compute_pipeline_compute_f1) =
            bind_group_and_pipeline_compute_f1(
                &device,
                &module,
                &initial_state_gpu,
                &bucket_sizes_gpu,
                &buckets_a_gpu,
            );
        let (bind_group_sort_buckets_a, compute_pipeline_sort_buckets_a) =
            bind_group_and_pipeline_sort_buckets(
                &device,
                &module,
                &bucket_sizes_gpu,
                &buckets_a_gpu,
            );

        let (bind_group_sort_buckets_b, compute_pipeline_sort_buckets_b) =
            bind_group_and_pipeline_sort_buckets(
                &device,
                &module,
                &bucket_sizes_gpu,
                &buckets_b_gpu,
            );

        let (bind_group_find_matches_and_compute_f2, compute_pipeline_find_matches_and_compute_f2) =
            bind_group_and_pipeline_find_matches_and_compute_f2(
                &device,
                &module,
                &buckets_a_gpu,
                &bucket_sizes_gpu,
                &buckets_b_gpu,
                &positions_f2_gpu,
                &metadatas_b_gpu,
            );

        let (bind_group_find_matches_and_compute_f3, compute_pipeline_find_matches_and_compute_f3) =
            bind_group_and_pipeline_find_matches_and_compute_fn::<3>(
                &device,
                &module,
                &buckets_b_gpu,
                &metadatas_b_gpu,
                &bucket_sizes_gpu,
                &buckets_a_gpu,
                &positions_f3_gpu,
                &metadatas_a_gpu,
            );

        let (bind_group_find_matches_and_compute_f4, compute_pipeline_find_matches_and_compute_f4) =
            bind_group_and_pipeline_find_matches_and_compute_fn::<4>(
                &device,
                &module,
                &buckets_a_gpu,
                &metadatas_a_gpu,
                &bucket_sizes_gpu,
                &buckets_b_gpu,
                &positions_f4_gpu,
                &metadatas_b_gpu,
            );

        let (bind_group_find_matches_and_compute_f5, compute_pipeline_find_matches_and_compute_f5) =
            bind_group_and_pipeline_find_matches_and_compute_fn::<5>(
                &device,
                &module,
                &buckets_b_gpu,
                &metadatas_b_gpu,
                &bucket_sizes_gpu,
                &buckets_a_gpu,
                &positions_f5_gpu,
                &metadatas_a_gpu,
            );

        let (bind_group_find_matches_and_compute_f6, compute_pipeline_find_matches_and_compute_f6) =
            bind_group_and_pipeline_find_matches_and_compute_fn::<6>(
                &device,
                &module,
                &buckets_a_gpu,
                &metadatas_a_gpu,
                &bucket_sizes_gpu,
                &buckets_b_gpu,
                &positions_f6_gpu,
                &metadatas_b_gpu,
            );

        let (bind_group_find_matches_and_compute_f7, compute_pipeline_find_matches_and_compute_f7) =
            bind_group_and_pipeline_find_matches_and_compute_f7(
                &device,
                &module,
                &buckets_b_gpu,
                &metadatas_b_gpu,
                &table_6_proof_targets_sizes_gpu,
                &table_6_proof_targets_gpu,
            );

        let (bind_group_find_proofs, compute_pipeline_find_proofs) =
            bind_group_and_pipeline_find_proofs(
                &device,
                &module,
                &positions_f2_gpu,
                &positions_f3_gpu,
                &positions_f4_gpu,
                &positions_f5_gpu,
                &positions_f6_gpu,
                &table_6_proof_targets_sizes_gpu,
                &table_6_proof_targets_gpu,
                &proofs_gpu,
            );

        Self {
            device,
            queue,
            mapping_error: Arc::new(Mutex::new(None)),
            tainted: false,
            initial_state_host,
            initial_state_gpu,
            proofs_host,
            proofs_gpu,
            bind_group_compute_f1,
            compute_pipeline_compute_f1,
            bind_group_sort_buckets_a,
            compute_pipeline_sort_buckets_a,
            bind_group_sort_buckets_b,
            compute_pipeline_sort_buckets_b,
            bind_group_find_matches_and_compute_f2,
            compute_pipeline_find_matches_and_compute_f2,
            bind_group_find_matches_and_compute_f3,
            compute_pipeline_find_matches_and_compute_f3,
            bind_group_find_matches_and_compute_f4,
            compute_pipeline_find_matches_and_compute_f4,
            bind_group_find_matches_and_compute_f5,
            compute_pipeline_find_matches_and_compute_f5,
            bind_group_find_matches_and_compute_f6,
            compute_pipeline_find_matches_and_compute_f6,
            bind_group_find_matches_and_compute_f7,
            compute_pipeline_find_matches_and_compute_f7,
            bind_group_find_proofs,
            compute_pipeline_find_proofs,
        }
    }

    pub fn create_proofs(
        &mut self,
        seed: &PosSeed,
    ) -> Result<ProofsHostWrapper<'_>, RecordEncodingError> {
        if self.tainted {
            return Err(RecordEncodingError::DeviceBroken);
        }
        self.tainted = true;

        let mut encoder = self
            .device
            .create_command_encoder(&CommandEncoderDescriptor {
                label: Some("create_proofs"),
            });

        // Mapped initially and re-mapped at the end of the computation
        self.initial_state_host
            .get_mapped_range_mut(..)
            .copy_from_slice(&block_to_bytes(
                &ChaCha8State::init(seed, &[0; _]).to_repr(),
            ));
        self.initial_state_host.unmap();

        encoder.copy_buffer_to_buffer(
            &self.initial_state_host,
            0,
            &self.initial_state_gpu,
            0,
            self.initial_state_host.size(),
        );

        {
            let mut cpass = encoder.begin_compute_pass(&ComputePassDescriptor {
                label: Some("create_proofs"),
                timestamp_writes: None,
            });

            cpass.set_bind_group(0, &self.bind_group_compute_f1, &[]);
            cpass.set_pipeline(&self.compute_pipeline_compute_f1);
            cpass.dispatch_workgroups(
                MAX_TABLE_SIZE
                    .div_ceil(compute_f1::WORKGROUP_SIZE * compute_f1::ELEMENTS_PER_INVOCATION),
                1,
                1,
            );

            cpass.set_bind_group(0, &self.bind_group_sort_buckets_a, &[]);
            cpass.set_pipeline(&self.compute_pipeline_sort_buckets_a);
            cpass.dispatch_workgroups(NUM_BUCKETS as u32, 1, 1);

            cpass.set_bind_group(0, &self.bind_group_find_matches_and_compute_f2, &[]);
            cpass.set_pipeline(&self.compute_pipeline_find_matches_and_compute_f2);
            cpass.dispatch_workgroups(NUM_MATCH_BUCKETS as u32, 1, 1);

            cpass.set_bind_group(0, &self.bind_group_sort_buckets_b, &[]);
            cpass.set_pipeline(&self.compute_pipeline_sort_buckets_b);
            cpass.dispatch_workgroups(NUM_BUCKETS as u32, 1, 1);

            cpass.set_bind_group(0, &self.bind_group_find_matches_and_compute_f3, &[]);
            cpass.set_pipeline(&self.compute_pipeline_find_matches_and_compute_f3);
            cpass.dispatch_workgroups(NUM_MATCH_BUCKETS as u32, 1, 1);

            cpass.set_bind_group(0, &self.bind_group_sort_buckets_a, &[]);
            cpass.set_pipeline(&self.compute_pipeline_sort_buckets_a);
            cpass.dispatch_workgroups(NUM_BUCKETS as u32, 1, 1);

            cpass.set_bind_group(0, &self.bind_group_find_matches_and_compute_f4, &[]);
            cpass.set_pipeline(&self.compute_pipeline_find_matches_and_compute_f4);
            cpass.dispatch_workgroups(NUM_MATCH_BUCKETS as u32, 1, 1);

            cpass.set_bind_group(0, &self.bind_group_sort_buckets_b, &[]);
            cpass.set_pipeline(&self.compute_pipeline_sort_buckets_b);
            cpass.dispatch_workgroups(NUM_BUCKETS as u32, 1, 1);

            cpass.set_bind_group(0, &self.bind_group_find_matches_and_compute_f5, &[]);
            cpass.set_pipeline(&self.compute_pipeline_find_matches_and_compute_f5);
            cpass.dispatch_workgroups(NUM_MATCH_BUCKETS as u32, 1, 1);

            cpass.set_bind_group(0, &self.bind_group_sort_buckets_a, &[]);
            cpass.set_pipeline(&self.compute_pipeline_sort_buckets_a);
            cpass.dispatch_workgroups(NUM_BUCKETS as u32, 1, 1);

            cpass.set_bind_group(0, &self.bind_group_find_matches_and_compute_f6, &[]);
            cpass.set_pipeline(&self.compute_pipeline_find_matches_and_compute_f6);
            cpass.dispatch_workgroups(NUM_MATCH_BUCKETS as u32, 1, 1);

            cpass.set_bind_group(0, &self.bind_group_sort_buckets_b, &[]);
            cpass.set_pipeline(&self.compute_pipeline_sort_buckets_b);
            cpass.dispatch_workgroups(NUM_BUCKETS as u32, 1, 1);

            cpass.set_bind_group(0, &self.bind_group_find_matches_and_compute_f7, &[]);
            cpass.set_pipeline(&self.compute_pipeline_find_matches_and_compute_f7);
            cpass.dispatch_workgroups(NUM_MATCH_BUCKETS as u32, 1, 1);

            cpass.set_bind_group(0, &self.bind_group_find_proofs, &[]);
            cpass.set_pipeline(&self.compute_pipeline_find_proofs);
            cpass.dispatch_workgroups(NUM_S_BUCKETS as u32 / find_proofs::WORKGROUP_SIZE, 1, 1);
        }

        encoder.copy_buffer_to_buffer(
            &self.proofs_gpu,
            0,
            &self.proofs_host,
            0,
            self.proofs_host.size(),
        );

        // Map initial state for writes for the next iteration
        encoder.map_buffer_on_submit(&self.initial_state_host, MapMode::Write, .., {
            let mapping_error = Arc::clone(&self.mapping_error);

            move |r| {
                if let Err(error) = r {
                    mapping_error.lock().replace(error);
                }
            }
        });
        encoder.map_buffer_on_submit(&self.proofs_host, MapMode::Read, .., {
            let mapping_error = Arc::clone(&self.mapping_error);

            move |r| {
                if let Err(error) = r {
                    mapping_error.lock().replace(error);
                }
            }
        });

        let submission_index = self.queue.submit([encoder.finish()]);

        self.device.poll(PollType::Wait {
            submission_index: Some(submission_index),
            timeout: None,
        })?;

        if let Some(error) = self.mapping_error.lock().take() {
            return Err(RecordEncodingError::BufferMapping(error));
        }

        let proofs = {
            let proofs_host_ptr = self
                .proofs_host
                .get_mapped_range(..)
                .as_ptr()
                .cast::<ProofsHost>();
            // SAFETY: Initialized on the GPU
            unsafe { &*proofs_host_ptr }
        };

        self.tainted = false;

        Ok(ProofsHostWrapper {
            proofs,
            proofs_host: &self.proofs_host,
        })
    }
}

fn bind_group_and_pipeline_compute_f1(
    device: &wgpu::Device,
    module: &ShaderModule,
    initial_state_gpu: &Buffer,
    bucket_sizes_gpu: &Buffer,
    buckets_gpu: &Buffer,
) -> (BindGroup, ComputePipeline) {
    let bind_group_layout = device.create_bind_group_layout(&BindGroupLayoutDescriptor {
        label: Some("compute_f1"),
        entries: &[
            BindGroupLayoutEntry {
                binding: 0,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Uniform,
                },
            },
            BindGroupLayoutEntry {
                binding: 1,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
            BindGroupLayoutEntry {
                binding: 2,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
        ],
    });

    let pipeline_layout = device.create_pipeline_layout(&PipelineLayoutDescriptor {
        label: Some("compute_f1"),
        bind_group_layouts: &[Some(&bind_group_layout)],
        immediate_size: 0,
    });

    let compute_pipeline = device.create_compute_pipeline(&ComputePipelineDescriptor {
        compilation_options: PipelineCompilationOptions {
            constants: &[],
            zero_initialize_workgroup_memory: false,
        },
        cache: None,
        label: Some("compute_f1"),
        layout: Some(&pipeline_layout),
        module,
        entry_point: Some("compute_f1"),
    });

    let bind_group = device.create_bind_group(&BindGroupDescriptor {
        label: Some("compute_f1"),
        layout: &bind_group_layout,
        entries: &[
            BindGroupEntry {
                binding: 0,
                resource: initial_state_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 1,
                resource: bucket_sizes_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 2,
                resource: buckets_gpu.as_entire_binding(),
            },
        ],
    });

    (bind_group, compute_pipeline)
}

fn bind_group_and_pipeline_sort_buckets(
    device: &wgpu::Device,
    module: &ShaderModule,
    bucket_sizes_gpu: &Buffer,
    buckets_gpu: &Buffer,
) -> (BindGroup, ComputePipeline) {
    let bind_group_layout = device.create_bind_group_layout(&BindGroupLayoutDescriptor {
        label: Some("sort_buckets"),
        entries: &[
            BindGroupLayoutEntry {
                binding: 0,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
            BindGroupLayoutEntry {
                binding: 1,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
        ],
    });

    let pipeline_layout = device.create_pipeline_layout(&PipelineLayoutDescriptor {
        label: Some("sort_buckets"),
        bind_group_layouts: &[Some(&bind_group_layout)],
        immediate_size: 0,
    });

    let compute_pipeline = device.create_compute_pipeline(&ComputePipelineDescriptor {
        compilation_options: PipelineCompilationOptions {
            constants: &[],
            zero_initialize_workgroup_memory: false,
        },
        cache: None,
        label: Some("sort_buckets"),
        layout: Some(&pipeline_layout),
        module,
        entry_point: Some("sort_buckets"),
    });

    let bind_group = device.create_bind_group(&BindGroupDescriptor {
        label: Some("sort_buckets"),
        layout: &bind_group_layout,
        entries: &[
            BindGroupEntry {
                binding: 0,
                resource: bucket_sizes_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 1,
                resource: buckets_gpu.as_entire_binding(),
            },
        ],
    });

    (bind_group, compute_pipeline)
}

fn bind_group_and_pipeline_find_matches_and_compute_f2(
    device: &wgpu::Device,
    module: &ShaderModule,
    parent_buckets_gpu: &Buffer,
    bucket_sizes_gpu: &Buffer,
    buckets_gpu: &Buffer,
    positions_gpu: &Buffer,
    metadatas_gpu: &Buffer,
) -> (BindGroup, ComputePipeline) {
    let bind_group_layout = device.create_bind_group_layout(&BindGroupLayoutDescriptor {
        label: Some("find_matches_and_compute_f2"),
        entries: &[
            BindGroupLayoutEntry {
                binding: 0,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: true },
                },
            },
            BindGroupLayoutEntry {
                binding: 1,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
            BindGroupLayoutEntry {
                binding: 2,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
            BindGroupLayoutEntry {
                binding: 3,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
            BindGroupLayoutEntry {
                binding: 4,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
        ],
    });

    let pipeline_layout = device.create_pipeline_layout(&PipelineLayoutDescriptor {
        label: Some("find_matches_and_compute_f2"),
        bind_group_layouts: &[Some(&bind_group_layout)],
        immediate_size: 0,
    });

    let compute_pipeline = device.create_compute_pipeline(&ComputePipelineDescriptor {
        compilation_options: PipelineCompilationOptions {
            constants: &[],
            zero_initialize_workgroup_memory: true,
        },
        cache: None,
        label: Some("find_matches_and_compute_f2"),
        layout: Some(&pipeline_layout),
        module,
        entry_point: Some("find_matches_and_compute_f2"),
    });

    let bind_group = device.create_bind_group(&BindGroupDescriptor {
        label: Some("find_matches_and_compute_f2"),
        layout: &bind_group_layout,
        entries: &[
            BindGroupEntry {
                binding: 0,
                resource: parent_buckets_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 1,
                resource: bucket_sizes_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 2,
                resource: buckets_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 3,
                resource: positions_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 4,
                resource: metadatas_gpu.as_entire_binding(),
            },
        ],
    });

    (bind_group, compute_pipeline)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Both I/O and Vulkan stuff together take a lot of arguments"
)]
fn bind_group_and_pipeline_find_matches_and_compute_fn<const TABLE_NUMBER: u8>(
    device: &wgpu::Device,
    module: &ShaderModule,
    parent_buckets_gpu: &Buffer,
    parent_metadatas_gpu: &Buffer,
    bucket_sizes_gpu: &Buffer,
    buckets_gpu: &Buffer,
    positions_gpu: &Buffer,
    metadatas_gpu: &Buffer,
) -> (BindGroup, ComputePipeline) {
    let label = format!("find_matches_and_compute_f{TABLE_NUMBER}");
    let bind_group_layout = device.create_bind_group_layout(&BindGroupLayoutDescriptor {
        label: Some(&label),
        entries: &[
            BindGroupLayoutEntry {
                binding: 0,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: true },
                },
            },
            BindGroupLayoutEntry {
                binding: 1,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: true },
                },
            },
            BindGroupLayoutEntry {
                binding: 2,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
            BindGroupLayoutEntry {
                binding: 3,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
            BindGroupLayoutEntry {
                binding: 4,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
            BindGroupLayoutEntry {
                binding: 5,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
        ],
    });

    let pipeline_layout = device.create_pipeline_layout(&PipelineLayoutDescriptor {
        label: Some(&label),
        bind_group_layouts: &[Some(&bind_group_layout)],
        immediate_size: 0,
    });

    let compute_pipeline = device.create_compute_pipeline(&ComputePipelineDescriptor {
        compilation_options: PipelineCompilationOptions {
            constants: &[],
            zero_initialize_workgroup_memory: true,
        },
        cache: None,
        label: Some(&label),
        layout: Some(&pipeline_layout),
        module,
        entry_point: Some(&format!("find_matches_and_compute_f{TABLE_NUMBER}")),
    });

    let bind_group = device.create_bind_group(&BindGroupDescriptor {
        label: Some(&label),
        layout: &bind_group_layout,
        entries: &[
            BindGroupEntry {
                binding: 0,
                resource: parent_buckets_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 1,
                resource: parent_metadatas_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 2,
                resource: bucket_sizes_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 3,
                resource: buckets_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 4,
                resource: positions_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 5,
                resource: metadatas_gpu.as_entire_binding(),
            },
        ],
    });

    (bind_group, compute_pipeline)
}

fn bind_group_and_pipeline_find_matches_and_compute_f7(
    device: &wgpu::Device,
    module: &ShaderModule,
    parent_buckets_gpu: &Buffer,
    parent_metadatas_gpu: &Buffer,
    table_6_proof_targets_sizes_gpu: &Buffer,
    table_6_proof_targets_gpu: &Buffer,
) -> (BindGroup, ComputePipeline) {
    let bind_group_layout = device.create_bind_group_layout(&BindGroupLayoutDescriptor {
        label: Some("find_matches_and_compute_f7"),
        entries: &[
            BindGroupLayoutEntry {
                binding: 0,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: true },
                },
            },
            BindGroupLayoutEntry {
                binding: 1,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: true },
                },
            },
            BindGroupLayoutEntry {
                binding: 2,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
            BindGroupLayoutEntry {
                binding: 3,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
        ],
    });

    let pipeline_layout = device.create_pipeline_layout(&PipelineLayoutDescriptor {
        label: Some("find_matches_and_compute_f7"),
        bind_group_layouts: &[Some(&bind_group_layout)],
        immediate_size: 0,
    });

    let compute_pipeline = device.create_compute_pipeline(&ComputePipelineDescriptor {
        compilation_options: PipelineCompilationOptions {
            constants: &[],
            zero_initialize_workgroup_memory: true,
        },
        cache: None,
        label: Some("find_matches_and_compute_f7"),
        layout: Some(&pipeline_layout),
        module,
        entry_point: Some("find_matches_and_compute_f7"),
    });

    let bind_group = device.create_bind_group(&BindGroupDescriptor {
        label: Some("find_matches_and_compute_f7"),
        layout: &bind_group_layout,
        entries: &[
            BindGroupEntry {
                binding: 0,
                resource: parent_buckets_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 1,
                resource: parent_metadatas_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 2,
                resource: table_6_proof_targets_sizes_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 3,
                resource: table_6_proof_targets_gpu.as_entire_binding(),
            },
        ],
    });

    (bind_group, compute_pipeline)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Both I/O and Vulkan stuff together take a lot of arguments"
)]
fn bind_group_and_pipeline_find_proofs(
    device: &wgpu::Device,
    module: &ShaderModule,
    table_2_positions_gpu: &Buffer,
    table_3_positions_gpu: &Buffer,
    table_4_positions_gpu: &Buffer,
    table_5_positions_gpu: &Buffer,
    table_6_positions_gpu: &Buffer,
    bucket_sizes_gpu: &Buffer,
    buckets_gpu: &Buffer,
    proofs_gpu: &Buffer,
) -> (BindGroup, ComputePipeline) {
    let bind_group_layout = device.create_bind_group_layout(&BindGroupLayoutDescriptor {
        label: Some("find_proofs"),
        entries: &[
            BindGroupLayoutEntry {
                binding: 0,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: true },
                },
            },
            BindGroupLayoutEntry {
                binding: 1,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: true },
                },
            },
            BindGroupLayoutEntry {
                binding: 2,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: true },
                },
            },
            BindGroupLayoutEntry {
                binding: 3,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: true },
                },
            },
            BindGroupLayoutEntry {
                binding: 4,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: true },
                },
            },
            BindGroupLayoutEntry {
                binding: 5,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
            BindGroupLayoutEntry {
                binding: 6,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: true },
                },
            },
            BindGroupLayoutEntry {
                binding: 7,
                count: None,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    has_dynamic_offset: false,
                    min_binding_size: None,
                    ty: BufferBindingType::Storage { read_only: false },
                },
            },
        ],
    });

    let pipeline_layout = device.create_pipeline_layout(&PipelineLayoutDescriptor {
        label: Some("find_proofs"),
        bind_group_layouts: &[Some(&bind_group_layout)],
        immediate_size: 0,
    });

    let compute_pipeline = device.create_compute_pipeline(&ComputePipelineDescriptor {
        compilation_options: PipelineCompilationOptions {
            constants: &[],
            zero_initialize_workgroup_memory: false,
        },
        cache: None,
        label: Some("find_proofs"),
        layout: Some(&pipeline_layout),
        module,
        entry_point: Some("find_proofs"),
    });

    let bind_group = device.create_bind_group(&BindGroupDescriptor {
        label: Some("find_proofs"),
        layout: &bind_group_layout,
        entries: &[
            BindGroupEntry {
                binding: 0,
                resource: table_2_positions_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 1,
                resource: table_3_positions_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 2,
                resource: table_4_positions_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 3,
                resource: table_5_positions_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 4,
                resource: table_6_positions_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 5,
                resource: bucket_sizes_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 6,
                resource: buckets_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 7,
                resource: proofs_gpu.as_entire_binding(),
            },
        ],
    });

    (bind_group, compute_pipeline)
}
