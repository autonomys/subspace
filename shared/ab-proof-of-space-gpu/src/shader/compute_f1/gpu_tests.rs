use crate::shader::compute_f1::cpu_tests::correct_compute_f1;
use crate::shader::compute_f1::{ELEMENTS_PER_INVOCATION, WORKGROUP_SIZE};
use crate::shader::constants::{MAX_BUCKET_SIZE, MAX_TABLE_SIZE, NUM_BUCKETS};
use crate::shader::select_shader_features_limits;
use crate::shader::types::{PositionR, X};
use ab_chacha8::ChaCha8State;
use futures::executor::block_on;
use std::slice;
use subspace_core_primitives::pos::PosProof;
use wgpu::util::{BufferInitDescriptor, DeviceExt};
use wgpu::{
    Adapter, BackendOptions, Backends, BindGroupDescriptor, BindGroupEntry,
    BindGroupLayoutDescriptor, BindGroupLayoutEntry, BindingType, BufferAddress, BufferBindingType,
    BufferDescriptor, BufferUsages, CommandEncoderDescriptor, ComputePassDescriptor,
    ComputePipelineDescriptor, DeviceDescriptor, Instance, InstanceDescriptor, InstanceFlags,
    MapMode, MemoryBudgetThresholds, PipelineCompilationOptions, PipelineLayoutDescriptor,
    PollType, ShaderStages,
};

#[test]
fn compute_f1_gpu() {
    let seed = [1; 32];

    let initial_state = ChaCha8State::init(&seed, &[0; _]);

    let Some(actual_output) = block_on(compute_f1(&initial_state)) else {
        panic!("No compatible device detected, can't run tests");
    };

    let expected_output = (X::ZERO..)
        .take(MAX_TABLE_SIZE as usize)
        .map(|x| correct_compute_f1::<const { PosProof::K }>(x, &seed))
        .collect::<Vec<_>>();

    assert_eq!(
        actual_output.iter().map(Vec::len).sum::<usize>(),
        MAX_TABLE_SIZE as usize
    );
    for (bucket_index, bucket) in actual_output.iter().enumerate() {
        for &PositionR { position, r } in bucket {
            // TODO: This doesn't compile right now, but will be once this is resolved:
            //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
            // let expected_y = expected_output[usize::from(position)];
            let expected_y = expected_output[position as usize];
            let (expected_bucket_index, expected_r) = expected_y.into_bucket_index_and_r();
            assert_eq!(
                bucket_index, expected_bucket_index as usize,
                "position={position:?}, r={r:?}"
            );
            assert_eq!(r, expected_r, "position={position:?}, r={r:?}");
        }
    }
}

async fn compute_f1(initial_state: &ChaCha8State) -> Option<Vec<Vec<PositionR>>> {
    let backends = Backends::from_env().unwrap_or(Backends::METAL | Backends::VULKAN);
    let instance = Instance::new(InstanceDescriptor {
        backends,
        flags: InstanceFlags::GPU_BASED_VALIDATION.with_env(),
        memory_budget_thresholds: MemoryBudgetThresholds::default(),
        backend_options: BackendOptions::from_env_or_default(),
        display: None,
    });

    let adapters = instance.enumerate_adapters(backends).await;
    let mut result = None::<Vec<Vec<PositionR>>>;

    for adapter in adapters {
        println!("Testing adapter {:?}", adapter.get_info());

        let Some(adapter_result) = compute_f1_adapter(initial_state, adapter).await else {
            continue;
        };

        match &result {
            Some(result) => {
                // Since output is non-deterministic here, sort buckets before comparing
                for (bucket_index, (result, adapter_result)) in
                    result.iter().zip(adapter_result).enumerate()
                {
                    let mut result = result.clone();
                    let mut adapter_result = adapter_result.clone();

                    result.sort();
                    adapter_result.sort();

                    assert!(result == adapter_result, "bucket_index={bucket_index}");
                }
            }
            None => {
                result.replace(adapter_result);
            }
        }
    }

    result
}

async fn compute_f1_adapter(
    initial_state: &ChaCha8State,
    adapter: Adapter,
) -> Option<Vec<Vec<PositionR>>> {
    let (shader, required_features, required_limits) = select_shader_features_limits(&adapter)?;

    let (device, queue) = adapter
        .request_device(&DeviceDescriptor {
            label: None,
            required_features,
            required_limits,
            ..DeviceDescriptor::default()
        })
        .await
        .unwrap();

    let module = device.create_shader_module(shader);

    let bind_group_layout = device.create_bind_group_layout(&BindGroupLayoutDescriptor {
        label: None,
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
        label: None,
        bind_group_layouts: &[Some(&bind_group_layout)],
        immediate_size: 0,
    });

    let compute_pipeline = device.create_compute_pipeline(&ComputePipelineDescriptor {
        compilation_options: PipelineCompilationOptions {
            constants: &[],
            zero_initialize_workgroup_memory: false,
        },
        cache: None,
        label: None,
        layout: Some(&pipeline_layout),
        module: &module,
        entry_point: Some("compute_f1"),
    });

    let initial_state = initial_state.to_repr();

    let initial_state_gpu = device.create_buffer_init(&BufferInitDescriptor {
        label: None,
        // SAFETY: Initialized bytes of the correct length
        contents: unsafe {
            slice::from_raw_parts(
                initial_state.as_ptr().cast::<u8>(),
                size_of_val(&initial_state),
            )
        },
        usage: BufferUsages::UNIFORM,
    });

    let bucket_sizes_host = device.create_buffer(&BufferDescriptor {
        label: None,
        size: size_of::<[u32; NUM_BUCKETS]>() as BufferAddress,
        usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let bucket_sizes_gpu = device.create_buffer(&BufferDescriptor {
        label: None,
        size: bucket_sizes_host.size(),
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
        mapped_at_creation: false,
    });

    let buckets_host = device.create_buffer(&BufferDescriptor {
        label: None,
        size: size_of::<[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS]>() as BufferAddress,
        usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let buckets_gpu = device.create_buffer(&BufferDescriptor {
        label: None,
        size: buckets_host.size(),
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
        mapped_at_creation: false,
    });

    let bind_group = device.create_bind_group(&BindGroupDescriptor {
        label: None,
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

    let mut encoder = device.create_command_encoder(&CommandEncoderDescriptor { label: None });

    {
        let mut cpass = encoder.begin_compute_pass(&ComputePassDescriptor::default());
        cpass.set_bind_group(0, &bind_group, &[]);
        cpass.set_pipeline(&compute_pipeline);
        cpass.dispatch_workgroups(
            MAX_TABLE_SIZE.div_ceil(WORKGROUP_SIZE * ELEMENTS_PER_INVOCATION),
            1,
            1,
        );
    }

    encoder.copy_buffer_to_buffer(
        &bucket_sizes_gpu,
        0,
        &bucket_sizes_host,
        0,
        bucket_sizes_host.size(),
    );
    encoder.copy_buffer_to_buffer(&buckets_gpu, 0, &buckets_host, 0, buckets_host.size());

    encoder.map_buffer_on_submit(&bucket_sizes_host, MapMode::Read, .., |r| r.unwrap());
    encoder.map_buffer_on_submit(&buckets_host, MapMode::Read, .., |r| r.unwrap());

    queue.submit([encoder.finish()]);

    device.poll(PollType::wait_indefinitely()).unwrap();

    let buckets = {
        let bucket_sizes_host_ptr = bucket_sizes_host
            .get_mapped_range(..)
            .unwrap()
            .as_ptr()
            .cast::<[u32; NUM_BUCKETS]>();
        // SAFETY: The pointer is to correctly initialized and aligned memory
        let bucket_sizes = unsafe { &*bucket_sizes_host_ptr };

        let buckets_host_ptr = buckets_host
            .get_mapped_range(..)
            .unwrap()
            .as_ptr()
            .cast::<[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS]>();
        // SAFETY: The pointer is to correctly initialized and aligned memory
        let buckets = unsafe { &*buckets_host_ptr };

        buckets
            .iter()
            .zip(bucket_sizes)
            .map(|(bucket, &bucket_count)| bucket[..bucket_count as usize].to_vec())
            .collect()
    };
    bucket_sizes_host.unmap();
    buckets_host.unmap();

    Some(buckets)
}
