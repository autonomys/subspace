use crate::shader::constants::{K, MAX_BUCKET_SIZE, NUM_BUCKETS, y_size_bits};
use crate::shader::select_shader_features_limits;
use crate::shader::types::{Position, PositionExt, PositionR, Y};
use chacha20::ChaCha8Rng;
use futures::executor::block_on;
use rand::prelude::*;
use std::mem::MaybeUninit;
use std::slice;
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
fn sort_buckets_gpu() {
    let mut rng = ChaCha8Rng::from_seed(Default::default());

    // SAFETY: Data structure filled with zeroes is a valid invariant
    let mut buckets =
        unsafe { Box::<[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS]>::new_zeroed().assume_init() };

    for (index, position_y) in buckets.as_flattened_mut().iter_mut().enumerate() {
        let y = Y::from(rng.next_u32() >> (u32::BITS - y_size_bits(K) as u32));
        let (_bucket_index, r) = y.into_bucket_index_and_r();
        *position_y = PositionR {
            position: Position::from_u32(index as u32),
            // Limit `y` to the appropriate number of bits
            r,
        };
    }

    buckets.as_flattened_mut().shuffle(&mut rng);

    let reduced_last_bucket_size = MAX_BUCKET_SIZE as u32 - 10;
    let mut bucket_sizes = Box::new([MAX_BUCKET_SIZE as u32; NUM_BUCKETS]);
    *bucket_sizes.last_mut().unwrap() = reduced_last_bucket_size;

    let Some(actual_output) = block_on(sort_buckets(&bucket_sizes, &buckets)) else {
        panic!("No compatible device detected, can't run tests");
    };

    let mut expected_output = buckets;
    for entry in &mut expected_output.last_mut().unwrap()[reduced_last_bucket_size as usize..] {
        *entry = PositionR::SENTINEL;
    }
    for bucket in &mut expected_output {
        bucket.sort();
    }

    for (bucket_index, (expected, actual)) in
        expected_output.iter().zip(actual_output.iter()).enumerate()
    {
        for (index, (expected, actual)) in expected.iter().zip(actual.iter()).enumerate() {
            assert_eq!(
                expected, actual,
                "bucket_index={bucket_index}, index={index}"
            );
        }
    }
}

async fn sort_buckets(
    bucket_sizes: &[u32; NUM_BUCKETS],
    buckets: &[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS],
) -> Option<Box<[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS]>> {
    let backends = Backends::from_env().unwrap_or(Backends::METAL | Backends::VULKAN);
    let instance = Instance::new(InstanceDescriptor {
        backends,
        flags: InstanceFlags::GPU_BASED_VALIDATION.with_env(),
        memory_budget_thresholds: MemoryBudgetThresholds::default(),
        backend_options: BackendOptions::from_env_or_default(),
        display: None,
    });

    let adapters = instance.enumerate_adapters(backends).await;
    let mut result = None::<Box<[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS]>>;

    for adapter in adapters {
        println!("Testing adapter {:?}", adapter.get_info());

        let Some(adapter_result) = sort_buckets_adapter(bucket_sizes, buckets, adapter).await
        else {
            continue;
        };

        match &result {
            Some(result) => {
                for (bucket_index, (result, adapter_result)) in
                    result.iter().zip(adapter_result.iter()).enumerate()
                {
                    for (index, (result, adapter_result)) in
                        result.iter().zip(adapter_result.iter()).enumerate()
                    {
                        assert_eq!(
                            result, adapter_result,
                            "bucket_index={bucket_index}, index={index}"
                        );
                    }
                }
            }
            None => {
                result.replace(adapter_result);
            }
        }
    }

    result
}

async fn sort_buckets_adapter(
    bucket_sizes: &[u32; NUM_BUCKETS],
    buckets: &[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS],
    adapter: Adapter,
) -> Option<Box<[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS]>> {
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
        entry_point: Some("sort_buckets"),
    });

    let bucket_sizes_gpu = device.create_buffer_init(&BufferInitDescriptor {
        label: None,
        // SAFETY: Initialized bytes of the correct length
        contents: unsafe {
            slice::from_raw_parts(
                bucket_sizes.as_ptr().cast::<u8>(),
                size_of_val(bucket_sizes),
            )
        },
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
    });

    let buckets_host = device.create_buffer(&BufferDescriptor {
        label: None,
        size: size_of_val(buckets) as BufferAddress,
        usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let buckets_gpu = device.create_buffer_init(&BufferInitDescriptor {
        label: None,
        // SAFETY: Initialized bytes of the correct length
        contents: unsafe {
            slice::from_raw_parts(buckets.as_ptr().cast::<u8>(), size_of_val(buckets))
        },
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
    });

    let bind_group = device.create_bind_group(&BindGroupDescriptor {
        label: None,
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

    let mut encoder = device.create_command_encoder(&CommandEncoderDescriptor { label: None });

    {
        let mut cpass = encoder.begin_compute_pass(&ComputePassDescriptor::default());
        cpass.set_bind_group(0, &bind_group, &[]);
        cpass.set_pipeline(&compute_pipeline);
        cpass.dispatch_workgroups(NUM_BUCKETS as u32, 1, 1);
    }

    encoder.copy_buffer_to_buffer(&buckets_gpu, 0, &buckets_host, 0, buckets_host.size());

    encoder.map_buffer_on_submit(&buckets_host, MapMode::Read, .., |r| r.unwrap());

    queue.submit([encoder.finish()]);

    device.poll(PollType::wait_indefinitely()).unwrap();

    let buckets = {
        let buckets_host_ptr = buckets_host
            .get_mapped_range(..)
            .unwrap()
            .as_ptr()
            .cast::<[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS]>();
        // SAFETY: The pointer points to correctly initialized and aligned memory
        let buckets_ref = unsafe { &*buckets_host_ptr };

        // SAFETY: Contents is `MaybeUninit`
        let mut buckets = unsafe {
            Box::<[MaybeUninit<[PositionR; MAX_BUCKET_SIZE]>; NUM_BUCKETS]>::new_uninit()
                .assume_init()
        };
        buckets.write_copy_of_slice(buckets_ref);
        // SAFETY: Just initialized
        unsafe {
            let ptr = Box::into_raw(buckets);
            Box::from_raw(ptr.cast::<[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS]>())
        }
    };
    buckets_host.unmap();

    Some(buckets)
}
