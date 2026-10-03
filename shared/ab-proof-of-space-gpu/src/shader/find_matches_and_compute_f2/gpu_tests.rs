use crate::shader::constants::{
    MAX_BUCKET_SIZE, MAX_TABLE_SIZE, NUM_BUCKETS, NUM_MATCH_BUCKETS, PARAM_BC, REDUCED_BUCKET_SIZE,
    REDUCED_MATCHES_COUNT,
};
use crate::shader::find_matches_and_compute_f2::cpu_tests::find_matches_and_compute_f2_correct;
use crate::shader::find_matches_and_compute_f2::{PARENT_TABLE_NUMBER, TABLE_NUMBER};
use crate::shader::select_shader_features_limits;
use crate::shader::types::{Metadata, Position, PositionExt, PositionR, Y};
use chacha20::ChaCha8Rng;
use chacha20::rand_core::{Rng, SeedableRng};
use futures::executor::block_on;
use std::mem::MaybeUninit;
use std::{iter, slice};
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
fn find_matches_and_compute_f2_gpu() {
    let mut rng = ChaCha8Rng::from_seed(Default::default());

    // Generate `y`s within `0..PARAM_BC*NUM_BUCKETS` range to fill the first `NUM_BUCKETS` buckets
    let parent_table_ys =
        iter::repeat_with(|| Y::from(rng.next_u32() % (u32::from(PARAM_BC) * NUM_BUCKETS as u32)))
            .take(MAX_TABLE_SIZE as usize)
            .collect::<Vec<_>>();
    let parent_buckets = {
        // SAFETY: Contents is `MaybeUninit`
        let mut buckets = unsafe {
            Box::<[[MaybeUninit<PositionR>; MAX_BUCKET_SIZE]; NUM_BUCKETS]>::new_uninit()
                .assume_init()
        };

        let mut bucket_offsets = [0usize; NUM_BUCKETS];
        for (position, &y) in parent_table_ys.iter().enumerate() {
            let (bucket_index, r) = y.into_bucket_index_and_r();
            let next_index = bucket_offsets[bucket_index as usize];
            if next_index < REDUCED_BUCKET_SIZE {
                buckets[bucket_index as usize][next_index].write(PositionR {
                    position: Position::from_u32(position as u32),
                    r,
                });
                bucket_offsets[bucket_index as usize] += 1;
            }
        }

        for (bucket, initialized) in buckets.iter_mut().zip(bucket_offsets) {
            bucket[initialized..].write_filled(PositionR::SENTINEL);
        }

        let ptr = Box::into_raw(buckets);

        // SAFETY: Just initialized
        unsafe { Box::from_raw(ptr.cast::<[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS]>()) }
    };

    let Some((actual_bucket_sizes, actual_buckets, actual_positions, actual_metadatas)) =
        block_on(find_matches_and_compute_f2(&parent_buckets))
    else {
        panic!("No compatible device detected, can't run tests");
    };

    // SAFETY: Contents is `MaybeUninit`
    let mut expected_buckets = unsafe {
        Box::<[[MaybeUninit<PositionR>; MAX_BUCKET_SIZE]; NUM_BUCKETS]>::new_uninit().assume_init()
    };
    // SAFETY: Contents is `MaybeUninit`
    let mut expected_positions = unsafe {
        Box::<[[MaybeUninit<[Position; 2]>; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>::new_uninit(
        )
        .assume_init()
    };
    // SAFETY: Contents is `MaybeUninit`
    let mut expected_metadatas = unsafe {
        Box::<[[MaybeUninit<Metadata>; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>::new_uninit()
            .assume_init()
    };
    let expected_buckets = find_matches_and_compute_f2_correct::<TABLE_NUMBER, PARENT_TABLE_NUMBER>(
        &parent_buckets,
        &mut expected_buckets,
        &mut expected_positions,
        &mut expected_metadatas,
    );

    let expected_metadatas = expected_metadatas.as_flattened();
    let expected_positions = expected_positions.as_flattened();
    let actual_metadatas = actual_metadatas.as_flattened();
    let actual_positions = actual_positions.as_flattened();

    for (bucket_index, (expected_bucket, (&actual_bucket_size, actual_bucket))) in expected_buckets
        .iter()
        .zip(actual_bucket_sizes.iter().zip(actual_buckets.iter()))
        .enumerate()
    {
        let expected_bucket_size = expected_bucket
            .iter()
            .take_while(|entry| entry.position != Position::SENTINEL)
            .count();
        // Actual bucket size can be larger simply because GPU implementation is concurrent and
        // doesn't truncate buckets
        assert!(
            expected_bucket_size as u32 <= actual_bucket_size,
            "bucket_index={bucket_index} expected_bucket_size={expected_bucket_size} <= \
            actual_bucket_size={actual_bucket_size}"
        );

        for (index, (expected, actual)) in expected_bucket[..expected_bucket_size]
            .iter()
            .zip(actual_bucket)
            .enumerate()
        {
            assert_eq!(
                expected.position, actual.position,
                "bucket_index={bucket_index}, index={index}"
            );
            let position = expected.position;
            if position != Position::SENTINEL {
                assert_eq!(
                    expected.r, actual.r,
                    "bucket_index={bucket_index}, index={index}"
                );

                assert_eq!(
                    // SAFETY: Non-sentinel positions are always initialized
                    unsafe { expected_metadatas[position as usize].assume_init() },
                    actual_metadatas[position as usize],
                    "bucket_index={bucket_index}, index={index}"
                );
                assert_eq!(
                    // SAFETY: Non-sentinel positions are always initialized
                    unsafe { expected_positions[position as usize].assume_init() },
                    actual_positions[position as usize],
                    "bucket_index={bucket_index}, index={index}"
                );
            }
        }
    }
}

async fn find_matches_and_compute_f2(
    parent_buckets: &[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS],
) -> Option<(
    Box<[u32; NUM_BUCKETS]>,
    Box<[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS]>,
    Box<[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>,
    Box<[[Metadata; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>,
)> {
    let backends = Backends::from_env().unwrap_or(Backends::METAL | Backends::VULKAN);
    let instance = Instance::new(InstanceDescriptor {
        backends,
        flags: InstanceFlags::GPU_BASED_VALIDATION.with_env(),
        memory_budget_thresholds: MemoryBudgetThresholds::default(),
        backend_options: BackendOptions::from_env_or_default(),
        display: None,
    });

    let adapters = instance.enumerate_adapters(backends).await;
    let mut result = None;

    for adapter in adapters {
        println!("Testing adapter {:?}", adapter.get_info());

        let Some(mut adapter_result) =
            find_matches_and_compute_f2_adapter(parent_buckets, adapter).await
        else {
            continue;
        };

        // Fix up order within buckets, since sorting is a separate step on GPU and before that the
        // results are non-deterministic
        adapter_result
            .0
            .iter()
            .zip(adapter_result.1.iter_mut())
            .for_each(|(&bucket_size, bucket)| {
                bucket[..bucket_size as usize].sort();
            });

        match &result {
            Some(result) => {
                assert!(result == &adapter_result);
            }
            None => {
                result.replace(adapter_result);
            }
        }
    }

    result
}

async fn find_matches_and_compute_f2_adapter(
    parent_buckets: &[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS],
    adapter: Adapter,
) -> Option<(
    Box<[u32; NUM_BUCKETS]>,
    Box<[[PositionR; MAX_BUCKET_SIZE]; NUM_BUCKETS]>,
    Box<[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>,
    Box<[[Metadata; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>,
)> {
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
        label: None,
        bind_group_layouts: &[Some(&bind_group_layout)],
        immediate_size: 0,
    });

    let compute_pipeline = device.create_compute_pipeline(&ComputePipelineDescriptor {
        compilation_options: PipelineCompilationOptions {
            constants: &[],
            zero_initialize_workgroup_memory: true,
        },
        cache: None,
        label: None,
        layout: Some(&pipeline_layout),
        module: &module,
        entry_point: Some("find_matches_and_compute_f2"),
    });

    let parent_buckets_gpu = device.create_buffer_init(&BufferInitDescriptor {
        label: None,
        // SAFETY: Initialized bytes of the correct length
        contents: unsafe {
            slice::from_raw_parts(
                parent_buckets.as_ptr().cast::<u8>(),
                size_of_val(parent_buckets),
            )
        },
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
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

    let positions_host = device.create_buffer(&BufferDescriptor {
        label: None,
        size: size_of::<[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>()
            as BufferAddress,
        usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let positions_gpu = device.create_buffer(&BufferDescriptor {
        label: None,
        size: positions_host.size(),
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
        mapped_at_creation: false,
    });

    let metadatas_host = device.create_buffer(&BufferDescriptor {
        label: None,
        size: size_of::<[[Metadata; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>() as BufferAddress,
        usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let metadatas_gpu = device.create_buffer(&BufferDescriptor {
        label: None,
        size: metadatas_host.size(),
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
        mapped_at_creation: false,
    });

    let bind_group = device.create_bind_group(&BindGroupDescriptor {
        label: None,
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

    let mut encoder = device.create_command_encoder(&CommandEncoderDescriptor { label: None });

    {
        let mut cpass = encoder.begin_compute_pass(&ComputePassDescriptor::default());
        cpass.set_bind_group(0, &bind_group, &[]);
        cpass.set_pipeline(&compute_pipeline);
        cpass.dispatch_workgroups(NUM_MATCH_BUCKETS as u32, 1, 1);
    }

    encoder.copy_buffer_to_buffer(
        &bucket_sizes_gpu,
        0,
        &bucket_sizes_host,
        0,
        bucket_sizes_host.size(),
    );
    encoder.copy_buffer_to_buffer(&buckets_gpu, 0, &buckets_host, 0, buckets_host.size());
    encoder.copy_buffer_to_buffer(&positions_gpu, 0, &positions_host, 0, positions_host.size());
    encoder.copy_buffer_to_buffer(&metadatas_gpu, 0, &metadatas_host, 0, metadatas_host.size());

    encoder.map_buffer_on_submit(&bucket_sizes_host, MapMode::Read, .., |r| r.unwrap());
    encoder.map_buffer_on_submit(&buckets_host, MapMode::Read, .., |r| r.unwrap());
    encoder.map_buffer_on_submit(&positions_host, MapMode::Read, .., |r| r.unwrap());
    encoder.map_buffer_on_submit(&metadatas_host, MapMode::Read, .., |r| r.unwrap());

    queue.submit([encoder.finish()]);

    device.poll(PollType::wait_indefinitely()).unwrap();

    let bucket_sizes = {
        let bucket_sizes_host_ptr = bucket_sizes_host
            .get_mapped_range(..)
            .unwrap()
            .as_ptr()
            .cast::<[u32; NUM_BUCKETS]>();
        // SAFETY: The pointer points to correctly initialized and aligned memory
        let bucket_sizes_ref = unsafe { &*bucket_sizes_host_ptr };

        // SAFETY: Contents is `MaybeUninit`
        let mut bucket_sizes =
            unsafe { Box::<[MaybeUninit<u32>; NUM_BUCKETS]>::new_uninit().assume_init() };
        bucket_sizes.write_copy_of_slice(bucket_sizes_ref);
        // SAFETY: Just initialized
        unsafe {
            let ptr = Box::into_raw(bucket_sizes);
            Box::from_raw(ptr.cast::<[u32; NUM_BUCKETS]>())
        }
    };
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
    let positions = {
        let positions_host_ptr = positions_host
            .get_mapped_range(..)
            .unwrap()
            .as_ptr()
            .cast::<[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>();
        // SAFETY: The pointer points to correctly initialized and aligned memory
        let positions_ref = unsafe { &*positions_host_ptr };

        // SAFETY: Contents is `MaybeUninit`
        let mut positions = unsafe {
            Box::<[MaybeUninit<[[Position;2]; REDUCED_MATCHES_COUNT]>; NUM_MATCH_BUCKETS]>::new_uninit()
                .assume_init()
        };
        positions.write_copy_of_slice(positions_ref);
        // SAFETY: Just initialized
        unsafe {
            let ptr = Box::into_raw(positions);
            Box::from_raw(ptr.cast::<[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>())
        }
    };
    let metadatas = {
        let metadatas_host_ptr = metadatas_host
            .get_mapped_range(..)
            .unwrap()
            .as_ptr()
            .cast::<[[Metadata; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>();
        // SAFETY: The pointer points to correctly initialized and aligned memory
        let metadatas_ref = unsafe { &*metadatas_host_ptr };

        // SAFETY: Contents is `MaybeUninit`
        let mut metadatas = unsafe {
            Box::<[MaybeUninit<[Metadata; REDUCED_MATCHES_COUNT]>; NUM_MATCH_BUCKETS]>::new_uninit()
                .assume_init()
        };
        metadatas.write_copy_of_slice(metadatas_ref);
        // SAFETY: Just initialized
        unsafe {
            let ptr = Box::into_raw(metadatas);
            Box::from_raw(ptr.cast::<[[Metadata; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>())
        }
    };
    bucket_sizes_host.unmap();
    buckets_host.unmap();
    positions_host.unmap();
    metadatas_host.unmap();

    Some((bucket_sizes, buckets, positions, metadatas))
}
