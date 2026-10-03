use crate::shader::constants::{MAX_BUCKET_SIZE, NUM_MATCH_BUCKETS, PARAM_BC, REDUCED_BUCKET_SIZE};
use crate::shader::find_matches_in_buckets::cpu_tests::find_matches_in_buckets_correct;
use crate::shader::select_shader_features_limits;
use crate::shader::types::{Match, Position, PositionExt, PositionR, Y};
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

const NUM_BUCKETS: usize = 3;

#[test]
fn find_matches_in_buckets_gpu() {
    let mut rng = ChaCha8Rng::from_seed(Default::default());
    let parent_table_size = 1000_usize;

    // Generate `y`s within `0..PARAM_BC*NUM_BUCKETS` range to fill the first `NUM_BUCKETS` buckets
    let parent_table_ys =
        iter::repeat_with(|| Y::from(rng.next_u32() % (u32::from(PARAM_BC) * NUM_BUCKETS as u32)))
            .take(parent_table_size)
            .collect::<Vec<_>>();
    let buckets = {
        let mut buckets = [[PositionR::SENTINEL; MAX_BUCKET_SIZE]; 3];

        let mut total_found = [0usize; 3];
        for (position, &y) in parent_table_ys.iter().enumerate() {
            let (bucket_index, r) = y.into_bucket_index_and_r();
            let next_index = total_found[bucket_index as usize];
            if next_index < REDUCED_BUCKET_SIZE {
                buckets[bucket_index as usize][next_index] = PositionR {
                    position: Position::from_u32(position as u32),
                    r,
                };
                total_found[bucket_index as usize] += 1;
            }
        }

        buckets
    };

    let Some(actual_matches) = block_on(find_matches_in_buckets(&buckets)) else {
        panic!("No compatible device detected, can't run tests");
    };

    let expected_matches = buckets
        .array_windows()
        .enumerate()
        .map(|(left_bucket_index, [left_bucket, right_bucket])| {
            let mut matches = [MaybeUninit::uninit(); _];
            find_matches_in_buckets_correct(
                left_bucket_index as u32,
                left_bucket,
                right_bucket,
                &mut matches,
            )
            .0
            .to_vec()
        })
        .collect::<Vec<_>>();

    assert_eq!(actual_matches.len(), expected_matches.len());
    for (bucket_pair, (expected, actual)) in
        expected_matches.into_iter().zip(actual_matches).enumerate()
    {
        assert_eq!(expected.len(), actual.len(), "bucket_pair={bucket_pair}");
        for (index, (expected, actual)) in expected.into_iter().zip(actual).enumerate() {
            assert_eq!(expected, actual, "bucket_pair={bucket_pair}, index={index}");
        }
    }
}

async fn find_matches_in_buckets(
    buckets: &[[PositionR; MAX_BUCKET_SIZE]],
) -> Option<Vec<Vec<Match>>> {
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

        let Some(adapter_result) = find_matches_in_buckets_adapter(buckets, adapter).await else {
            continue;
        };

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

async fn find_matches_in_buckets_adapter(
    buckets: &[[PositionR; MAX_BUCKET_SIZE]],
    adapter: Adapter,
) -> Option<Vec<Vec<Match>>> {
    let num_bucket_pairs = buckets.len() - 1;

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
        entry_point: Some("find_matches_in_buckets"),
    });

    let buckets_gpu = device.create_buffer_init(&BufferInitDescriptor {
        label: None,
        // SAFETY: Initialized bytes of the correct length
        contents: unsafe {
            slice::from_raw_parts(buckets.as_ptr().cast::<u8>(), size_of_val(buckets))
        },
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
    });

    let matches_host = device.create_buffer(&BufferDescriptor {
        label: None,
        size: (size_of::<[Match; MAX_BUCKET_SIZE]>() * num_bucket_pairs) as BufferAddress,
        usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let matches_gpu = device.create_buffer(&BufferDescriptor {
        label: None,
        size: matches_host.size(),
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
        mapped_at_creation: false,
    });

    let matches_counts_host = device.create_buffer(&BufferDescriptor {
        label: None,
        size: (size_of::<u32>() * num_bucket_pairs) as BufferAddress,
        usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let matches_counts_gpu = device.create_buffer(&BufferDescriptor {
        label: None,
        size: matches_counts_host.size(),
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
        mapped_at_creation: false,
    });

    let bind_group = device.create_bind_group(&BindGroupDescriptor {
        label: None,
        layout: &bind_group_layout,
        entries: &[
            BindGroupEntry {
                binding: 0,
                resource: buckets_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 1,
                resource: matches_gpu.as_entire_binding(),
            },
            BindGroupEntry {
                binding: 2,
                resource: matches_counts_gpu.as_entire_binding(),
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

    encoder.copy_buffer_to_buffer(&matches_gpu, 0, &matches_host, 0, matches_host.size());
    encoder.copy_buffer_to_buffer(
        &matches_counts_gpu,
        0,
        &matches_counts_host,
        0,
        matches_counts_host.size(),
    );

    encoder.map_buffer_on_submit(&matches_host, MapMode::Read, .., |r| r.unwrap());
    encoder.map_buffer_on_submit(&matches_counts_host, MapMode::Read, .., |r| r.unwrap());

    queue.submit([encoder.finish()]);

    device.poll(PollType::wait_indefinitely()).unwrap();

    let matches = {
        let matches_host_ptr = matches_host
            .get_mapped_range(..)
            .unwrap()
            .as_ptr()
            .cast::<[Match; MAX_BUCKET_SIZE]>();
        let matches_counts_host_ptr = matches_counts_host
            .get_mapped_range(..)
            .unwrap()
            .as_ptr()
            .cast::<u32>();

        // SAFETY: The pointer points to correctly initialized and aligned memory
        let matches = unsafe { slice::from_raw_parts(matches_host_ptr, num_bucket_pairs) };
        // SAFETY: The pointer points to correctly initialized and aligned memory
        let matches_counts =
            unsafe { slice::from_raw_parts(matches_counts_host_ptr, num_bucket_pairs) };

        matches
            .iter()
            .zip(matches_counts)
            .map(|(matches, &matches_count)| matches[..matches_count as usize].to_vec())
            .collect()
    };
    matches_host.unmap();
    matches_counts_host.unmap();

    Some(matches)
}
