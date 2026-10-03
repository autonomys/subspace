use crate::shader::constants::{
    MAX_TABLE_SIZE, NUM_MATCH_BUCKETS, NUM_S_BUCKETS, REDUCED_MATCHES_COUNT,
};
use crate::shader::find_matches_and_compute_f7::{NUM_ELEMENTS_PER_S_BUCKET, ProofTargets};
use crate::shader::find_proofs::cpu_tests::find_proofs_correct;
use crate::shader::find_proofs::{ProofsHost, WORKGROUP_SIZE};
use crate::shader::select_shader_features_limits;
use crate::shader::types::Position;
use chacha20::ChaCha8Rng;
use futures::executor::block_on;
use rand::prelude::*;
use std::mem::MaybeUninit;
use std::{array, slice};
use subspace_core_primitives::pieces::Record;
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

fn generate_positions(
    rng: &mut ChaCha8Rng,
) -> Box<[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]> {
    // SAFETY: Contents is `MaybeUninit`
    let mut positions = unsafe {
        Box::<[[MaybeUninit<[Position; 2]>; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>::new_uninit(
        )
        .assume_init()
    };

    for positions in positions.as_flattened_mut() {
        positions.write([
            rng.random_range(0..REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS) as u32,
            rng.random_range(0..REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS) as u32,
        ]);
    }

    // SAFETY: Just initialized
    unsafe {
        let ptr = Box::into_raw(positions);
        Box::from_raw(ptr.cast::<[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS]>())
    }
}

fn generate_buckets(
    rng: &mut ChaCha8Rng,
) -> (
    Box<[u32; NUM_S_BUCKETS]>,
    Box<[[ProofTargets; NUM_ELEMENTS_PER_S_BUCKET]; NUM_S_BUCKETS]>,
) {
    // Ensure exactly `Record::NUM_CHUNKS` elements have non-zero bucket size
    let mut bucket_sizes = Box::new(array::from_fn::<_, NUM_S_BUCKETS, _>(|_| {
        // Must not be zero, we'll zero some of these later
        rng.random_range(1..=NUM_ELEMENTS_PER_S_BUCKET as u32)
    }));
    bucket_sizes[..Record::NUM_CHUNKS].fill(0);
    bucket_sizes.shuffle(rng);

    // SAFETY: Contents is `MaybeUninit`
    let mut buckets = unsafe {
        Box::<[[MaybeUninit<ProofTargets>; NUM_ELEMENTS_PER_S_BUCKET]; NUM_S_BUCKETS]>::new_uninit()
            .assume_init()
    };

    for (absolute_position, proof_targets) in buckets.as_flattened_mut().iter_mut().enumerate() {
        proof_targets.write(ProofTargets {
            absolute_position: absolute_position as u32,
            positions: [
                rng.random_range(0..REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS) as u32,
                rng.random_range(0..REDUCED_MATCHES_COUNT * NUM_MATCH_BUCKETS) as u32,
            ],
        });
    }

    // SAFETY: Just initialized
    let mut buckets = unsafe {
        let ptr = Box::into_raw(buckets);
        Box::from_raw(ptr.cast::<[[ProofTargets; NUM_ELEMENTS_PER_S_BUCKET]; NUM_S_BUCKETS]>())
    };

    for bucket in buckets.iter_mut() {
        bucket.shuffle(rng);
    }

    (bucket_sizes, buckets)
}

#[test]
fn find_proofs_gpu() {
    let mut rng = ChaCha8Rng::from_seed(Default::default());

    let mut table_2_positions = generate_positions(&mut rng);
    // Clamp values in the first table to the correct range
    for positions in table_2_positions.as_flattened_mut() {
        positions[0] = positions[0].min(MAX_TABLE_SIZE - 1);
        positions[1] = positions[1].min(MAX_TABLE_SIZE - 1);
    }
    let table_3_positions = generate_positions(&mut rng);
    let table_4_positions = generate_positions(&mut rng);
    let table_5_positions = generate_positions(&mut rng);
    let table_6_positions = generate_positions(&mut rng);

    let (bucket_sizes, buckets) = generate_buckets(&mut rng);

    let Some((actual_found_proofs, actual_proofs)) = block_on(find_proofs(
        &table_2_positions,
        &table_3_positions,
        &table_4_positions,
        &table_5_positions,
        &table_6_positions,
        &bucket_sizes,
        &buckets,
    )) else {
        panic!("No compatible device detected, can't run tests");
    };

    let (expected_found_proofs, expected_proofs) = find_proofs_correct(
        &table_2_positions,
        &table_3_positions,
        &table_4_positions,
        &table_5_positions,
        &table_6_positions,
        &bucket_sizes,
        &buckets,
    );

    for (byte_index, (expected, actual)) in expected_found_proofs
        .iter()
        .zip(actual_found_proofs.iter())
        .enumerate()
    {
        assert_eq!(
            expected, actual,
            "byte_index={byte_index} expected={expected:#b} actual={actual:#b}",
        );
    }
    for (s_bucket, ((expected, actual), &bucket_size)) in expected_proofs
        .iter()
        .zip(actual_proofs.iter())
        .zip(bucket_sizes.iter())
        .enumerate()
    {
        if bucket_size != 0 {
            assert_eq!(expected, &**actual, "s_bucket={s_bucket}");
        }
    }
}

async fn find_proofs(
    table_2_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_3_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_4_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_5_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_6_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    bucket_sizes: &[u32; NUM_S_BUCKETS],
    buckets: &[[ProofTargets; NUM_ELEMENTS_PER_S_BUCKET]; NUM_S_BUCKETS],
) -> Option<(
    Box<[u8; Record::NUM_S_BUCKETS / u8::BITS as usize]>,
    Box<[PosProof; NUM_S_BUCKETS]>,
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

        let Some(adapter_result) = find_proofs_adapter(
            table_2_positions,
            table_3_positions,
            table_4_positions,
            table_5_positions,
            table_6_positions,
            bucket_sizes,
            buckets,
            adapter,
        )
        .await
        else {
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

#[expect(clippy::too_many_arguments, reason = "Fine for tests")]
async fn find_proofs_adapter(
    table_2_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_3_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_4_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_5_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    table_6_positions: &[[[Position; 2]; REDUCED_MATCHES_COUNT]; NUM_MATCH_BUCKETS],
    bucket_sizes: &[u32; NUM_S_BUCKETS],
    buckets: &[[ProofTargets; NUM_ELEMENTS_PER_S_BUCKET]; NUM_S_BUCKETS],
    adapter: Adapter,
) -> Option<(
    Box<[u8; Record::NUM_S_BUCKETS / u8::BITS as usize]>,
    Box<[PosProof; NUM_S_BUCKETS]>,
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
        entry_point: Some("find_proofs"),
    });

    let table_2_positions_gpu = device.create_buffer_init(&BufferInitDescriptor {
        label: None,
        // SAFETY: Initialized bytes of the correct length
        contents: unsafe {
            slice::from_raw_parts(
                table_2_positions.as_ptr().cast::<u8>(),
                size_of_val(table_2_positions),
            )
        },
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
    });

    let table_3_positions_gpu = device.create_buffer_init(&BufferInitDescriptor {
        label: None,
        // SAFETY: Initialized bytes of the correct length
        contents: unsafe {
            slice::from_raw_parts(
                table_3_positions.as_ptr().cast::<u8>(),
                size_of_val(table_3_positions),
            )
        },
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
    });

    let table_4_positions_gpu = device.create_buffer_init(&BufferInitDescriptor {
        label: None,
        // SAFETY: Initialized bytes of the correct length
        contents: unsafe {
            slice::from_raw_parts(
                table_4_positions.as_ptr().cast::<u8>(),
                size_of_val(table_4_positions),
            )
        },
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
    });

    let table_5_positions_gpu = device.create_buffer_init(&BufferInitDescriptor {
        label: None,
        // SAFETY: Initialized bytes of the correct length
        contents: unsafe {
            slice::from_raw_parts(
                table_5_positions.as_ptr().cast::<u8>(),
                size_of_val(table_5_positions),
            )
        },
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
    });

    let table_6_positions_gpu = device.create_buffer_init(&BufferInitDescriptor {
        label: None,
        // SAFETY: Initialized bytes of the correct length
        contents: unsafe {
            slice::from_raw_parts(
                table_6_positions.as_ptr().cast::<u8>(),
                size_of_val(table_6_positions),
            )
        },
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
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

    let buckets_gpu = device.create_buffer_init(&BufferInitDescriptor {
        label: None,
        // SAFETY: Initialized bytes of the correct length
        contents: unsafe {
            slice::from_raw_parts(buckets.as_ptr().cast::<u8>(), size_of_val(buckets))
        },
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
    });

    let proofs_host = device.create_buffer(&BufferDescriptor {
        label: None,
        size: size_of::<ProofsHost>() as BufferAddress,
        usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let proofs_gpu = device.create_buffer(&BufferDescriptor {
        label: None,
        size: proofs_host.size(),
        usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
        mapped_at_creation: false,
    });

    let bind_group = device.create_bind_group(&BindGroupDescriptor {
        label: None,
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

    let mut encoder = device.create_command_encoder(&CommandEncoderDescriptor { label: None });

    {
        let mut cpass = encoder.begin_compute_pass(&ComputePassDescriptor::default());
        cpass.set_bind_group(0, &bind_group, &[]);
        cpass.set_pipeline(&compute_pipeline);
        cpass.dispatch_workgroups(NUM_S_BUCKETS as u32 / WORKGROUP_SIZE, 1, 1);
    }

    encoder.copy_buffer_to_buffer(&proofs_gpu, 0, &proofs_host, 0, proofs_host.size());

    encoder.map_buffer_on_submit(&proofs_host, MapMode::Read, .., |r| r.unwrap());

    queue.submit([encoder.finish()]);

    device.poll(PollType::wait_indefinitely()).unwrap();

    let (found_proofs, proofs) = {
        let proofs_host_ptr = proofs_host
            .get_mapped_range(..)
            .unwrap()
            .as_ptr()
            .cast::<ProofsHost>();
        // SAFETY: The pointer points to correctly initialized and aligned memory
        let proofs_ref = unsafe { &*proofs_host_ptr };

        let found_proofs = Box::new(proofs_ref.found_proofs);
        // SAFETY: Contents is `MaybeUninit`
        let mut proofs =
            unsafe { Box::<[MaybeUninit<PosProof>; NUM_S_BUCKETS]>::new_uninit().assume_init() };
        proofs.write_copy_of_slice(&proofs_ref.proofs);
        // SAFETY: Just initialized
        let proofs = unsafe {
            let ptr = Box::into_raw(proofs);
            Box::from_raw(ptr.cast::<[PosProof; NUM_S_BUCKETS]>())
        };

        (found_proofs, proofs)
    };
    proofs_host.unmap();

    Some((found_proofs, proofs))
}
