//! Subspace proof of space plotting on the GPU via wgpu (Vulkan/Metal).
//!
//! Host-only: proofs are produced on the GPU by the vendored `ab-proof-of-space-gpu`, and records
//! are encoded here with subspace's KZG scheme, so a GPU-plotted sector reads back byte-for-byte the
//! same as the CPU one.

#![feature(portable_simd)]

mod host;

pub use ab_proof_of_space_gpu::{Backend, Device, DeviceType};
pub use host::WgpuDevice;
