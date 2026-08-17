//! Proof of space plotting utilities for GPU (Vulkan/Metal).
//!
//! Similarly to `ab-proof-of-space`, max supported `K` within range `15..=24` due to internal data
//! structures used (`ab-proof-of-space` also supports `K=25`, but this crate doesn't for now).

#![cfg_attr(target_arch = "spirv", no_std)]
#![feature(generic_const_exprs, step_trait)]
#![expect(incomplete_features, reason = "generic_const_exprs")]

#[cfg(not(target_arch = "spirv"))]
mod host;
// This is used for benchmarks of isolated shaders externally, not for general use
#[doc(hidden)]
pub mod shader;

// TODO: Remove gate after https://github.com/Rust-GPU/rust-gpu/pull/249
#[cfg(not(target_arch = "spirv"))]
pub use crate::shader::find_proofs::ProofsHost;
#[cfg(not(target_arch = "spirv"))]
pub use host::{Device, GpuRecordsEncoderInstance, ProofsHostWrapper, RecordEncodingError};
#[cfg(not(target_arch = "spirv"))]
use subspace_core_primitives::pos::PosProof;
#[cfg(not(target_arch = "spirv"))]
pub use wgpu::{Backend, DeviceType};

// TODO: Remove gate after https://github.com/Rust-GPU/rust-gpu/pull/249
#[cfg(not(target_arch = "spirv"))]
const _: () = {
    assert!(PosProof::K >= 15 && PosProof::K <= 24);
};
