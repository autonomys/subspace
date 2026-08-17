pub mod compute_f1;
pub mod compute_fn;
// TODO: Reuse constants from `ab-proof-of-space` once it compiles with `rust-gpu`
pub mod constants;
pub mod find_matches_and_compute_f2;
pub mod find_matches_and_compute_f7;
pub mod find_matches_and_compute_fn;
pub mod find_matches_in_buckets;
pub mod find_proofs;
mod polyfills;
#[cfg(not(target_arch = "spirv"))]
mod shader_bytes;
pub mod sort_buckets;
// TODO: Reuse types from `ab-proof-of-space` once it compiles with `rust-gpu`
pub mod types;
mod u32n;

#[cfg(not(target_arch = "spirv"))]
use wgpu::{Adapter, Features, Limits};

#[cfg(not(target_endian = "little"))]
compile_error!("Only little-endian platforms are supported");

/// This should be more than any usable implementation has.
///
/// There are assertions elsewhere ensuring this is large enough at compile time.
const MIN_SUBGROUP_SIZE: u32 = 4;
/// Compiled SPIR-V shader
#[cfg(not(target_arch = "spirv"))]
const SHADER: wgpu::ShaderModuleDescriptor<'static> = {
    use crate::shader::shader_bytes::ShaderBytes;

    const SHADER_BYTES_INTERNAL: &ShaderBytes<[u8]> =
        &ShaderBytes(*include_bytes!(env!("SHADER_PATH")));

    SHADER_BYTES_INTERNAL.to_module()
};

/// For a given set of adapter features and limits, this function returns the shader itself,
/// required features, and required limits.
///
/// Returns `None` for unsupported adapter.
#[cfg(not(target_arch = "spirv"))]
pub fn select_shader_features_limits(
    adapter: &Adapter,
) -> Option<(wgpu::ShaderModuleDescriptor<'static>, Features, Limits)> {
    const SHADER_BASELINE_FEATURES: Features = Features::SUBGROUP;

    let adapter_features = adapter.features();
    let adapter_limits = adapter.limits();

    if adapter_features.contains(SHADER_BASELINE_FEATURES)
        && adapter.get_info().subgroup_min_size >= MIN_SUBGROUP_SIZE
    {
        Some((SHADER, SHADER_BASELINE_FEATURES, adapter_limits))
    } else {
        None
    }
}
