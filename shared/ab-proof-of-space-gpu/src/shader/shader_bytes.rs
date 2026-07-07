use std::borrow::Cow;
use std::slice;
use wgpu::{ShaderModuleDescriptor, ShaderSource};

#[repr(align(4))]
pub(super) struct ShaderBytes<T>(pub(super) T)
where
    T: ?Sized;

#[cfg(not(target_arch = "spirv"))]
impl ShaderBytes<[u8]> {
    pub(super) const fn to_module(&self) -> ShaderModuleDescriptor<'_> {
        assert!(align_of_val(self) == align_of::<u32>());
        let shader_bytes = &self.0;

        // SAFETY: Correctly aligned, all bit patterns are valid, lifetime is static before and
        // after
        let shader_bytes = unsafe {
            slice::from_raw_parts(
                shader_bytes.as_ptr().cast::<u32>(),
                shader_bytes.len() / size_of::<u32>(),
            )
        };

        ShaderModuleDescriptor {
            label: Some(env!("CARGO_PKG_NAME")),
            source: ShaderSource::SpirV(Cow::Borrowed(shader_bytes)),
        }
    }
}
