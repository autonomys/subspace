#[cfg(target_arch = "spirv")]
use spirv_std::arch::IndexUnchecked;

// TODO: This is a polyfill to work around for this issue:
//  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
#[cfg(target_arch = "spirv")]
pub(super) trait ArrayIndexingPolyfill<T> {
    /// The same as [`<[T]>::get_unchecked()`]
    unsafe fn get_unchecked(&self, index: usize) -> &T;
    /// The same as [`<[T]>::get_unchecked_mut()`]
    unsafe fn get_unchecked_mut(&mut self, index: usize) -> &mut T;
}

#[cfg(target_arch = "spirv")]
impl<const N: usize, T> ArrayIndexingPolyfill<T> for [T; N] {
    #[inline(always)]
    unsafe fn get_unchecked(&self, index: usize) -> &T {
        // SAFETY: Explicitly unchecked
        unsafe { self.index_unchecked(index) }
    }

    #[inline(always)]
    unsafe fn get_unchecked_mut(&mut self, index: usize) -> &mut T {
        // SAFETY: Explicitly unchecked
        unsafe { self.index_unchecked_mut(index) }
    }
}
