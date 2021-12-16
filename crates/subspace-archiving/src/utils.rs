extern crate alloc;

use alloc::vec::Vec;
use core::mem;
use reed_solomon_erasure::galois_16::Field as Galois16Field;
use reed_solomon_erasure::Field;

pub(crate) type Gf16Element = <Galois16Field as Field>::Elem;
pub(crate) const GF_16_ELEMENT_BYTES: usize = mem::size_of::<Gf16Element>();

/// Convert slice to a vector of arrays for `reed_solomon_erasure` library.
pub(crate) fn slice_to_arrays<S: AsRef<[u8]> + ?Sized>(slice: &S) -> Vec<Gf16Element> {
    slice
        .as_ref()
        .chunks_exact(GF_16_ELEMENT_BYTES)
        .map(|s| s.try_into().unwrap())
        .collect()
}
