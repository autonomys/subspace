use reed_solomon_erasure::galois_16::Field as Galois16Field;
use reed_solomon_erasure::Field;
use std::mem;

type Elem = <Galois16Field as Field>::Elem;
const ELEM_BYTES: usize = mem::size_of::<Elem>();

/// Convert slice to a vector of arrays for `reed_solomon_erasure` library.
pub(crate) fn slice_to_arrays<S: AsRef<[u8]> + ?Sized>(slice: &S) -> Vec<Elem> {
    slice
        .as_ref()
        .chunks_exact(ELEM_BYTES)
        .map(|s| s.try_into().unwrap())
        .collect()
}
