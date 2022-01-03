use crate::utils::{Gf16Element, GF_16_ELEMENT_BYTES};
use std::io;
use std::mem::ManuallyDrop;

/// Wrapper data structure for record shards that correspond to the same recorded history segment
/// for more convenient management.
///
/// Allows to accessing underlying data both as list of shards for erasure coding and regular slice
/// of bytes for other purposes, also implements [`std::io::Write`] so that it can be used with
/// `parity-scale-codec` to write encoded data right into [`RecordShards`].
pub(super) struct RecordShards {
    shards: Vec<Gf16Element>,
    cursor: usize,
    /// Shard size in bytes
    shard_size: usize,
}

impl io::Write for RecordShards {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY:
        // Lifetime is the same as source, de-allocation is prevented with `ManuallyDrop`, no
        // re-allocation will happen so interpreting one vector as different vector is fine.
        unsafe {
            let mut target = ManuallyDrop::new(Vec::from_raw_parts(
                self.shards.as_mut_ptr() as *mut u8,
                self.shards.len() * GF_16_ELEMENT_BYTES,
                self.shards.len() * GF_16_ELEMENT_BYTES,
            ));

            let written_bytes = target[self.cursor..].as_mut().write(buf)?;

            self.cursor += written_bytes;

            Ok(written_bytes)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl RecordShards {
    /// Create new `Shards` struct for specified number of shards and shard size in bytes.
    ///
    /// Panics if shard size is not multiple of 2.
    pub(super) fn new(number_of_shards: usize, shard_size: usize) -> Self {
        assert_eq!(shard_size % GF_16_ELEMENT_BYTES, 0);

        let mut shards = Vec::with_capacity(number_of_shards * shard_size / GF_16_ELEMENT_BYTES);
        shards.resize(shards.capacity(), Gf16Element::default());

        Self {
            shards,
            cursor: 0,
            shard_size,
        }
    }

    /// Access internal record shards as contiguous memory slice.
    pub(super) fn as_bytes(&mut self) -> impl AsRef<[u8]> + '_ {
        // SAFETY:
        // Returned lifetime is the same as source, de-allocation is prevented with `ManuallyDrop`
        // and specific type is erased from API, so nothing except reading bytes is possible.
        unsafe {
            /// Private wrapper just so that `AsRef<[u8]>` can be implemented on it.
            struct AsRefRecordShards(ManuallyDrop<Vec<u8>>);

            impl AsRef<[u8]> for AsRefRecordShards {
                fn as_ref(&self) -> &[u8] {
                    &self.0
                }
            }

            AsRefRecordShards(ManuallyDrop::new(Vec::from_raw_parts(
                self.shards.as_mut_ptr() as *mut u8,
                self.shards.len() * GF_16_ELEMENT_BYTES,
                self.shards.len() * GF_16_ELEMENT_BYTES,
            )))
        }
    }

    /// Access internal record shards as vector of mutable shards.
    pub(super) fn as_mut_slices(&mut self) -> Vec<&mut [Gf16Element]> {
        self.shards
            .chunks_exact_mut(self.shard_size / GF_16_ELEMENT_BYTES)
            .collect()
    }
}
