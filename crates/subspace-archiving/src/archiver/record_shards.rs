extern crate alloc;

use crate::archiver::Segment;
use crate::utils::{Gf16Element, GF_16_ELEMENT_BYTES};
use alloc::vec;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;
use parity_scale_codec::{Encode, Output};

/// Container that allows SCALE-encoding into directly while making sure nothing is written past
/// data shard space and without extra memory copies.
struct WritableShards {
    data_shards_size: u32,
    shards: Vec<Gf16Element>,
    cursor: usize,
}

impl Output for WritableShards {
    fn write(&mut self, buf: &[u8]) {
        // SAFETY:
        // Lifetime is the same as source, de-allocation is prevented with `ManuallyDrop`, no
        // re-allocation will happen so interpreting one vector as different vector is fine.
        unsafe {
            let mut target = ManuallyDrop::new(Vec::from_raw_parts(
                self.shards.as_mut_ptr() as *mut u8,
                self.shards.len() * GF_16_ELEMENT_BYTES,
                self.shards.len() * GF_16_ELEMENT_BYTES,
            ));

            // May panic only if inputs are incorrect.
            target[..self.data_shards_size as usize][self.cursor..][..buf.len()]
                .as_mut()
                .copy_from_slice(buf);

            self.cursor += buf.len();
        }
    }
}

/// Wrapper data structure for record shards that correspond to the same recorded history segment
/// for more convenient management.
///
/// Allows to accessing underlying data both as list of shards for erasure coding and regular slice
/// of bytes for other purposes, also implements [`std::io::Write`] so that it can be used with
/// `parity-scale-codec` to write encoded data right into [`RecordShards`].
pub(super) struct RecordShards {
    shards: Vec<Gf16Element>,
    /// Shard size in bytes
    shard_size: u32,
}

impl RecordShards {
    /// Create new `Shards` struct for specified number of shards and shard size in bytes.
    ///
    /// Panics if shard size is not multiple of 2 or encoded segment doesn't fit into data shards.
    pub(super) fn new(
        data_shards: u32,
        parity_shards: u32,
        shard_size: u32,
        segment: &Segment,
    ) -> Self {
        assert_eq!(shard_size as usize % GF_16_ELEMENT_BYTES, 0);

        let mut writable_shards = WritableShards {
            data_shards_size: data_shards * shard_size,
            shards: vec![
                Gf16Element::default();
                ((data_shards + parity_shards) * shard_size) as usize / GF_16_ELEMENT_BYTES
            ],
            cursor: 0,
        };

        segment.encode_to(&mut writable_shards);

        Self {
            shards: writable_shards.shards,
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
            .chunks_exact_mut(self.shard_size as usize / GF_16_ELEMENT_BYTES)
            .collect()
    }
}
