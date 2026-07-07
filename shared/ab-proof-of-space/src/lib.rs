//! Proof of space implementation
#![no_std]
#![expect(incomplete_features, reason = "generic_const_exprs")]
#![warn(rust_2018_idioms, missing_debug_implementations, missing_docs)]
#![feature(
    const_block_items,
    const_convert,
    const_trait_impl,
    generic_const_exprs,
    step_trait
)]
#![cfg_attr(test, feature(float_erf))]
#![cfg_attr(feature = "parallel", feature(exact_size_is_empty, sync_unsafe_cell))]
#![cfg_attr(feature = "alloc", feature(maybe_uninit_fill, ptr_as_uninit))]
#![cfg_attr(any(feature = "alloc", test), feature(portable_simd))]

pub mod chiapos;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use subspace_core_primitives::pieces::Record;
#[cfg(feature = "alloc")]
use subspace_core_primitives::pos::PosProof;
#[cfg(feature = "alloc")]
use subspace_core_primitives::sectors::SBucket;

// TODO: Return a single full proof and the rest as hashes instead to optimize memory usage and
//  parallelize compute more easily
/// Proof-of-space proofs
#[derive(Debug)]
#[cfg(feature = "alloc")]
#[repr(C)]
pub struct PosProofs {
    /// S-buckets at which proofs were found.
    ///
    /// S-buckets are grouped by 8, within each `u8` bits right to left (LSB) indicate the presence
    /// of a proof for corresponding s-bucket, so that the whole array of bytes can be thought as a
    /// large set of bits.
    ///
    /// There will be at most [`Record::NUM_CHUNKS`] proofs produced/bits set to `1`.
    pub found_proofs: [u8; Record::NUM_S_BUCKETS / u8::BITS as usize],
    /// [`Record::NUM_CHUNKS`] proofs, corresponding to set bits of `found_proofs`.
    pub proofs: [PosProof; Record::NUM_CHUNKS],
}

// TODO: A method that returns hashed proofs (with SIMD) for all s-buckets for plotting
#[cfg(feature = "alloc")]
impl PosProofs {
    /// Get proof for specified s-bucket (if exists).
    ///
    /// Note that this is not the most efficient API possible, so prefer using the `proofs` field
    /// directly if the use case allows.
    #[inline]
    pub fn for_s_bucket(&self, s_bucket: SBucket) -> Option<PosProof> {
        let proof_index = Self::proof_index_for_s_bucket(&self.found_proofs, s_bucket)?;

        Some(self.proofs[proof_index])
    }

    #[inline(always)]
    fn proof_index_for_s_bucket(
        found_proofs: &[u8; Record::NUM_S_BUCKETS / u8::BITS as usize],
        s_bucket: SBucket,
    ) -> Option<usize> {
        let bits_offset = usize::from(s_bucket);
        let found_proofs_byte_offset = bits_offset / u8::BITS as usize;
        let found_proofs_bit_offset = bits_offset as u32 % u8::BITS;
        let (found_proofs_before, found_proofs_after) =
            found_proofs.split_at(found_proofs_byte_offset);
        if (found_proofs_after[0] & (1 << found_proofs_bit_offset)) == 0 {
            return None;
        }
        let proof_index = found_proofs_before
            .iter()
            .map(|&bits| bits.count_ones())
            .sum::<u32>()
            + found_proofs_after[0]
                .unbounded_shl(u8::BITS - found_proofs_bit_offset)
                .count_ones();

        Some(proof_index as usize)
    }
}
