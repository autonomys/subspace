#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::archiver::Segment;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use parity_scale_codec::{Encode, Output};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use subspace_core_primitives::pieces::RawRecord;
use subspace_core_primitives::ScalarBytes;
use subspace_kzg::{Commitment, Kzg, Scalar};

/// State of incremental record commitments, encapsulated to hide implementation details and
/// encapsulate tricky logic
#[derive(Debug, Default, Clone)]
pub(super) struct IncrementalRecordCommitmentsState {
    /// State contains record commitments.
    ///
    /// NOTE: Until full segment is processed, this will not contain commitment to the first record
    /// since it is not ready yet. This in turn means all commitments will be at `-1` offset.
    state: Vec<Commitment>,
}

impl Deref for IncrementalRecordCommitmentsState {
    type Target = Vec<Commitment>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl DerefMut for IncrementalRecordCommitmentsState {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

impl IncrementalRecordCommitmentsState {
    /// Creates an empty state with space for at least capacity records.
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            state: Vec::with_capacity(capacity),
        }
    }

    /// Clears internal state before start of the next segment
    pub(super) fn clear(&mut self) {
        self.state.clear();
    }
}

/// Update internal record commitments state based on provided segment.
pub(super) fn update_record_commitments(
    incremental_record_commitments: &mut IncrementalRecordCommitmentsState,
    segment: &Segment,
    kzg: &Kzg,
) {
    segment.encode_to(&mut IncrementalRecordCommitmentsProcessor::new(
        incremental_record_commitments,
        kzg,
    ));
}

/// Processor is hidden to not expose unnecessary implementation details (like `Output` trait
/// implementation)
struct IncrementalRecordCommitmentsProcessor<'a> {
    /// Number of bytes of recorded history segment for which commitments were already created
    skip_bytes: usize,
    /// Buffer where new bytes for which commitments need to be created are pushed
    buffer: Vec<u8>,
    /// Record commitments already created
    incremental_record_commitments: &'a mut IncrementalRecordCommitmentsState,
    /// Kzg instance used for commitments creation
    kzg: &'a Kzg,
}

impl<'a> Drop for IncrementalRecordCommitmentsProcessor<'a> {
    fn drop(&mut self) {
        #[cfg(not(feature = "parallel"))]
        let raw_records_bytes = self.buffer.chunks_exact(RawRecord::SIZE);
        #[cfg(feature = "parallel")]
        let raw_records_bytes = self.buffer.par_chunks_exact(RawRecord::SIZE);

        let iter = raw_records_bytes
            .map(|raw_record_bytes| {
                raw_record_bytes
                    .array_chunks::<{ ScalarBytes::SAFE_BYTES }>()
                    .map(Scalar::from)
            })
            .map(|record_chunks| {
                let number_of_chunks = record_chunks.len();
                let mut scalars = Vec::with_capacity(number_of_chunks.next_power_of_two());

                record_chunks.collect_into(&mut scalars);

                // Number of scalars for KZG must be a power of two elements
                scalars.resize(scalars.capacity(), Scalar::default());

                let polynomial = self
                    .kzg
                    .poly(&scalars)
                    .expect("KZG instance must be configured to support this many scalars; qed");
                self.kzg
                    .commit(&polynomial)
                    .expect("KZG instance must be configured to support this many scalars; qed")
            });

        #[cfg(not(feature = "parallel"))]
        iter.collect_into(&mut self.incremental_record_commitments.state);
        // TODO: `collect_into_vec()`, unfortunately, truncates input, which is not what we want
        //  can be unified when https://github.com/rayon-rs/rayon/issues/1039 is resolved
        #[cfg(feature = "parallel")]
        self.incremental_record_commitments.par_extend(iter);
    }
}

impl<'a> Output for IncrementalRecordCommitmentsProcessor<'a> {
    fn write(&mut self, mut bytes: &[u8]) {
        if self.skip_bytes >= bytes.len() {
            self.skip_bytes -= bytes.len();
        } else {
            bytes = &bytes[self.skip_bytes..];
            self.skip_bytes = 0;
            self.buffer.extend_from_slice(bytes);
        }
    }
}

impl<'a> IncrementalRecordCommitmentsProcessor<'a> {
    fn new(
        incremental_record_commitments: &'a mut IncrementalRecordCommitmentsState,
        kzg: &'a Kzg,
    ) -> Self {
        Self {
            skip_bytes: incremental_record_commitments.len() * RawRecord::SIZE,
            // Default to record size, may grow if necessary
            buffer: Vec::with_capacity(RawRecord::SIZE),
            incremental_record_commitments,
            kzg,
        }
    }
}
