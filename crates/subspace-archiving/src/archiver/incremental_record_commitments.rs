extern crate alloc;

use crate::archiver::Segment;
use alloc::collections::VecDeque;
use blake2::digest::typenum::U32;
use blake2::digest::{FixedOutput, Update};
use blake2::Blake2b;
use core::mem;
use parity_scale_codec::{Encode, Output};
use subspace_core_primitives::Blake2b256Hash;

/// State of incremental record commitments, encapsulated to hide implementation details and
/// encapsulate tricky logic
#[derive(Debug, Default, Clone)]
pub(super) struct IncrementalRecordCommitmentsState {
    /// State contains record commitments.
    ///
    /// NOTE: Until full segment is processed, this will not contain commitment to the first record
    /// since it is not ready yet. This in turn means all commitments will be at `-1` offset.
    state: VecDeque<Blake2b256Hash>,
}

impl IncrementalRecordCommitmentsState {
    /// Creates an empty state with space for at least capacity records.
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            state: VecDeque::with_capacity(capacity),
        }
    }

    pub(super) fn drain(&mut self) -> impl Iterator<Item = Blake2b256Hash> + '_ {
        self.state.drain(..)
    }
}

/// Update internal record commitments state based on (full or partial) segment.
pub(super) fn update_record_commitments(
    incremental_record_commitments: &mut IncrementalRecordCommitmentsState,
    segment: &Segment,
    full: bool,
    record_size: usize,
) {
    segment.encode_to(&mut IncrementalRecordCommitmentsProcessor::new(
        incremental_record_commitments,
        record_size,
        full,
    ));
}

/// Processor is hidden to not expose unnecessary implementation details (like `Output` trait
/// implementation)
struct IncrementalRecordCommitmentsProcessor<'a> {
    /// Processed bytes in the segment so far
    processed_bytes: usize,
    /// Record commitments already created
    incremental_record_commitments: &'a mut IncrementalRecordCommitmentsState,
    /// Record size
    record_size: usize,
    /// Whether segment is full or partial
    full: bool,
    /// Intermediate hashing state that computes Blake2-256-254.
    ///
    /// See [`subspace_core_primitives::crypto::blake2b_256_254_hash`] for details.
    hashing_state: Blake2b<U32>,
}

impl<'a> Drop for IncrementalRecordCommitmentsProcessor<'a> {
    fn drop(&mut self) {
        if self.full {
            let record_offset = self.processed_bytes % self.record_size;
            if record_offset > 0 {
                // This is fine since we'll have at most a few iterations and allocation is less
                // desirable than a loop here
                for _ in 0..(self.record_size - record_offset) {
                    self.update_commitment_state(&[0]);
                }
                self.create_commitment();
            }
        }
    }
}

impl<'a> Output for IncrementalRecordCommitmentsProcessor<'a> {
    fn write(&mut self, mut bytes: &[u8]) {
        // Try to finish last partial record if possible

        let record_offset = self.processed_bytes % self.record_size;
        let bytes_left_in_record = self.record_size - record_offset;
        if bytes_left_in_record > 0 {
            let remaining_record_bytes;
            (remaining_record_bytes, bytes) =
                bytes.split_at(if bytes.len() >= bytes_left_in_record {
                    bytes_left_in_record
                } else {
                    bytes.len()
                });

            self.update_commitment_state(remaining_record_bytes);

            if remaining_record_bytes.len() == bytes_left_in_record {
                self.create_commitment();
            }
        }

        // Continue processing records (full and partial) from remaining data, at this point we have
        // processed some number of full records, so can simply chunk the remaining bytes into
        // record sizes
        bytes.chunks(self.record_size).for_each(|record| {
            self.update_commitment_state(record);

            // Store hashes of full records
            if record.len() == self.record_size {
                self.create_commitment();
            }
        });
    }
}

impl<'a> IncrementalRecordCommitmentsProcessor<'a> {
    fn new(
        incremental_record_commitments: &'a mut IncrementalRecordCommitmentsState,
        record_size: usize,
        full: bool,
    ) -> Self {
        Self {
            processed_bytes: 0,
            incremental_record_commitments,
            record_size,
            full,
            hashing_state: Blake2b::<U32>::default(),
        }
    }

    /// Whether commitment for current record needs to be created
    fn should_commit_to_record(&self, record_position: usize) -> bool {
        self.incremental_record_commitments
            .state
            .get(record_position)
            .is_none()
    }

    /// In case commitment is necessary for currently processed record, internal commitment state
    /// will be updated with provided bytes.
    ///
    /// NOTE: This method is called with bytes that either cover part of the record or stop at the
    /// edge of the record.
    fn update_commitment_state(&mut self, bytes: &[u8]) {
        if self.should_commit_to_record(self.processed_bytes / self.record_size) {
            self.hashing_state.update(bytes);
        }
        self.processed_bytes += bytes.len();
    }

    /// In case commitment is necessary for currently processed record, internal hashing state will
    /// be finalized and commitment will be stored in shared state.
    fn create_commitment(&mut self) {
        if self.should_commit_to_record(self.processed_bytes / self.record_size - 1) {
            let hashing_state = mem::take(&mut self.hashing_state);

            let mut hash = Blake2b256Hash::from(hashing_state.finalize_fixed());
            // Erase last 2 bits to effectively truncate the hash (number is interpreted as
            // little-endian)
            hash[31] &= 0b00111111;

            self.incremental_record_commitments.state.push_back(hash);
        }
    }
}
