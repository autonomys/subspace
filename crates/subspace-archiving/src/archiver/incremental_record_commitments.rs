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
    processed: usize,
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
            // How many bytes to read before the start of the next record
            let bytes_until_full_record = self.bytes_until_full_record();
            if bytes_until_full_record > 0 {
                // This is fine since we'll have at most a few iterations and allocation is less
                // desirable than a loop here
                for _ in 0..bytes_until_full_record {
                    self.update_hashing_state(&[0]);
                }
                self.finish_hash();
            }
        }
    }
}

impl<'a> Output for IncrementalRecordCommitmentsProcessor<'a> {
    fn write(&mut self, bytes: &[u8]) {
        // Try to finish last partial record if possible
        let bytes = {
            let bytes_until_full_record =
                ((self.processed / self.record_size) + 1) * self.record_size - self.processed;
            let (remaining_record_bytes, bytes) =
                bytes.split_at(if bytes.len() >= bytes_until_full_record {
                    bytes_until_full_record
                } else {
                    bytes.len()
                });

            self.update_hashing_state(remaining_record_bytes);

            if remaining_record_bytes.len() == bytes_until_full_record {
                self.finish_hash();
            }

            bytes
        };

        // Continue processing records (full and partial) from remaining data
        bytes.chunks(self.record_size).for_each(|record| {
            self.update_hashing_state(record);

            // Store hashes of full records
            if record.len() == self.record_size {
                self.finish_hash();
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
            processed: 0,
            incremental_record_commitments,
            record_size,
            full,
            hashing_state: Blake2b::<U32>::default(),
        }
    }

    /// How many bytes to read before the start of the next record
    fn bytes_until_full_record(&self) -> usize {
        let bytes_to_next_record =
            ((self.processed / self.record_size) + 1) * self.record_size - self.processed;
        bytes_to_next_record % self.record_size
    }

    /// Whether commitment for current record needs to be created
    fn should_commit_to_record(&self, record_position: usize) -> bool {
        if self.full {
            // For full segment we need to create the first record and any that are not present yet
            record_position == 0
                || self
                    .incremental_record_commitments
                    .state
                    .get(record_position)
                    .is_none()
        } else {
            // For partial segment we need to skip the first record (it is not final) and generate
            // any other that are currently missing
            record_position
                .checked_sub(1)
                .map(|shifted_position| {
                    self.incremental_record_commitments
                        .state
                        .get(shifted_position)
                        .is_none()
                })
                .unwrap_or_default()
        }
    }

    /// In case commitment is necessary for currently processed record, internal hashing state will
    /// be updated with provided bytes.
    fn update_hashing_state(&mut self, bytes: &[u8]) {
        if self.should_commit_to_record(self.processed / self.record_size) {
            self.hashing_state.update(bytes);
        }
        self.processed += bytes.len();
    }

    /// In case commitment is necessary for currently processed record, internal hashing state will
    /// be finalized and commitment will be stored in shared state.
    fn finish_hash(&mut self) {
        if self.should_commit_to_record(self.processed / self.record_size - 1) {
            let hashing_state = mem::take(&mut self.hashing_state);

            let mut hash = Blake2b256Hash::from(hashing_state.finalize_fixed());
            // Erase last 2 bits to effectively truncate the hash (number is interpreted as
            // little-endian)
            hash[31] &= 0b00111111;

            // In case full segment was provided, the very first record should be processed and inserted
            // in front of everything
            if self.full && self.processed == self.record_size {
                self.incremental_record_commitments.state.push_front(hash);
            } else {
                self.incremental_record_commitments.state.push_back(hash);
            }
        }
    }
}
