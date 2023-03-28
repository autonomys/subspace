extern crate alloc;

use crate::archiver::Segment;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use parity_scale_codec::{Encode, Output};
use subspace_core_primitives::crypto::kzg::{Commitment, Kzg};
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::RawRecord;

/// State of incremental record commitments, encapsulated to hide implementation details and
/// encapsulate tricky logic
#[derive(Debug, Default, Clone)]
pub(super) struct IncrementalRecordCommitmentsState {
    /// State contains record commitments.
    ///
    /// NOTE: Until full segment is processed, this will not contain commitment to the first record
    /// since it is not ready yet. This in turn means all commitments will be at `-1` offset.
    state: VecDeque<Commitment>,
}

impl IncrementalRecordCommitmentsState {
    /// Creates an empty state with space for at least capacity records.
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            state: VecDeque::with_capacity(capacity),
        }
    }

    pub(super) fn drain(&mut self) -> impl Iterator<Item = Commitment> + '_ {
        self.state.drain(..)
    }
}

/// Update internal record commitments state based on (full or partial) segment.
pub(super) fn update_record_commitments(
    incremental_record_commitments: &mut IncrementalRecordCommitmentsState,
    segment: &Segment,
    kzg: &Kzg,
    full: bool,
) {
    segment.encode_to(&mut IncrementalRecordCommitmentsProcessor::new(
        incremental_record_commitments,
        kzg,
        full,
    ));
}

/// Processor is hidden to not expose unnecessary implementation details (like `Output` trait
/// implementation)
struct IncrementalRecordCommitmentsProcessor<'a> {
    /// Processed bytes in the segment so far
    processed_bytes: usize,
    /// Buffer where current (partial) record is written
    raw_record_buffer: Vec<u8>,
    /// Record commitments already created
    incremental_record_commitments: &'a mut IncrementalRecordCommitmentsState,
    /// Kzg instance used for commitments creation
    kzg: &'a Kzg,
    /// Whether segment is full or partial
    full: bool,
}

impl<'a> Drop for IncrementalRecordCommitmentsProcessor<'a> {
    fn drop(&mut self) {
        if self.full {
            let record_offset = self.processed_bytes % RawRecord::SIZE;
            if record_offset > 0 {
                // This is fine since we'll have at most a few iterations and allocation is less
                // desirable than a loop here
                for _ in 0..(RawRecord::SIZE - record_offset) {
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

        let record_offset = self.processed_bytes % RawRecord::SIZE;
        let bytes_left_in_record = RawRecord::SIZE - record_offset;
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
        bytes.chunks(RawRecord::SIZE).for_each(|record| {
            self.update_commitment_state(record);

            // Store hashes of full records
            if record.len() == RawRecord::SIZE {
                self.create_commitment();
            }
        });
    }
}

impl<'a> IncrementalRecordCommitmentsProcessor<'a> {
    fn new(
        incremental_record_commitments: &'a mut IncrementalRecordCommitmentsState,
        kzg: &'a Kzg,
        full: bool,
    ) -> Self {
        Self {
            // TODO: Remove `processed_bytes`, `raw_record_buffer` should be sufficient
            processed_bytes: 0,
            raw_record_buffer: Vec::with_capacity(RawRecord::SIZE),
            incremental_record_commitments,
            kzg,
            full,
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
        if self.should_commit_to_record(self.processed_bytes / RawRecord::SIZE) {
            self.raw_record_buffer.extend_from_slice(bytes);
        }
        self.processed_bytes += bytes.len();
    }

    /// In case commitment is necessary for currently processed record, internal hashing state will
    /// be finalized and commitment will be stored in shared state.
    fn create_commitment(&mut self) {
        if self.should_commit_to_record(self.processed_bytes / RawRecord::SIZE - 1) {
            let scalars = {
                let record_chunks = self
                    .raw_record_buffer
                    .array_chunks::<{ Scalar::SAFE_BYTES }>();
                let number_of_chunks = record_chunks.len();
                let mut scalars = Vec::with_capacity(number_of_chunks.next_power_of_two());

                record_chunks.map(Scalar::from).collect_into(&mut scalars);

                // Number of scalars for KZG must be a power of two elements
                scalars.resize(scalars.capacity(), Scalar::default());

                scalars
            };
            self.raw_record_buffer.clear();

            let polynomial = self
                .kzg
                .poly(&scalars)
                .expect("KZG instance must be configured to support this many scalars; qed");
            let commitment = self
                .kzg
                .commit(&polynomial)
                .expect("KZG instance must be configured to support this many scalars; qed");

            self.incremental_record_commitments
                .state
                .push_back(commitment);
        }
    }
}
