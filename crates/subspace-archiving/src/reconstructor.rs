#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::archiver::{Segment, SegmentItem};
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::mem;
use parity_scale_codec::Decode;
use subspace_core_primitives::BlockNumber;
use subspace_core_primitives::pieces::{Piece, RawRecord};
use subspace_core_primitives::segments::{
    ArchivedBlockProgress, ArchivedHistorySegment, LastArchivedBlock, RecordedHistorySegment,
    SegmentHeader, SegmentIndex,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_kzg::Scalar;

/// Reconstructor-related instantiation error
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ReconstructorError {
    /// Error during data shards reconstruction
    #[error("Error during data shards reconstruction: {0}")]
    DataShardsReconstruction(String),
    /// Segment size is not bigger than record size
    #[error("Error during segment decoding: {0}")]
    SegmentDecoding(parity_scale_codec::Error),
    /// Incorrect segment order, each next segment must directly follow the previous one
    #[error(
        "Incorrect segment order, expected index {expected_segment_index}, actual \
        {actual_segment_index}"
    )]
    IncorrectSegmentOrder {
        expected_segment_index: SegmentIndex,
        actual_segment_index: SegmentIndex,
    },
    /// Parent segment header is not the first item of the segment
    #[error("Parent segment header is not the first item of the segment")]
    UnexpectedParentSegmentHeader,
    /// Segment index overflow, no segment can follow the segment with the maximum index
    #[error("Segment index overflow, no segment can follow the segment with the maximum index")]
    SegmentIndexOverflow,
    /// Block number overflow
    #[error("Block number overflow")]
    BlockNumberOverflow,
}

/// Data structure that contains information reconstructed from given segment (potentially using
/// information from segments that were added previously)
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ReconstructedContents {
    /// Segment header stored in a segment
    pub segment_header: Option<SegmentHeader>,
    /// Reconstructed encoded blocks with their block numbers
    pub blocks: Vec<(BlockNumber, Vec<u8>)>,
}

/// Reconstructor helps to retrieve blocks from archived pieces.
#[derive(Debug, Clone)]
pub struct Reconstructor {
    /// Erasure coding data structure
    erasure_coding: ErasureCoding,
    /// Index of last segment added to reconstructor
    last_segment_index: Option<SegmentIndex>,
    /// Partially reconstructed block waiting for more data, empty if there is none
    partial_block: Vec<u8>,
}

impl Reconstructor {
    /// Create a new instance
    pub fn new(erasure_coding: ErasureCoding) -> Self {
        Self {
            erasure_coding,
            last_segment_index: None,
            partial_block: Vec::new(),
        }
    }

    /// Given a set of pieces of a segment of the archived history (any half of all pieces are
    /// required to be present, the rest will be recovered automatically due to use of erasure
    /// coding if needed), reconstructs and returns the segment itself.
    ///
    /// Does not modify the internal state of the reconstructor.
    pub fn reconstruct_segment(
        &self,
        segment_pieces: &[Option<Piece>],
    ) -> Result<Segment, ReconstructorError> {
        let mut segment_data = RecordedHistorySegment::new_boxed();

        if !segment_pieces
            .iter()
            // Take each source shards here
            .step_by(2)
            .zip(segment_data.iter_mut())
            .all(|(maybe_piece, raw_record)| {
                if let Some(piece) = maybe_piece {
                    piece
                        .record()
                        .to_raw_record_chunks()
                        .zip(raw_record.iter_mut())
                        .for_each(|(source, target)| {
                            target.copy_from_slice(source);
                        });
                    true
                } else {
                    false
                }
            })
        {
            // If not all data pieces are available, need to reconstruct data shards using erasure
            // coding.

            // Scratch buffer to avoid re-allocation
            let mut tmp_shards_scalars =
                Vec::<Option<Scalar>>::with_capacity(ArchivedHistorySegment::NUM_PIECES);
            // Iterate over the chunks of `ScalarBytes::SAFE_BYTES` bytes of all records
            for record_offset in 0..RawRecord::NUM_CHUNKS {
                // Collect chunks of each record at the same offset
                for maybe_piece in segment_pieces.iter() {
                    let maybe_scalar = maybe_piece
                        .as_ref()
                        .map(|piece| {
                            piece
                                .record()
                                .get(record_offset)
                                .expect("Statically guaranteed to exist in a piece; qed")
                        })
                        .map(Scalar::try_from)
                        .transpose()
                        .map_err(ReconstructorError::DataShardsReconstruction)?;

                    tmp_shards_scalars.push(maybe_scalar);
                }

                self.erasure_coding
                    .recover(&tmp_shards_scalars)
                    .map_err(ReconstructorError::DataShardsReconstruction)?
                    .into_iter()
                    // Take each source shards here
                    .step_by(2)
                    .zip(segment_data.iter_mut().map(|raw_record| {
                        raw_record
                            .get_mut(record_offset)
                            .expect("Statically guaranteed to exist in a piece; qed")
                    }))
                    .for_each(|(source_scalar, segment_data)| {
                        segment_data.copy_from_slice(
                            &source_scalar
                                .try_to_safe_bytes()
                                .expect("Source scalar has only safe bytes; qed"),
                        );
                    });

                tmp_shards_scalars.clear();
            }
        }

        let segment = Segment::decode(&mut AsRef::<[u8]>::as_ref(segment_data.as_ref()))
            .map_err(ReconstructorError::SegmentDecoding)?;

        Ok(segment)
    }

    /// Given a set of pieces of a segment of the archived history (any half of all pieces are
    /// required to be present, the rest will be recovered automatically due to use of erasure
    /// coding if needed), reconstructs and returns segment header and a list of encoded blocks with
    /// corresponding block numbers.
    ///
    /// The reconstructor is consumed and returned together with reconstructed contents if the
    /// segment was added successfully. It is possible to start with any segment, but when next
    /// segment is pushed, it needs to follow the previous one or else error will be returned.
    pub fn add_segment(
        mut self,
        segment_pieces: &[Option<Piece>],
    ) -> Result<(Self, ReconstructedContents), ReconstructorError> {
        let mut segment_items = self
            .reconstruct_segment(segment_pieces)?
            .into_items()
            .into_iter()
            .peekable();

        let mut reconstructed_contents = ReconstructedContents::default();
        let mut next_block_number: BlockNumber = 0;

        // Only the first segment has no parent segment header, all other segments start with it
        let segment_index = if let Some(&SegmentItem::ParentSegmentHeader(parent_segment_header)) =
            segment_items.peek()
        {
            segment_items.next();

            let LastArchivedBlock {
                number,
                archived_progress,
            } = parent_segment_header.last_archived_block();

            reconstructed_contents
                .segment_header
                .replace(parent_segment_header);

            match archived_progress {
                ArchivedBlockProgress::Complete => {
                    // The last archived block ended exactly with the previous segment, so if its
                    // beginning was reconstructed from previous segments, it is complete now
                    if !self.partial_block.is_empty() {
                        reconstructed_contents
                            .blocks
                            .push((number, mem::take(&mut self.partial_block)));
                    }

                    next_block_number = number
                        .checked_add(1)
                        .ok_or(ReconstructorError::BlockNumberOverflow)?;
                }
                ArchivedBlockProgress::Partial(_bytes) => {
                    next_block_number = number;

                    if self.partial_block.is_empty() {
                        // Will not be able to recover full block, bump right away
                        next_block_number = next_block_number
                            .checked_add(1)
                            .ok_or(ReconstructorError::BlockNumberOverflow)?;
                    }
                }
            }

            parent_segment_header
                .segment_index()
                .checked_add(SegmentIndex::ONE)
                .ok_or(ReconstructorError::SegmentIndexOverflow)?
        } else {
            SegmentIndex::ZERO
        };

        if let Some(last_segment_index) = self.last_segment_index {
            let expected_segment_index = last_segment_index
                .checked_add(SegmentIndex::ONE)
                .ok_or(ReconstructorError::SegmentIndexOverflow)?;

            if segment_index != expected_segment_index {
                return Err(ReconstructorError::IncorrectSegmentOrder {
                    expected_segment_index,
                    actual_segment_index: segment_index,
                });
            }
        }

        self.last_segment_index.replace(segment_index);

        for segment_item in segment_items {
            match segment_item {
                SegmentItem::Padding => {
                    // Doesn't contain anything
                }
                SegmentItem::Block { bytes, .. } => {
                    if !self.partial_block.is_empty() {
                        reconstructed_contents
                            .blocks
                            .push((next_block_number, mem::take(&mut self.partial_block)));

                        next_block_number = next_block_number
                            .checked_add(1)
                            .ok_or(ReconstructorError::BlockNumberOverflow)?;
                    }

                    reconstructed_contents
                        .blocks
                        .push((next_block_number, bytes));

                    next_block_number = next_block_number
                        .checked_add(1)
                        .ok_or(ReconstructorError::BlockNumberOverflow)?;
                }
                SegmentItem::BlockStart { bytes, .. } => {
                    if !self.partial_block.is_empty() {
                        reconstructed_contents
                            .blocks
                            .push((next_block_number, mem::take(&mut self.partial_block)));

                        next_block_number = next_block_number
                            .checked_add(1)
                            .ok_or(ReconstructorError::BlockNumberOverflow)?;
                    }

                    self.partial_block = bytes;
                }
                SegmentItem::BlockContinuation { bytes, .. } => {
                    if self.partial_block.is_empty() {
                        // This is continuation from previous segment, we don't have the beginning
                        // of the block to continue.
                        continue;
                    }

                    self.partial_block.extend_from_slice(&bytes);
                }
                SegmentItem::ParentSegmentHeader(_) => {
                    return Err(ReconstructorError::UnexpectedParentSegmentHeader);
                }
            }
        }

        Ok((self, reconstructed_contents))
    }
}
