extern crate alloc;

use crate::archiver::{Segment, SegmentItem};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem;
use core::num::NonZeroUsize;
use parity_scale_codec::Decode;
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::{
    ArchivedBlockProgress, BlockNumber, LastArchivedBlock, Piece, RawRecord,
    RecordedHistorySegment, SegmentHeader, SegmentIndex, PIECES_IN_SEGMENT,
};
use subspace_erasure_coding::ErasureCoding;

/// Reconstructor-related instantiation error.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum ReconstructorInstantiationError {
    /// Failed to initialize erasure coding
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to initialize erasure coding: {0}")
    )]
    FailedToInitializeErasureCoding(String),
}

/// Reconstructor-related instantiation error
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum ReconstructorError {
    /// Error during data shards reconstruction
    #[cfg_attr(
        feature = "thiserror",
        error("Error during data shards reconstruction: {0}")
    )]
    DataShardsReconstruction(String),
    /// Segment size is not bigger than record size
    #[cfg_attr(feature = "thiserror", error("Error during segment decoding: {0}"))]
    SegmentDecoding(parity_scale_codec::Error),
    /// Incorrect segment order, each next segment must have monotonically increasing segment index
    #[cfg_attr(
        feature = "thiserror",
        error("Incorrect segment order, expected index {expected_segment_index}, actual {actual_segment_index}")
    )]
    IncorrectSegmentOrder {
        expected_segment_index: SegmentIndex,
        actual_segment_index: SegmentIndex,
    },
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
    /// Partially reconstructed block waiting for more data
    partial_block: Option<Vec<u8>>,
}

impl Reconstructor {
    pub fn new() -> Result<Self, ReconstructorInstantiationError> {
        // TODO: Check if KZG can process number configured number of elements and update proof
        //  message in `.expect()`

        let erasure_coding = ErasureCoding::new(
            NonZeroUsize::new(PIECES_IN_SEGMENT.ilog2() as usize)
                .expect("Recorded history segment contains at very least one record; qed"),
        )
        .map_err(ReconstructorInstantiationError::FailedToInitializeErasureCoding)?;

        Ok(Self {
            erasure_coding,
            last_segment_index: None,
            partial_block: None,
        })
    }

    /// Given a set of pieces of a segment of the archived history (any half of all pieces are
    /// required to be present, the rest will be recovered automatically due to use of erasure
    /// coding if needed), reconstructs and returns segment header and a list of encoded blocks with
    /// corresponding block numbers.
    ///
    /// It is possible to start with any segment, but when next segment is pushed, it needs to
    /// follow the previous one or else error will be returned.
    pub fn add_segment(
        &mut self,
        segment_pieces: &[Option<Piece>],
    ) -> Result<ReconstructedContents, ReconstructorError> {
        // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
        // SAFETY: Data structure filled with zeroes is a valid invariant
        let mut segment_data = unsafe { Box::<RecordedHistorySegment>::new_zeroed().assume_init() };

        if !segment_pieces
            .iter()
            // Take each source shards here
            .step_by(2)
            .zip(segment_data.iter_mut())
            .all(|(maybe_piece, raw_record)| {
                if let Some(piece) = maybe_piece {
                    piece
                        .record()
                        .safe_scalar_arrays()
                        .zip(raw_record.iter_mut())
                        .for_each(|(source, target)| {
                            *target = *source;
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
                Vec::<Option<Scalar>>::with_capacity(PIECES_IN_SEGMENT as usize);
            // Iterate over the chunks of `Scalar::SAFE_BYTES` bytes of all records
            for record_offset in 0..RawRecord::SIZE / Scalar::SAFE_BYTES {
                // Collect chunks of each record at the same offset
                for maybe_piece in segment_pieces.iter() {
                    let maybe_scalar = maybe_piece
                        .as_ref()
                        .map(|piece| {
                            piece
                                .record()
                                .full_scalar_arrays()
                                .nth(record_offset)
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
                            .iter_mut()
                            .nth(record_offset)
                            .expect("Statically guaranteed to exist in a piece; qed")
                    }))
                    .for_each(|(source_scalar, segment_data)| {
                        // Source scalar only contains payload data within first
                        // [`Scalar::SAFE_BYTES`]
                        segment_data
                            .copy_from_slice(&source_scalar.to_bytes()[..Scalar::SAFE_BYTES]);
                    });

                tmp_shards_scalars.clear();
            }
        }

        let Segment::V0 { items } =
            Segment::decode(&mut AsRef::<[u8]>::as_ref(segment_data.as_ref()))
                .map_err(ReconstructorError::SegmentDecoding)?;

        let mut reconstructed_contents = ReconstructedContents::default();
        let mut next_block_number = 0;
        let mut partial_block = self.partial_block.take().unwrap_or_default();

        for segment_item in items {
            match segment_item {
                SegmentItem::Padding => {
                    // Doesn't contain anything
                }
                SegmentItem::Block { bytes, .. } => {
                    if !partial_block.is_empty() {
                        reconstructed_contents
                            .blocks
                            .push((next_block_number, mem::take(&mut partial_block)));

                        next_block_number += 1;
                    }

                    reconstructed_contents
                        .blocks
                        .push((next_block_number, bytes));

                    next_block_number += 1;
                }
                SegmentItem::BlockStart { bytes, .. } => {
                    if !partial_block.is_empty() {
                        reconstructed_contents
                            .blocks
                            .push((next_block_number, mem::take(&mut partial_block)));

                        next_block_number += 1;
                    }

                    partial_block = bytes;
                }
                SegmentItem::BlockContinuation { bytes, .. } => {
                    if partial_block.is_empty() {
                        // This is continuation from previous segment, we don't have the beginning
                        // of the block to continue.
                        continue;
                    }

                    partial_block.extend_from_slice(&bytes);
                }
                SegmentItem::ParentSegmentHeader(segment_header) => {
                    let segment_index = segment_header.segment_index();

                    if let Some(last_segment_index) = self.last_segment_index {
                        if last_segment_index != segment_index {
                            return Err(ReconstructorError::IncorrectSegmentOrder {
                                expected_segment_index: last_segment_index + SegmentIndex::ONE,
                                actual_segment_index: segment_index + SegmentIndex::ONE,
                            });
                        }
                    }

                    self.last_segment_index
                        .replace(segment_index + SegmentIndex::ONE);

                    let LastArchivedBlock {
                        number,
                        archived_progress,
                    } = segment_header.last_archived_block();

                    reconstructed_contents
                        .segment_header
                        .replace(segment_header);

                    match archived_progress {
                        ArchivedBlockProgress::Complete => {
                            reconstructed_contents
                                .blocks
                                .push((next_block_number, mem::take(&mut partial_block)));

                            next_block_number = number + 1;
                        }
                        ArchivedBlockProgress::Partial(_bytes) => {
                            next_block_number = number;

                            if partial_block.is_empty() {
                                // Will not be able to recover full block, bump right away.
                                next_block_number += 1;
                            }
                        }
                    }
                }
            }
        }

        if !partial_block.is_empty() {
            self.partial_block.replace(partial_block);
        }

        if self.last_segment_index.is_none() {
            self.last_segment_index.replace(SegmentIndex::ZERO);
        }

        Ok(reconstructed_contents)
    }
}
