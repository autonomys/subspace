extern crate alloc;

use crate::archiver::{Segment, SegmentItem};
use crate::utils;
use alloc::vec::Vec;
use core::mem;
use parity_scale_codec::Decode;
use reed_solomon_erasure::galois_16::ReedSolomon;
use subspace_core_primitives::{
    ArchivedBlockProgress, BlockNumber, LastArchivedBlock, Piece, RootBlock, SegmentIndex,
};

/// Reconstructor-related instantiation error.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum ReconstructorInstantiationError {
    /// Segment size is not bigger than record size
    #[cfg_attr(
        feature = "thiserror",
        error("Segment size is not bigger than record size")
    )]
    SegmentSizeTooSmall,
    /// Segment size is not a multiple of record size
    #[cfg_attr(
        feature = "thiserror",
        error("Segment size is not a multiple of record size")
    )]
    SegmentSizesNotMultipleOfRecordSize,
}

/// Reconstructor-related instantiation error
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum ReconstructorError {
    /// Segment size is not bigger than record size
    #[cfg_attr(
        feature = "thiserror",
        error("Error during data shards reconstruction: {0}")
    )]
    DataShardsReconstruction(reed_solomon_erasure::Error),
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
    /// Root block stored in a segment
    pub root_block: Option<RootBlock>,
    /// Reconstructed encoded blocks with their block numbers
    pub blocks: Vec<(BlockNumber, Vec<u8>)>,
}

/// Reconstructor helps to retrieve blocks from archived pieces.
#[derive(Debug, Clone)]
pub struct Reconstructor {
    /// Configuration parameter defining the size of one record (data in one piece excluding witness
    /// size)
    record_size: u32,
    /// Configuration parameter defining the size of one recorded history segment
    segment_size: u32,
    /// Erasure coding data structure
    reed_solomon: ReedSolomon,
    /// Index of last segment added to reconstructor
    last_segment_index: Option<SegmentIndex>,
    /// Partially reconstructed block waiting for more data
    partial_block: Option<Vec<u8>>,
}

impl Reconstructor {
    pub fn new(
        record_size: u32,
        segment_size: u32,
    ) -> Result<Self, ReconstructorInstantiationError> {
        if segment_size <= record_size {
            return Err(ReconstructorInstantiationError::SegmentSizeTooSmall);
        }
        if segment_size % record_size != 0 {
            return Err(ReconstructorInstantiationError::SegmentSizesNotMultipleOfRecordSize);
        }

        let data_shards = segment_size / record_size;
        let parity_shards = data_shards;
        let reed_solomon = ReedSolomon::new(data_shards as usize, parity_shards as usize)
            .expect("ReedSolomon must always be correctly instantiated");

        Ok(Self {
            record_size,
            segment_size,
            reed_solomon,
            last_segment_index: None,
            partial_block: None,
        })
    }

    /// Given a set of pieces of a segment of the archived history (any half of all pieces are
    /// required to be present, the rest will be recovered automatically due to use of erasure
    /// coding if needed), reconstructs and returns root block and a list of encoded blocks with
    /// corresponding block numbers.
    ///
    /// It is possible to start with any segment, but when next segment is pushed, it needs to
    /// follow the previous one or else error will be returned.
    pub fn add_segment(
        &mut self,
        segment_pieces: &[Option<Piece>],
    ) -> Result<ReconstructedContents, ReconstructorError> {
        let mut segment_data = Vec::with_capacity(self.segment_size as usize);
        if !segment_pieces
            .iter()
            .take(self.reed_solomon.data_shard_count())
            .all(|maybe_piece| {
                if let Some(piece) = maybe_piece {
                    segment_data.extend_from_slice(&piece.record());
                    true
                } else {
                    false
                }
            })
        {
            // If not all data pieces are available, need to reconstruct data shards using erasure
            // coding.
            let mut shards = segment_pieces
                .iter()
                .map(|maybe_piece| maybe_piece.as_ref().map(utils::slice_to_arrays))
                .collect::<Vec<_>>();

            self.reed_solomon
                .reconstruct_data(&mut shards)
                .map_err(ReconstructorError::DataShardsReconstruction)?;

            segment_data.clear();
            shards
                .into_iter()
                .take(self.reed_solomon.data_shard_count())
                .for_each(|maybe_piece| {
                    let piece = maybe_piece.expect(
                        "All data shards are available after successful reconstruction; qed",
                    );

                    for chunk in piece.iter().take(self.record_size as usize / 2) {
                        segment_data.extend_from_slice(chunk.as_ref());
                    }
                });
        }

        let Segment::V0 { items } = Segment::decode(&mut segment_data.as_ref())
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
                SegmentItem::RootBlock(root_block) => {
                    let segment_index = root_block.segment_index();

                    if let Some(last_segment_index) = self.last_segment_index {
                        if last_segment_index != segment_index {
                            return Err(ReconstructorError::IncorrectSegmentOrder {
                                expected_segment_index: last_segment_index + 1,
                                actual_segment_index: segment_index + 1,
                            });
                        }
                    }

                    self.last_segment_index.replace(segment_index + 1);

                    let LastArchivedBlock {
                        number,
                        archived_progress,
                    } = root_block.last_archived_block();

                    reconstructed_contents.root_block.replace(root_block);

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
            self.last_segment_index.replace(0);
        }

        Ok(reconstructed_contents)
    }
}
