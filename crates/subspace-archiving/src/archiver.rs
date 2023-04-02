// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod incremental_record_commitments;

extern crate alloc;

use crate::archiver::incremental_record_commitments::{
    update_record_commitments, IncrementalRecordCommitmentsState,
};
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::num::NonZeroUsize;
use parity_scale_codec::{Compact, CompactLen, Decode, Encode, Input, Output};
#[cfg(feature = "rayon")]
use rayon::prelude::*;
use subspace_core_primitives::crypto::kzg::{Kzg, Witness};
use subspace_core_primitives::crypto::{blake2b_256_254_hash_to_scalar, Scalar};
use subspace_core_primitives::objects::{
    BlockObject, BlockObjectMapping, PieceObject, PieceObjectMapping,
};
use subspace_core_primitives::{
    ArchivedBlockProgress, ArchivedHistorySegment, Blake2b256Hash, BlockNumber, LastArchivedBlock,
    PieceArray, RawRecord, RecordedHistorySegment, SegmentCommitment, SegmentHeader, SegmentIndex,
};
use subspace_erasure_coding::ErasureCoding;

const INITIAL_LAST_ARCHIVED_BLOCK: LastArchivedBlock = LastArchivedBlock {
    number: 0,
    // Special case for the genesis block.
    //
    // When we start archiving process with pre-genesis objects, we do not yet have any blocks
    // archived, but `LastArchivedBlock` is required for `SegmentHeader`s to be produced, so
    // `ArchivedBlockProgress::Partial(0)` indicates that we have archived 0 bytes of block `0` (see
    // field above), meaning we did not in fact archive actual blocks yet.
    archived_progress: ArchivedBlockProgress::Partial(0),
};

/// Segment represents a collection of items stored in archival history of the Subspace blockchain
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Segment {
    // V0 of the segment data structure
    V0 {
        /// Segment items
        items: Vec<SegmentItem>,
    },
}

impl Encode for Segment {
    fn size_hint(&self) -> usize {
        RecordedHistorySegment::SIZE
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        match self {
            Segment::V0 { items } => {
                dest.push_byte(0);
                for item in items {
                    item.encode_to(dest);
                }
            }
        }
    }
}

impl Decode for Segment {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let variant = input
            .read_byte()
            .map_err(|e| e.chain("Could not decode `Segment`, failed to read variant byte"))?;
        match variant {
            0 => {
                let mut items = Vec::new();
                loop {
                    match input.remaining_len()? {
                        Some(0) => {
                            break;
                        }
                        Some(_) => {
                            // Processing continues below
                        }
                        None => {
                            return Err(
                                "Source doesn't report remaining length, decoding not possible"
                                    .into(),
                            );
                        }
                    }

                    match SegmentItem::decode(input) {
                        Ok(item) => {
                            items.push(item);
                        }
                        Err(error) => {
                            return Err(error.chain("Could not decode `Segment::V0::items`"));
                        }
                    }
                }

                Ok(Segment::V0 { items })
            }
            _ => Err("Could not decode `Segment`, variant doesn't exist".into()),
        }
    }
}

impl Segment {
    fn push_item(&mut self, segment_item: SegmentItem) {
        let Self::V0 { items } = self;
        items.push(segment_item);
    }

    fn pop_item(&mut self) -> Option<SegmentItem> {
        let Self::V0 { items } = self;
        items.pop()
    }
}

/// Kinds of items that are contained within a segment
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub enum SegmentItem {
    /// Special dummy enum variant only used as an implementation detail for padding purposes
    #[codec(index = 0)]
    Padding,
    /// Contains full block inside
    #[codec(index = 1)]
    Block {
        /// Block bytes
        bytes: Vec<u8>,
        /// This is a convenience implementation detail and will not be available on decoding
        #[doc(hidden)]
        #[codec(skip)]
        object_mapping: BlockObjectMapping,
    },
    /// Contains the beginning of the block inside, remainder will be found in subsequent segments
    #[codec(index = 2)]
    BlockStart {
        /// Block bytes
        bytes: Vec<u8>,
        /// This is a convenience implementation detail and will not be available on decoding
        #[doc(hidden)]
        #[codec(skip)]
        object_mapping: BlockObjectMapping,
    },
    /// Continuation of the partial block spilled over into the next segment
    #[codec(index = 3)]
    BlockContinuation {
        /// Block bytes
        bytes: Vec<u8>,
        /// This is a convenience implementation detail and will not be available on decoding
        #[doc(hidden)]
        #[codec(skip)]
        object_mapping: BlockObjectMapping,
    },
    /// Segment header of the parent
    #[codec(index = 4)]
    ParentSegmentHeader(SegmentHeader),
}

/// Newly archived segment as a combination of segment header hash, segment index and corresponding
/// archived history segment containing pieces
#[derive(Debug, Clone, Eq, PartialEq, Decode, Encode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct NewArchivedSegment {
    /// Segment header
    pub segment_header: SegmentHeader,
    /// Segment of archived history containing pieces
    pub pieces: ArchivedHistorySegment,
    /// Mappings for objects stored in corresponding pieces.
    ///
    /// NOTE: Only half (source pieces) will have corresponding mapping item in this `Vec`.
    pub object_mapping: Vec<PieceObjectMapping>,
}

/// Archiver instantiation error
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum ArchiverInstantiationError {
    /// Failed to initialize erasure coding
    #[cfg_attr(
        feature = "thiserror",
        error("Failed to initialize erasure coding: {0}")
    )]
    FailedToInitializeErasureCoding(String),
    /// Invalid last archived block, its size is the same as encoded block
    #[cfg_attr(
        feature = "thiserror",
        error("Invalid last archived block, its size {0} bytes is the same as encoded block")
    )]
    InvalidLastArchivedBlock(BlockNumber),
    /// Invalid block, its size is smaller than already archived number of bytes
    #[cfg_attr(
        feature = "thiserror",
        error("Invalid block, its size {block_bytes} bytes is smaller than already archived {archived_block_bytes} bytes")
    )]
    InvalidBlockSmallSize {
        /// Full block size
        block_bytes: u32,
        /// Already archived portion of the block
        archived_block_bytes: u32,
    },
}

/// Block archiver for Subspace blockchain.
///
/// It takes new confirmed (at `K` depth) blocks and concatenates them into a buffer, buffer is
/// sliced into segments of [`RecordedHistorySegment::SIZE`] size, segments are sliced into source
/// records of [`RawRecord::SIZE`], records are erasure coded, committed to with [`Kzg`], then
/// commitments with witnesses are appended and records become pieces that are returned alongside
/// corresponding segment header header.
///
/// ## Panics
/// Panics when operating on blocks, whose length doesn't fit into u32 (should never be the case in
/// blockchain context anyway).
#[derive(Debug, Clone)]
pub struct Archiver {
    /// Buffer containing blocks and other buffered items that are pending to be included into the
    /// next segment
    buffer: VecDeque<SegmentItem>,
    /// Intermediate record commitments that are built incrementally as above buffer fills up.
    incremental_record_commitments: IncrementalRecordCommitmentsState,
    /// Erasure coding data structure
    erasure_coding: ErasureCoding,
    /// KZG instance
    kzg: Kzg,
    /// An index of the current segment
    segment_index: SegmentIndex,
    /// Hash of the segment header of the previous segment
    prev_segment_header_hash: Blake2b256Hash,
    /// Last archived block
    last_archived_block: LastArchivedBlock,
}

impl Archiver {
    /// Create a new instance with specified record size and recorded history segment size.
    ///
    /// Note: this is the only way to instantiate object archiver, while block archiver can be
    /// instantiated with `BlockArchiver::with_initial_state()` in case of restarts.
    pub fn new(kzg: Kzg) -> Result<Self, ArchiverInstantiationError> {
        // TODO: Check if KZG can process number configured number of elements and update proof
        //  message in `.expect()`

        let erasure_coding = ErasureCoding::new(
            NonZeroUsize::new(ArchivedHistorySegment::NUM_PIECES.ilog2() as usize)
                .expect("Recorded history segment contains at very least one record; qed"),
        )
        .map_err(ArchiverInstantiationError::FailedToInitializeErasureCoding)?;

        Ok(Self {
            buffer: VecDeque::default(),
            incremental_record_commitments: IncrementalRecordCommitmentsState::with_capacity(
                RecordedHistorySegment::NUM_RAW_RECORDS,
            ),
            erasure_coding,
            kzg,
            segment_index: SegmentIndex::ZERO,
            prev_segment_header_hash: Blake2b256Hash::default(),
            last_archived_block: INITIAL_LAST_ARCHIVED_BLOCK,
        })
    }

    /// Create a new instance of the archiver with initial state in case of restart.
    ///
    /// `block` corresponds to `last_archived_block` and will be processed accordingly to its state.
    pub fn with_initial_state(
        kzg: Kzg,
        segment_header: SegmentHeader,
        encoded_block: &[u8],
        mut object_mapping: BlockObjectMapping,
    ) -> Result<Self, ArchiverInstantiationError> {
        let mut archiver = Self::new(kzg)?;

        archiver.segment_index = segment_header.segment_index() + SegmentIndex::ONE;
        archiver.prev_segment_header_hash = segment_header.hash();
        archiver.last_archived_block = segment_header.last_archived_block();

        // The first thing in the buffer should be segment header
        archiver
            .buffer
            .push_back(SegmentItem::ParentSegmentHeader(segment_header));

        if let Some(archived_block_bytes) = archiver.last_archived_block.partial_archived() {
            let encoded_block_bytes = u32::try_from(encoded_block.len())
                .expect("Blocks length is never bigger than u32; qed");

            match encoded_block_bytes.cmp(&archived_block_bytes) {
                Ordering::Less => {
                    return Err(ArchiverInstantiationError::InvalidBlockSmallSize {
                        block_bytes: encoded_block_bytes,
                        archived_block_bytes,
                    });
                }
                Ordering::Equal => {
                    return Err(ArchiverInstantiationError::InvalidLastArchivedBlock(
                        encoded_block_bytes,
                    ));
                }
                Ordering::Greater => {
                    // Take part of the encoded block that wasn't archived yet and push to the
                    // buffer and block continuation
                    object_mapping
                        .objects
                        .drain_filter(|block_object: &mut BlockObject| {
                            let current_offset = block_object.offset();
                            if current_offset >= archived_block_bytes {
                                block_object.set_offset(current_offset - archived_block_bytes);
                                false
                            } else {
                                true
                            }
                        });
                    archiver.buffer.push_back(SegmentItem::BlockContinuation {
                        bytes: encoded_block[(archived_block_bytes as usize)..].to_vec(),
                        object_mapping,
                    });
                }
            }
        }

        Ok(archiver)
    }

    /// Get last archived block if there was any
    pub fn last_archived_block_number(&self) -> Option<BlockNumber> {
        if self.last_archived_block != INITIAL_LAST_ARCHIVED_BLOCK {
            Some(self.last_archived_block.number)
        } else {
            None
        }
    }

    /// Adds new block to internal buffer, potentially producing pieces and segment header headers
    pub fn add_block(
        &mut self,
        bytes: Vec<u8>,
        object_mapping: BlockObjectMapping,
    ) -> Vec<NewArchivedSegment> {
        // Append new block to the buffer
        self.buffer.push_back(SegmentItem::Block {
            bytes,
            object_mapping,
        });

        let mut archived_segments = Vec::new();

        while let Some(segment) = self.produce_segment() {
            archived_segments.push(self.produce_archived_segment(segment));
        }

        archived_segments
    }

    /// Try to slice buffer contents into segments if there is enough data, producing one segment at
    /// a time
    fn produce_segment(&mut self) -> Option<Segment> {
        let mut segment = Segment::V0 {
            items: Vec::with_capacity(self.buffer.len()),
        };

        let mut last_archived_block = self.last_archived_block;

        // `-2` because even the smallest segment item will take 2 bytes to encode, so it makes
        // sense to stop earlier here
        while segment.encoded_size() < (RecordedHistorySegment::SIZE - 2) {
            let segment_item = match self.buffer.pop_front() {
                Some(segment_item) => segment_item,
                None => {
                    update_record_commitments(
                        &mut self.incremental_record_commitments,
                        &segment,
                        &self.kzg,
                    );

                    let Segment::V0 { items } = segment;
                    // Push all of the items back into the buffer, we don't have enough data yet
                    for segment_item in items.into_iter().rev() {
                        self.buffer.push_front(segment_item);
                    }

                    return None;
                }
            };

            // Push segment item into the segment temporarily to measure encoded size of resulting
            // segment
            segment.push_item(segment_item);
            let encoded_segment_length = segment.encoded_size();
            // Pop segment item back from segment
            let segment_item = segment.pop_item().unwrap();

            // Check if there would be enough data collected with above segment item inserted
            if encoded_segment_length >= RecordedHistorySegment::SIZE {
                // Check if there is an excess of data that should be spilled over into the next
                // segment
                let spill_over = encoded_segment_length - RecordedHistorySegment::SIZE;

                // Due to compact vector length encoding in scale codec, spill over might happen to
                // be the same or even bigger than the inserted segment item bytes, in which case
                // last segment item insertion needs to be skipped to avoid out of range panic when
                // trying to cut segment item internal bytes.
                let inner_bytes_size = match &segment_item {
                    SegmentItem::Padding => {
                        unreachable!("Buffer never contains SegmentItem::Padding; qed");
                    }
                    SegmentItem::Block { bytes, .. } => bytes.len(),
                    SegmentItem::BlockStart { .. } => {
                        unreachable!("Buffer never contains SegmentItem::BlockStart; qed");
                    }
                    SegmentItem::BlockContinuation { bytes, .. } => bytes.len(),
                    SegmentItem::ParentSegmentHeader(_) => {
                        unreachable!(
                            "SegmentItem::SegmentHeader is always the first element in the buffer \
                            and fits into the segment; qed",
                        );
                    }
                };

                if spill_over > inner_bytes_size {
                    self.buffer.push_front(segment_item);
                    break;
                }
            }

            match &segment_item {
                SegmentItem::Padding => {
                    unreachable!("Buffer never contains SegmentItem::Padding; qed");
                }
                SegmentItem::Block { .. } => {
                    // Skip block number increase in case of the very first block
                    if last_archived_block != INITIAL_LAST_ARCHIVED_BLOCK {
                        // Increase archived block number and assume the whole block was
                        // archived
                        last_archived_block.number += 1;
                    }
                    last_archived_block.set_complete();
                }
                SegmentItem::BlockStart { .. } => {
                    unreachable!("Buffer never contains SegmentItem::BlockStart; qed");
                }
                SegmentItem::BlockContinuation { bytes, .. } => {
                    // Same block, but assume for now that the whole block was archived, but
                    // also store the number of bytes as opposed to `None`, we'll transform
                    // it into `None` if needed later
                    let archived_bytes = last_archived_block.partial_archived().expect(
                        "Block continuation implies that there are some bytes \
                            archived already; qed",
                    );
                    last_archived_block.set_partial_archived(
                        archived_bytes
                            + u32::try_from(bytes.len())
                                .expect("Blocks length is never bigger than u32; qed"),
                    );
                }
                SegmentItem::ParentSegmentHeader(_) => {
                    // We are not interested in segment header here
                }
            }

            segment.push_item(segment_item);
        }

        // Check if there is an excess of data that should be spilled over into the next segment
        let segment_encoded_length = segment.encoded_size();
        let spill_over = segment_encoded_length
            .checked_sub(RecordedHistorySegment::SIZE)
            .unwrap_or_default();

        if spill_over > 0 {
            let Segment::V0 { items } = &mut segment;
            let segment_item = items
                .pop()
                .expect("Segment over segment size always has at least one item; qed");

            let segment_item = match segment_item {
                SegmentItem::Padding => {
                    unreachable!("Buffer never contains SegmentItem::Padding; qed");
                }
                SegmentItem::Block {
                    mut bytes,
                    mut object_mapping,
                } => {
                    let split_point = bytes.len() - spill_over;
                    let continuation_bytes = bytes[split_point..].to_vec();

                    bytes.truncate(split_point);

                    let continuation_object_mapping = BlockObjectMapping {
                        objects: object_mapping
                            .objects
                            .drain_filter(|block_object: &mut BlockObject| {
                                let current_offset = block_object.offset();
                                if current_offset >= split_point as u32 {
                                    block_object.set_offset(current_offset - split_point as u32);
                                    true
                                } else {
                                    false
                                }
                            })
                            .collect(),
                    };

                    // Update last archived block to include partial archiving info
                    last_archived_block.set_partial_archived(
                        u32::try_from(bytes.len())
                            .expect("Blocks length is never bigger than u32; qed"),
                    );

                    // Push continuation element back into the buffer where removed segment item was
                    self.buffer.push_front(SegmentItem::BlockContinuation {
                        bytes: continuation_bytes,
                        object_mapping: continuation_object_mapping,
                    });

                    SegmentItem::BlockStart {
                        bytes,
                        object_mapping,
                    }
                }
                SegmentItem::BlockStart { .. } => {
                    unreachable!("Buffer never contains SegmentItem::BlockStart; qed");
                }
                SegmentItem::BlockContinuation {
                    mut bytes,
                    mut object_mapping,
                } => {
                    let split_point = bytes.len() - spill_over;
                    let continuation_bytes = bytes[split_point..].to_vec();

                    bytes.truncate(split_point);

                    let continuation_object_mapping = BlockObjectMapping {
                        objects: object_mapping
                            .objects
                            .drain_filter(|block_object: &mut BlockObject| {
                                let current_offset = block_object.offset();
                                if current_offset >= split_point as u32 {
                                    block_object.set_offset(current_offset - split_point as u32);
                                    true
                                } else {
                                    false
                                }
                            })
                            .collect(),
                    };

                    // Above code assumed that block was archived fully, now remove spilled-over
                    // bytes from the size
                    let archived_bytes = last_archived_block.partial_archived().expect(
                        "Block continuation implies that there are some bytes archived \
                        already; qed",
                    );
                    last_archived_block.set_partial_archived(
                        archived_bytes
                            - u32::try_from(spill_over)
                                .expect("Blocks length is never bigger than u32; qed"),
                    );

                    // Push continuation element back into the buffer where removed segment item was
                    self.buffer.push_front(SegmentItem::BlockContinuation {
                        bytes: continuation_bytes,
                        object_mapping: continuation_object_mapping,
                    });

                    SegmentItem::BlockContinuation {
                        bytes,
                        object_mapping,
                    }
                }
                SegmentItem::ParentSegmentHeader(_) => {
                    unreachable!(
                        "SegmentItem::SegmentHeader is always the first element in the buffer and \
                        fits into the segment; qed",
                    );
                }
            };

            // Push back shortened segment item
            items.push(segment_item);
        } else {
            // Above code added bytes length even though it was assumed that all continuation bytes
            // fit into the segment, now we need to tweak that
            last_archived_block.set_complete();
        }

        self.last_archived_block = last_archived_block;

        Some(segment)
    }

    // Take segment as an input, apply necessary transformations and produce archived segment
    fn produce_archived_segment(&mut self, segment: Segment) -> NewArchivedSegment {
        // Create mappings
        let object_mapping = {
            let mut corrected_object_mapping =
                vec![PieceObjectMapping::default(); RecordedHistorySegment::NUM_RAW_RECORDS];
            let Segment::V0 { items } = &segment;
            // `+1` corresponds to enum variant encoding
            let mut base_offset_in_segment = 1;
            for segment_item in items {
                match segment_item {
                    SegmentItem::Padding => {
                        unreachable!(
                            "Segment during archiving never contains SegmentItem::Padding; qed"
                        );
                    }
                    SegmentItem::Block {
                        bytes,
                        object_mapping,
                    }
                    | SegmentItem::BlockStart {
                        bytes,
                        object_mapping,
                    }
                    | SegmentItem::BlockContinuation {
                        bytes,
                        object_mapping,
                    } => {
                        for block_object in &object_mapping.objects {
                            // `+1` corresponds to `SegmentItem::X {}` enum variant encoding
                            let offset_in_segment = base_offset_in_segment
                                + 1
                                + Compact::compact_len(&(bytes.len() as u32))
                                + block_object.offset() as usize;
                            let offset = (offset_in_segment % RawRecord::SIZE).try_into().expect(
                                "Offset within piece should always fit in 16-bit integer; qed",
                            );

                            if let Some(piece_object_mapping) = corrected_object_mapping
                                .get_mut(offset_in_segment / RawRecord::SIZE)
                            {
                                piece_object_mapping.objects.push(PieceObject::V0 {
                                    hash: block_object.hash(),
                                    offset,
                                });
                            }
                        }
                    }
                    SegmentItem::ParentSegmentHeader(_) => {
                        // Ignore, no objects mappings here
                    }
                }

                base_offset_in_segment += segment_item.encoded_size();
            }
            corrected_object_mapping
        };

        let mut pieces = {
            // Serialize segment into concatenation of raw records
            let mut raw_record_shards = Vec::<u8>::with_capacity(RecordedHistorySegment::SIZE);
            segment.encode_to(&mut raw_record_shards);
            // Segment might require some padding (see [`Self::produce_segment`] for details)
            raw_record_shards.resize(raw_record_shards.capacity(), 0);

            // Segment is quite big and no longer necessary
            drop(segment);

            let mut pieces = ArchivedHistorySegment::default();

            // Scratch buffer to avoid re-allocation
            let mut tmp_source_shards_scalars =
                Vec::<Scalar>::with_capacity(RecordedHistorySegment::NUM_RAW_RECORDS);
            // Iterate over the chunks of `Scalar::SAFE_BYTES` bytes of all records
            for record_offset in 0..RawRecord::SIZE / Scalar::SAFE_BYTES {
                // Collect chunks of each record at the same offset
                raw_record_shards
                    .array_chunks::<{ RawRecord::SIZE }>()
                    .map(|record_bytes| {
                        record_bytes
                            .array_chunks::<{ Scalar::SAFE_BYTES }>()
                            .nth(record_offset)
                            .expect("Statically known to exist in a record; qed")
                    })
                    .map(Scalar::from)
                    .collect_into(&mut tmp_source_shards_scalars);

                // Extend to obtain corresponding parity shards
                let parity_shards = self
                    .erasure_coding
                    .extend(&tmp_source_shards_scalars)
                    .expect(
                        "Erasure coding instance is deliberately configured to support this \
                        input; qed",
                    );

                let interleaved_input_chunks = tmp_source_shards_scalars
                    .drain(..)
                    .zip(parity_shards)
                    .flat_map(|(a, b)| [a, b]);
                let output_chunks = pieces.iter_mut().map(|piece| {
                    piece
                        .record_mut()
                        .full_scalar_arrays_mut()
                        .nth(record_offset)
                        .expect("Statically known to exist in a record; qed")
                });

                interleaved_input_chunks
                    .zip(output_chunks)
                    .for_each(|(input, output)| output.copy_from_slice(&input.to_bytes()));
            }

            pieces
        };

        let existing_commitments = self.incremental_record_commitments.len();
        // Add commitments for pieces that were not created incrementally
        {
            #[cfg(not(feature = "rayon"))]
            let source_pieces = pieces.source();
            #[cfg(feature = "rayon")]
            let source_pieces = pieces.par_source();

            let iter = source_pieces
                .skip(existing_commitments)
                .map(|piece| piece.record().safe_scalar_arrays().map(Scalar::from))
                .map(|record_chunks| {
                    let number_of_chunks = record_chunks.len();
                    let mut scalars = Vec::with_capacity(number_of_chunks.next_power_of_two());

                    record_chunks.collect_into(&mut scalars);

                    // Number of scalars for KZG must be a power of two elements
                    scalars.resize(scalars.capacity(), Scalar::default());

                    let polynomial = self.kzg.poly(&scalars).expect(
                        "KZG instance must be configured to support this many scalars; qed",
                    );
                    self.kzg
                        .commit(&polynomial)
                        .expect("KZG instance must be configured to support this many scalars; qed")
                });

            #[cfg(not(feature = "rayon"))]
            iter.collect_into(&mut *self.incremental_record_commitments);
            // TODO: `collect_into_vec()`, unfortunately, truncates input, which is not what we want
            //  can be unified when https://github.com/rayon-rs/rayon/issues/1039 is resolved
            #[cfg(feature = "rayon")]
            self.incremental_record_commitments
                .extend(&iter.collect::<Vec<_>>());
        }
        // Collect hashes to commitments from all records
        let record_commitments = self
            .erasure_coding
            .extend_commitments(&self.incremental_record_commitments)
            .expect(
                "Erasure coding instance is deliberately configured to support this input; qed",
            );
        self.incremental_record_commitments.clear();

        let polynomial = self
            .kzg
            .poly(
                &record_commitments
                    .iter()
                    .map(|commitment| blake2b_256_254_hash_to_scalar(&commitment.to_bytes()))
                    .collect::<Vec<_>>(),
            )
            .expect("Internally produced values must never fail; qed");

        let segment_commitment = self
            .kzg
            .commit(&polynomial)
            .expect("Internally produced values must never fail; qed");

        // Create witness for every record and write it to corresponding piece.
        pieces
            .iter_mut()
            .zip(record_commitments)
            .enumerate()
            .for_each(|(position, (piece, commitment))| {
                let commitment_bytes = commitment.to_bytes();
                let (_record, commitment, witness) = piece.split_mut();
                commitment.copy_from_slice(&commitment_bytes);
                // TODO: Consider batch witness creation for improved performance
                witness.copy_from_slice(
                    &self
                        .kzg
                        .create_witness(&polynomial, position as u32)
                        .expect("Position is statically known to be valid; qed")
                        .to_bytes(),
                );
            });

        // Now produce segment header
        let segment_header = SegmentHeader::V0 {
            segment_index: self.segment_index,
            segment_commitment,
            prev_segment_header_hash: self.prev_segment_header_hash,
            last_archived_block: self.last_archived_block,
        };

        // Update state
        self.segment_index += SegmentIndex::ONE;
        self.prev_segment_header_hash = segment_header.hash();

        // Add segment header to the beginning of the buffer to be the first thing included in the
        //  nextsegment
        self.buffer
            .push_front(SegmentItem::ParentSegmentHeader(segment_header));

        NewArchivedSegment {
            segment_header,
            pieces,
            object_mapping,
        }
    }
}

/// Validate witness embedded within a piece produced by archiver
pub fn is_piece_valid(
    kzg: &Kzg,
    piece: &PieceArray,
    segment_commitment: &SegmentCommitment,
    position: u32,
) -> bool {
    let (record, commitment, witness) = piece.split();
    let witness = match Witness::try_from_bytes(witness) {
        Ok(witness) => witness,
        _ => {
            return false;
        }
    };

    let record_chunks = record.full_scalar_arrays();
    let number_of_chunks = record_chunks.len();
    let mut scalars = Vec::with_capacity(number_of_chunks.next_power_of_two());

    for record_chunk in record_chunks {
        match Scalar::try_from(record_chunk) {
            Ok(scalar) => {
                scalars.push(scalar);
            }
            _ => {
                return false;
            }
        }
    }

    // Number of scalars for KZG must be a power of two elements
    scalars.resize(scalars.capacity(), Scalar::default());

    let polynomial = match kzg.poly(&scalars) {
        Ok(polynomial) => polynomial,
        _ => {
            return false;
        }
    };

    if kzg
        .commit(&polynomial)
        .map(|commitment| commitment.to_bytes())
        .as_ref()
        != Ok(commitment)
    {
        return false;
    }

    let commitment_hash = blake2b_256_254_hash_to_scalar(commitment.as_ref());

    kzg.verify(
        segment_commitment,
        ArchivedHistorySegment::NUM_PIECES,
        position,
        &commitment_hash,
        &witness,
    )
}

/// Validate witness for piece commitment hash produced by archiver
pub fn is_record_commitment_hash_valid(
    kzg: &Kzg,
    commitment_hash: &Scalar,
    commitment: &SegmentCommitment,
    witness: &Witness,
    position: u32,
) -> bool {
    kzg.verify(
        commitment,
        ArchivedHistorySegment::NUM_PIECES,
        position,
        commitment_hash,
        witness,
    )
}
