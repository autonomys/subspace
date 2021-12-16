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
extern crate alloc;

use crate::merkle_tree::{MerkleTree, Witness};
use crate::utils;
use crate::utils::{Gf16Element, GF_16_ELEMENT_BYTES};
use alloc::borrow::Cow;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::iter;
use parity_scale_codec::{Compact, CompactLen, Decode, Encode};
use reed_solomon_erasure::galois_16::ReedSolomon;
use subspace_core_primitives::objects::{
    BlockObject, BlockObjectMapping, PieceObject, PieceObjectMapping,
};
use subspace_core_primitives::{
    crypto, ArchivedBlockProgress, FlatPieces, LastArchivedBlock, RootBlock, Sha256Hash,
    PIECE_SIZE, SHA256_HASH_SIZE,
};

const INITIAL_LAST_ARCHIVED_BLOCK: LastArchivedBlock = LastArchivedBlock {
    number: 0,
    // Special case for the genesis block.
    //
    // When we start archiving process with pre-genesis objects, we do not yet have any blocks
    // archived, but `LastArchivedBlock` is required for `RootBlock`s to be produced, so
    // `ArchivedBlockProgress::Partial(0)` indicates that we have archived 0 bytes of block `0` (see
    // field above), meaning we did not in fact archive actual blocks yet.
    archived_progress: ArchivedBlockProgress::Partial(0),
};

/// Segment represents a collection of items stored in archival history of the Subspace blockchain
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode)]
pub enum Segment {
    // V0 of the segment data structure
    #[codec(index = 0)]
    V0 {
        /// Segment items
        items: Vec<SegmentItem>,
    },
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
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode)]
pub enum SegmentItem {
    /// Contains full block inside
    #[codec(index = 3)]
    Block {
        /// Block bytes
        bytes: Vec<u8>,
        /// This is a convenience implementation detail and will not be available on decoding
        #[doc(hidden)]
        #[codec(skip)]
        object_mapping: BlockObjectMapping,
    },
    /// Contains the beginning of the block inside, remainder will be found in subsequent segments
    #[codec(index = 4)]
    BlockStart {
        /// Block bytes
        bytes: Vec<u8>,
        /// This is a convenience implementation detail and will not be available on decoding
        #[doc(hidden)]
        #[codec(skip)]
        object_mapping: BlockObjectMapping,
    },
    /// Continuation of the partial block spilled over into the next segment
    #[codec(index = 5)]
    BlockContinuation {
        /// Block bytes
        bytes: Vec<u8>,
        /// This is a convenience implementation detail and will not be available on decoding
        #[doc(hidden)]
        #[codec(skip)]
        object_mapping: BlockObjectMapping,
    },
    /// Root block
    #[codec(index = 6)]
    RootBlock(RootBlock),
}

/// Archived segment as a combination of root block hash, segment index and corresponding pieces
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct ArchivedSegment {
    /// Root block of the segment
    pub root_block: RootBlock,
    /// Pieces that correspond to this segment
    pub pieces: FlatPieces,
    /// Mappings for objects stored in corresponding pieces.
    ///
    /// NOTE: Only first half (data pieces) will have corresponding mapping item in this `Vec`.
    pub object_mapping: Vec<PieceObjectMapping>,
}

/// Archiver instantiation error
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum ArchiverInstantiationError {
    /// Record size it smaller that needed to hold any information
    #[cfg_attr(
        feature = "thiserror",
        error("Record size it smaller that needed to hold any information")
    )]
    RecordSizeTooSmall,
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
    /// Wrong record and segment size, it will not be possible to produce pieces
    #[cfg_attr(
        feature = "thiserror",
        error("Wrong record and segment size, it will not be possible to produce pieces")
    )]
    WrongRecordAndSegmentCombination,
    /// Invalid last archived block, its size is the same as encoded block
    #[cfg_attr(
        feature = "thiserror",
        error("Invalid last archived block, its size {0} bytes is the same as encoded block")
    )]
    InvalidLastArchivedBlock(u32),
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
/// sliced into segments of `RECORDED_HISTORY_SEGMENT_SIZE` size, segments are sliced into source
/// records of `RECORD_SIZE`, records are erasure coded, Merkle Tree is built over them, and
/// with Merkle Proofs appended records become pieces that are returned alongside corresponding root
/// block header.
#[derive(Debug)]
pub struct Archiver {
    /// Buffer containing blocks and other buffered items that are pending to be included into the
    /// next segment
    buffer: VecDeque<SegmentItem>,
    /// Configuration parameter defining the size of one record (data in one piece excluding witness
    /// size)
    record_size: usize,
    /// Configuration parameter defining the size of one recorded history segment
    segment_size: usize,
    /// Erasure coding data structure
    reed_solomon: ReedSolomon,
    /// An index of the current segment
    segment_index: u64,
    /// Hash of the root block of the previous segment
    prev_root_block_hash: Sha256Hash,
    /// Last archived block
    last_archived_block: LastArchivedBlock,
}

impl Archiver {
    /// Create a new instance with specified record size and recorded history segment size.
    ///
    /// Note: this is the only way to instantiate object archiver, while block archiver can be
    /// instantiated with `BlockArchiver::with_initial_state()` in case of restarts.
    ///
    /// Panics if:
    /// * record size it smaller that needed to hold any information
    /// * segment size is not bigger than record size
    /// * segment size is not a multiple of record size
    /// * segment size and record size do not make sense together
    pub fn new(
        record_size: usize,
        segment_size: usize,
    ) -> Result<Self, ArchiverInstantiationError> {
        let tiny_segment = Segment::V0 {
            items: vec![SegmentItem::Block {
                bytes: vec![0u8],
                object_mapping: BlockObjectMapping::default(),
            }],
        };
        if record_size <= tiny_segment.encoded_size() {
            return Err(ArchiverInstantiationError::RecordSizeTooSmall);
        }
        if segment_size <= record_size {
            return Err(ArchiverInstantiationError::SegmentSizeTooSmall);
        }
        if segment_size % record_size != 0 {
            return Err(ArchiverInstantiationError::SegmentSizesNotMultipleOfRecordSize);
        }

        // We take N data records and will creates the same number of parity records, hence `*2`
        let merkle_num_leaves = segment_size / record_size * 2;
        let witness_size = SHA256_HASH_SIZE * merkle_num_leaves.log2() as usize;
        if record_size + witness_size != PIECE_SIZE {
            return Err(ArchiverInstantiationError::WrongRecordAndSegmentCombination);
        }

        let shards = segment_size / record_size;
        let reed_solomon = ReedSolomon::new(shards, shards)
            .expect("ReedSolomon should always be correctly instantiated");

        Ok(Self {
            buffer: VecDeque::default(),
            record_size,
            segment_size,
            reed_solomon,
            segment_index: 0,
            prev_root_block_hash: Sha256Hash::default(),
            last_archived_block: INITIAL_LAST_ARCHIVED_BLOCK,
        })
    }

    /// Create a new instance of the archiver with initial state in case of restart.
    ///
    /// `block` corresponds to `last_archived_block` and will be processed accordingly to its state.
    pub fn with_initial_state<B: AsRef<[u8]>>(
        record_size: usize,
        segment_size: usize,
        root_block: RootBlock,
        encoded_block: B,
        mut object_mapping: BlockObjectMapping,
    ) -> Result<Self, ArchiverInstantiationError> {
        let mut archiver = Self::new(record_size, segment_size)?;

        archiver.segment_index = root_block.segment_index() + 1;
        archiver.prev_root_block_hash = root_block.hash();
        archiver.last_archived_block = root_block.last_archived_block();

        // The first thing in the buffer should be root block
        archiver
            .buffer
            .push_back(SegmentItem::RootBlock(root_block));

        if let Some(archived_block_bytes) = archiver.last_archived_block.partial_archived() {
            let encoded_block = encoded_block.as_ref();
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
    pub fn last_archived_block_number(&self) -> Option<u32> {
        if self.last_archived_block != INITIAL_LAST_ARCHIVED_BLOCK {
            Some(self.last_archived_block.number)
        } else {
            None
        }
    }

    /// Adds new block to internal buffer, potentially producing pieces and root block headers
    pub fn add_block(
        &mut self,
        bytes: Vec<u8>,
        object_mapping: BlockObjectMapping,
    ) -> Vec<ArchivedSegment> {
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
        while segment.encoded_size() < (self.segment_size - 2) {
            let segment_item = match self.buffer.pop_front() {
                Some(segment_item) => segment_item,
                None => {
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
            if encoded_segment_length >= self.segment_size {
                // Check if there is an excess of data that should be spilled over into the next
                // segment
                let spill_over = encoded_segment_length - self.segment_size;

                // Due to compact vector length encoding in scale codec, spill over might happen to
                // be the same or even bigger than the inserted segment item bytes, in which case
                // last segment item insertion needs to be skipped to avoid out of range panic when
                // trying to cut segment item internal bytes.
                let inner_bytes_size = match &segment_item {
                    SegmentItem::Block { bytes, .. } => bytes.len(),
                    SegmentItem::BlockStart { .. } => {
                        unreachable!("Buffer never contains SegmentItem::BlockStart; qed");
                    }
                    SegmentItem::BlockContinuation { bytes, .. } => bytes.len(),
                    SegmentItem::RootBlock(_) => {
                        unreachable!(
                            "SegmentItem::RootBlock is always the first element in the buffer and \
                            fits into the segment; qed",
                        );
                    }
                };

                if spill_over > inner_bytes_size {
                    self.buffer.push_front(segment_item);
                    break;
                }
            }

            match &segment_item {
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
                SegmentItem::RootBlock(_) => {
                    // We are not interested in root block here
                }
            }

            segment.push_item(segment_item);
        }

        // Check if there is an excess of data that should be spilled over into the next segment
        let segment_encoded_length = segment.encoded_size();
        let spill_over = segment_encoded_length
            .checked_sub(self.segment_size)
            .unwrap_or_default();

        if spill_over > 0 {
            let Segment::V0 { items } = &mut segment;
            let segment_item = items
                .pop()
                .expect("Segment over segment size always has at least one item; qed");

            let segment_item = match segment_item {
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
                SegmentItem::RootBlock(_) => {
                    unreachable!(
                        "SegmentItem::RootBlock is always the first element in the buffer and \
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
    fn produce_archived_segment(&mut self, segment: Segment) -> ArchivedSegment {
        // Create mappings
        let object_mapping = {
            let mut corrected_object_mapping =
                vec![PieceObjectMapping::default(); self.segment_size / self.record_size];
            let Segment::V0 { items } = &segment;
            // `+1` corresponds to enum variant encoding
            let mut base_offset_in_segment = 1 + Compact::compact_len(&(items.len() as u32));
            for segment_item in items {
                match segment_item {
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
                            let offset = (offset_in_segment % self.record_size).try_into().expect(
                                "Offset within piece should always fit in 16-bit integer; qed",
                            );

                            corrected_object_mapping[offset_in_segment / self.record_size]
                                .objects
                                .push(PieceObject::V0 {
                                    hash: block_object.hash(),
                                    offset,
                                })
                        }
                    }
                    SegmentItem::RootBlock(_) => {
                        // Ignore, no objects mappings here
                    }
                }

                base_offset_in_segment += segment_item.encoded_size();
            }
            corrected_object_mapping
        };
        let segment = {
            let mut segment = segment.encode();
            // Add a few bytes of padding if needed to get constant size (caused by compact length
            // encoding of scale codec)
            assert!(self.segment_size >= segment.len());
            segment.resize(self.segment_size, 0u8);
            segment
        };

        let data_shards: Vec<Vec<Gf16Element>> = segment
            .chunks_exact(self.record_size)
            .map(utils::slice_to_arrays)
            .collect();

        drop(segment);

        let mut parity_shards: Vec<Vec<Gf16Element>> =
            iter::repeat(vec![Gf16Element::default(); self.record_size / 2])
                .take(data_shards.len())
                .collect();

        // Apply erasure coding to to create parity shards/records
        self.reed_solomon
            .encode_sep(&data_shards, &mut parity_shards)
            .expect("Encoding is running with fixed parameters and should never fail");

        let mut pieces = vec![0u8; (data_shards.len() + parity_shards.len()) * PIECE_SIZE];
        // Combine data and parity records back into flat vector of pieces (witness part of piece is
        // still zeroes after this and is filled later)
        pieces
            .chunks_exact_mut(PIECE_SIZE)
            .zip(data_shards.into_iter().chain(parity_shards))
            .flat_map(|(piece, shard)| {
                piece
                    .chunks_exact_mut(GF_16_ELEMENT_BYTES)
                    .zip(shard.into_iter())
            })
            .for_each(|(piece_chunk, shard_chunk)| {
                piece_chunk.copy_from_slice(&shard_chunk);
            });

        // Build a Merkle tree over all records
        let merkle_tree = MerkleTree::from_data(
            pieces
                .chunks_exact(PIECE_SIZE)
                .map(|piece| &piece[..self.record_size]),
        );

        // Fill witnesses (Merkle proofs) in pieces created earlier
        pieces
            .chunks_exact_mut(PIECE_SIZE)
            .enumerate()
            .for_each(|(position, piece)| {
                let witness = merkle_tree
                    .get_witness(position)
                    .expect("We use the same indexes as during Merkle tree creation; qed");

                piece[self.record_size..].copy_from_slice(&witness);
            });

        // Now produce root block
        let root_block = RootBlock::V0 {
            segment_index: self.segment_index,
            records_root: merkle_tree.root(),
            prev_root_block_hash: self.prev_root_block_hash,
            last_archived_block: self.last_archived_block,
        };

        // Update state
        self.segment_index += 1;
        self.prev_root_block_hash = root_block.hash();

        // Add root block to the beginning of the buffer to be the first thing included in the next
        // segment
        self.buffer.push_front(SegmentItem::RootBlock(root_block));

        ArchivedSegment {
            root_block,
            pieces: pieces
                .try_into()
                .expect("Pieces length is correct as created above; qed"),
            object_mapping,
        }
    }
}

/// Validate witness embedded within a piece produced by archiver
pub fn is_piece_valid(piece: &[u8], root: Sha256Hash, position: usize, record_size: usize) -> bool {
    let witness = match Witness::new(Cow::Borrowed(&piece[record_size..])) {
        Ok(witness) => witness,
        Err(_) => {
            return false;
        }
    };
    let leaf_hash = crypto::sha256_hash(&piece[..record_size]);

    witness.is_valid(root, position, leaf_hash)
}
