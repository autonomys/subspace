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

use crate::merkle_tree::{MerkleTree, Witness};
use parity_scale_codec::{Decode, Encode};
use reed_solomon_erasure::galois_16::ReedSolomon;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::io::Write;
use std::iter;
use subspace_core_primitives::{
    crypto, LastArchivedBlock, Piece, RootBlock, Sha256Hash, PIECE_SIZE, SHA256_HASH_SIZE,
};
use thiserror::Error;

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
}

/// Kinds of items that are contained within a segment
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode)]
pub enum SegmentItem {
    /// Contains full block inside
    #[codec(index = 0)]
    Block(Vec<u8>),
    /// Contains the beginning of the block inside, remainder will be found in subsequent segments
    #[codec(index = 1)]
    BlockStart(Vec<u8>),
    /// Continuation of the partial block spilled over into the next segment
    #[codec(index = 2)]
    BlockContinuation(Vec<u8>),
    /// Root block
    #[codec(index = 2)]
    RootBlock(RootBlock),
}

#[derive(Debug, Clone)]
/// Archived segment as a combination of root block hash, segment index and corresponding pieces
pub struct ArchivedSegment {
    /// Root block of the segment
    pub root_block: RootBlock,
    /// Pieces that correspond to this segment
    pub pieces: Vec<Piece>,
}

/// Archiver instantiation error
#[derive(Debug, Error, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ArchiverInstantiationError {
    /// Record size it smaller that needed to hold any information
    #[error("Record size it smaller that needed to hold any information")]
    RecordSizeTooSmall,
    /// Segment size is not bigger than record size
    #[error("Segment size is not bigger than record size")]
    SegmentSizeTooSmall,
    /// Segment size is not a multiple of record size
    #[error("Segment size is not a multiple of record size")]
    SegmentSizesNotMultipleOfRecordSize,
    /// Wrong record and segment size, it will not be possible to produce pieces
    #[error("Wrong record and segment size, it will not be possible to produce pieces")]
    WrongRecordAndSegmentCombination,
}

/// Archiver for Subspace blockchain.
///
/// It takes new confirmed (at `K` depth) blocks and concatenates them into a buffer, buffer is
/// sliced into segments of `RECORDED_HISTORY_SEGMENT_SIZE` size, segments are sliced into source
/// records of `RECORD_SIZE`, records are erasure coded, Merkle Tree is built over them, and
/// with Merkle Proofs appended records become pieces that are returned alongside corresponding root
/// block header.
// TODO: Make this survive restarts without loosing state
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
            items: vec![SegmentItem::Block(vec![0u8])],
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
            last_archived_block: LastArchivedBlock {
                number: 0,
                bytes: Some(0),
            },
        })
    }

    /// Adds new block to internal buffer, potentially producing pieces and root block headers
    pub fn add_block<B: Encode>(&mut self, block: B) -> Vec<ArchivedSegment> {
        // Append new block to the buffer
        self.buffer.push_back(SegmentItem::Block(block.encode()));

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

        while segment.encoded_size() < self.segment_size {
            let segment_item = match self.buffer.pop_front() {
                Some(segment_item) => {
                    match &segment_item {
                        SegmentItem::Block(_) => {
                            // Skip block number increase in case of the very first block
                            if last_archived_block
                                != (LastArchivedBlock {
                                    number: 0,
                                    bytes: Some(0),
                                })
                            {
                                // Increase archived block number and assume the whole block was
                                // archived
                                last_archived_block.number += 1;
                            }
                            last_archived_block.bytes = None;
                        }
                        SegmentItem::BlockStart(_) => {
                            unreachable!("Buffer never contains SegmentItem::BlockStart; qed");
                        }
                        SegmentItem::BlockContinuation(continuation_bytes) => {
                            // Same block, but assume for now that the whole block was archived, but
                            // also store the number of bytes as opposed to `None`, we'll transform
                            // it into `None` if needed later
                            let archived_bytes = last_archived_block.bytes.expect(
                                "Block continuation implies that there are some bytes \
                                archived already; qed",
                            );
                            last_archived_block.bytes.replace(
                                archived_bytes
                                    + u32::try_from(continuation_bytes.len())
                                        .expect("Blocks length is never bigger than u32; qed"),
                            );
                        }
                        SegmentItem::RootBlock(_) => {
                            // We are not interested in root block here
                        }
                    }
                    segment_item
                }
                None => {
                    let Segment::V0 { items } = segment;
                    // Push all of the items back into the buffer, we don't have enough data yet
                    for segment_item in items.into_iter().rev() {
                        self.buffer.push_front(segment_item);
                    }

                    return None;
                }
            };

            segment.push_item(segment_item);
        }

        // We may have gotten more data than needed, check and move the excess into the next segment
        let spill_over = segment.encoded_size() - self.segment_size;

        if spill_over > 0 {
            let Segment::V0 { items } = &mut segment;
            let segment_item = items
                .pop()
                .expect("Segment over segment size always has at least one item; qed");

            let (segment_item, continuation_segment_item_bytes) = match segment_item {
                SegmentItem::Block(mut bytes) => {
                    let split_point = bytes.len() - spill_over;
                    let block_continuation_bytes = bytes[split_point..].to_vec();

                    bytes.truncate(split_point);

                    // Update last archived block to include partial archiving info
                    last_archived_block.bytes.replace(
                        u32::try_from(bytes.len())
                            .expect("Blocks length is never bigger than u32; qed"),
                    );

                    (SegmentItem::BlockStart(bytes), block_continuation_bytes)
                }
                SegmentItem::BlockStart(_) => {
                    unreachable!("Buffer never contains SegmentItem::BlockStart; qed");
                }
                SegmentItem::BlockContinuation(mut block_bytes) => {
                    let split_point = block_bytes.len() - spill_over;
                    let block_continuation_bytes = block_bytes[split_point..].to_vec();

                    block_bytes.truncate(split_point);

                    // Above code assumed that block was archived fully, now remove spilled-over
                    // bytes from the size
                    let archived_bytes = last_archived_block.bytes.expect(
                        "Block continuation implies that there are some bytes archived \
                        already; qed",
                    );
                    last_archived_block.bytes.replace(
                        archived_bytes
                            - u32::try_from(spill_over)
                                .expect("Blocks length is never bigger than u32; qed"),
                    );

                    (
                        SegmentItem::BlockContinuation(block_bytes),
                        block_continuation_bytes,
                    )
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
            // Push continuation element back into the buffer where removed segment item was
            self.buffer.push_front(SegmentItem::BlockContinuation(
                continuation_segment_item_bytes,
            ));
        } else {
            // Above code added bytes length even though it was assumed that all continuation bytes
            // fit into the segment, now we need to tweak that
            last_archived_block.bytes.take();
        }

        self.last_archived_block = last_archived_block;

        Some(segment)
    }

    // Take segment as an input, apply necessary transformations and produce archived segment
    fn produce_archived_segment(&mut self, segment: Segment) -> ArchivedSegment {
        let segment = {
            let mut segment = segment.encode();
            // Add a few bytes of padding if needed to get constant size (caused by compact length
            // encoding of scale codec)
            segment.resize(self.segment_size, 0u8);
            segment
        };

        fn slice_to_arrays(slice: &[u8]) -> Vec<[u8; 2]> {
            slice
                .chunks_exact(2)
                .map(|s| s.try_into().unwrap())
                .collect()
        }

        let data_shards: Vec<Vec<[u8; 2]>> = segment
            .chunks_exact(self.record_size)
            .map(slice_to_arrays)
            .collect();

        drop(segment);

        let mut parity_shards: Vec<Vec<[u8; 2]>> =
            iter::repeat(vec![[0u8; 2]; self.record_size / 2])
                .take(data_shards.len())
                .collect();

        // Apply erasure coding to to create parity shards/records
        self.reed_solomon
            .encode_sep(&data_shards, &mut parity_shards)
            .expect("Encoding is running with fixed parameters and should never fail");

        // Combine data and parity records back into vectors for further processing
        let records: Vec<Vec<u8>> = data_shards
            .into_iter()
            .chain(parity_shards)
            .map(|shard| {
                let mut record = Vec::with_capacity(self.record_size);

                for chunk in shard {
                    record.extend_from_slice(&chunk);
                }

                record
            })
            .collect();

        // Build a Merkle tree over data and parity records
        let merkle_tree = MerkleTree::from_data(records.iter());

        // Take records, combine them with witnesses (Merkle proofs) to produce data and parity
        // pieces
        let pieces: Vec<Piece> = records
            .into_iter()
            .enumerate()
            .map(|(index, record)| {
                let witness = merkle_tree
                    .get_witness(index)
                    .expect("We use the same indexes as during Merkle tree creation; qed");
                let mut piece: Piece = [0u8; PIECE_SIZE];

                piece.as_mut().write_all(&record).expect(
                    "With correct archiver parameters record is always smaller than \
                        piece size; qed",
                );
                drop(record);

                (&mut piece[self.record_size..]).write_all(&witness).expect(
                    "Parameters are verified in the archiver constructor to make sure this \
                    never happens; qed",
                );

                piece
            })
            .collect();

        let segment_index = self.segment_index;
        let merkle_tree_root = merkle_tree.root();

        // Now produce root block
        let root_block = RootBlock::V0 {
            segment_index,
            merkle_tree_root,
            prev_root_block_hash: self.prev_root_block_hash,
            last_archived_block: self.last_archived_block,
        };

        let root_block_hash = root_block.hash();

        // Update state
        self.segment_index = segment_index + 1;
        self.prev_root_block_hash = root_block_hash;

        // Add root block to the beginning of the buffer to be the first thing included in the next
        // segment
        self.buffer.push_front(SegmentItem::RootBlock(root_block));

        ArchivedSegment { root_block, pieces }
    }
}

/// Validate witness embedded within a piece produced by archiver
pub fn is_piece_valid(piece: &Piece, root: Sha256Hash, index: usize, record_size: usize) -> bool {
    let witness = match Witness::new(Cow::Borrowed(&piece[record_size..])) {
        Ok(witness) => witness,
        Err(_) => {
            return false;
        }
    };
    let leaf_hash = crypto::sha256_hash(&piece[..record_size]);

    witness.is_valid(root, index, leaf_hash)
}
