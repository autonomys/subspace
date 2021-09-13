// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//! Utility module for handling Subspace client notifications.

use crate::merkle_tree::MerkleTree;
use codec::Encode;
use reed_solomon_erasure::galois_16::ReedSolomon;
use ring::digest;
use sp_consensus_spartan::spartan::{Piece, PIECE_SIZE};
use std::collections::VecDeque;
use std::convert::TryInto;
use std::io::Write;
use std::iter;

type Sha256Hash = [u8; 32];

/// Segment represents a collection of items stored in archival history of the Subspace blockchain
#[derive(Debug, Encode)]
enum Segment {
    // V0 of the segment data structure
    #[codec(index = 0)]
    V0 {
        /// Segment items
        items: Vec<SegmentItem>,
    },
}

/// Root block for a specific segment
#[derive(Debug, Encode)]
enum RootBlock {
    // V0 of the root block data structure
    #[codec(index = 0)]
    V0 {
        /// Segment index
        segment_index: u64,
        /// Merkle tree root of all pieces within segment
        merkle_tree_root: Sha256Hash,
        /// Hash of the root block of the previous segment
        prev_root_block_hash: Sha256Hash,
    },
}

impl RootBlock {
    fn hash(&self) -> Sha256Hash {
        digest::digest(&digest::SHA256, &self.encode())
            .as_ref()
            .try_into()
            .expect("Sha256 output is always 32 bytes; qed")
    }
}

/// Kinds of items that are contained within a segment
#[derive(Debug, Encode)]
enum SegmentItem {
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

#[derive(Debug, Encode, Clone)]
/// Archived segment as a combination of root block hash, segment index and corresponding pieces
pub(super) struct ArchivedSegment {
    /// Segment index
    pub(super) segment_index: u64,
    /// Root block hash
    pub(super) root_block_hash: Sha256Hash,
    /// Pieces that correspond to this segment
    pub(super) pieces: Vec<Piece>,
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
pub(super) struct Archiver {
    /// Buffer containing blocks and other buffered items that are pending to be included into the
    /// next segment
    buffer: VecDeque<SegmentItem>,
    /// Configuration parameter defining the size of one record (data in one piece excluding witness
    /// size)
    record_size: usize,
    /// Size of the witness for every record
    witness_size: usize,
    /// Configuration parameter defining the size of one recorded history segment
    segment_size: usize,
    /// Erasure coding data structure
    reed_solomon: ReedSolomon,
    /// An index of the current segment
    segment_index: u64,
    /// Hash of the root block of the previous segment
    prev_root_block_hash: Sha256Hash,
}

impl Archiver {
    /// Create a new instance with specified record size and recorded history segment size.
    ///
    /// Panics if:
    /// * record size it smaller that needed to hold any information
    /// * segment size is not bigger than record size
    /// * segment size is not a multiple of record size
    pub(super) fn new(record_size: usize, witness_size: usize, segment_size: usize) -> Self {
        let empty_segment = Segment::V0 { items: Vec::new() };
        assert!(
            record_size > empty_segment.encoded_size(),
            "Record size it smaller that needed to hold any information",
        );
        assert!(
            segment_size > record_size,
            "Segment size is not bigger than record size",
        );
        assert_eq!(
            segment_size % record_size,
            0,
            "Segment size is not a multiple of record size",
        );

        let shards = segment_size / record_size;
        let reed_solomon = ReedSolomon::new(shards, shards)
            .expect("ReedSolomon should always be correctly instantiated");

        Self {
            buffer: VecDeque::default(),
            record_size,
            witness_size,
            segment_size,
            reed_solomon,
            segment_index: 0,
            prev_root_block_hash: Sha256Hash::default(),
        }
    }

    /// Adds new block to internal buffer, potentially producing pieces and root block headers
    pub(super) fn add_block<B: Encode>(&mut self, block: B) -> Vec<ArchivedSegment> {
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

        while segment.encoded_size() < self.segment_size {
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
            let Segment::V0 { items } = &mut segment;
            items.push(segment_item);
        }

        // We may have gotten more data than needed, check and move the excess into the next
        // segment
        {
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

                        (SegmentItem::BlockStart(bytes), block_continuation_bytes)
                    }
                    SegmentItem::BlockStart(_) => {
                        unreachable!("Buffer never contains SegmentItem::BlockStart; qed");
                    }
                    SegmentItem::BlockContinuation(mut block_bytes) => {
                        let split_point = block_bytes.len() - spill_over;
                        let block_continuation_bytes = block_bytes[split_point..].to_vec();

                        block_bytes.truncate(split_point);

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
            }
        }

        Some(segment)
    }

    // Take segment as an input, apply necessary transformations and produce archived segment
    fn produce_archived_segment(&mut self, segment: Segment) -> ArchivedSegment {
        let segment = segment.encode();
        assert_eq!(
            segment.len(),
            self.segment_size,
            "Segment must always be of correct size",
        );

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
                    "With correct archiver parameters there should be just enough space to write \
                    a witness; qed",
                );

                piece.try_into().expect(
                    "With correct archiver parameters piece should always be of a correct \
                        size after this; qed",
                )
            })
            .collect();

        let segment_index = self.segment_index;
        let merkle_tree_root = merkle_tree.root();

        // Now produce root block
        let root_block = RootBlock::V0 {
            segment_index,
            merkle_tree_root,
            prev_root_block_hash: self.prev_root_block_hash,
        };

        let root_block_hash = root_block.hash();

        // Update state
        self.segment_index = segment_index + 1;
        self.prev_root_block_hash = root_block_hash;

        // Add root block to the beginning of the buffer to be the first thing included in the next
        // segment
        self.buffer.push_front(SegmentItem::RootBlock(root_block));

        ArchivedSegment {
            segment_index,
            root_block_hash,
            pieces,
        }
    }
}

// TODO: Tests
