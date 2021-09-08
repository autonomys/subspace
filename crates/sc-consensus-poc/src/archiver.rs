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

use codec::Encode;
use reed_solomon_erasure::galois_16::ReedSolomon;
use std::collections::VecDeque;
use std::convert::TryInto;
use std::iter;

/// Segment represents a collection of items stored in archival history of the Subspace blockchain
#[derive(Debug, Encode)]
struct Segment {
    /// Version of the segment data structure and its contents
    version: u8,
    /// Segment items
    items: Vec<SegmentItem>,
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
    Continuation(Vec<u8>),
}

/// Archiver for Subspace blockchain.
///
/// It takes new confirmed (at `K` depth) blocks and concatenates them into a buffer, buffer is
/// sliced into segments of `RECORDED_HISTORY_SEGMENT_SIZE` size, segments are sliced into source
/// records of `RECORD_SIZE`, records are erasure coded, Merkle Tree is built over them, and
/// with Merkle Proofs appended records become pieces that are returned alongside corresponding root
/// block header.
#[derive(Debug)]
pub(super) struct Archiver {
    /// Buffer containing blocks and other buffered items that are pending to be included into the
    /// next segment
    buffer: VecDeque<SegmentItem>,
    /// Version of the segment data structure and its contents
    segment_version: u8,
    /// Configuration parameter defining the size of one record (data in one piece excluding witness
    /// size)
    record_size: usize,
    /// Size of the witness for every record
    witness_size: usize,
    /// Configuration parameter defining the size of one recorded history segment
    segment_size: usize,
    /// Erasure coding data structure
    reed_solomon: ReedSolomon,
}

impl Archiver {
    /// Create a new instance with specified record size and recorded history segment size.
    ///
    /// Panics if:
    /// * record size it smaller that needed to hold any information
    /// * segment size is not bigger than record size
    /// * segment size is not a multiple of record size
    pub(super) fn new(
        segment_version: u8,
        record_size: u32,
        witness_size: u32,
        segment_size: u32,
    ) -> Self {
        let record_size = record_size as usize;
        let witness_size = witness_size as usize;
        let segment_size = segment_size as usize;

        let empty_segment = Segment {
            version: 0,
            items: Vec::new(),
        };
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
            segment_version,
            record_size,
            witness_size,
            segment_size,
            reed_solomon,
        }
    }

    /// Adds new block to internal buffer, potentially producing pieces and root block headers
    pub(super) fn add_block<B: Encode>(&mut self, block: B) {
        // Append new block to the buffer
        self.buffer.push_back(SegmentItem::Block(block.encode()));

        while let Some(segment) = self.produce_segment().map(|s| s.encode()) {
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

            self.reed_solomon
                .encode_sep(&data_shards, &mut parity_shards)
                .expect("Encoding is running with fixed parameters and should never fail");

            let pieces: Vec<Vec<u8>> = data_shards
                .into_iter()
                .chain(parity_shards)
                .map(|shard| {
                    // Here we pre-allocate vectors of piece size (record + witness) to avoid
                    // re-allocations later
                    let mut piece = Vec::with_capacity(self.record_size + self.witness_size);

                    for chunk in shard {
                        piece.extend_from_slice(&chunk);
                    }

                    piece
                })
                .collect();

            // TODO: Build Merkle Tree, fill pieces, etc.
        }
    }

    // Try to slice buffer contents into segments if there is enough data, producing one segment at
    // a time
    fn produce_segment(&mut self) -> Option<Segment> {
        let mut segment = Segment {
            version: self.segment_version,
            items: Vec::with_capacity(self.buffer.len()),
        };

        while segment.encoded_size() < self.segment_size {
            let segment_item = match self.buffer.pop_front() {
                Some(segment_item) => segment_item,
                None => {
                    // Push all of the items back into the buffer, we don't have enough data yet
                    for segment_item in segment.items.into_iter().rev() {
                        self.buffer.push_front(segment_item);
                    }

                    return None;
                }
            };
            segment.items.push(segment_item);
        }

        // We may have gotten more data than needed, check and move the excess into the next
        // segment
        {
            let spill_over = segment.encoded_size() - self.segment_size;

            if spill_over > 0 {
                let segment_item = segment
                    .items
                    .pop()
                    .expect("Segment over segment size always has at least one item; qed");

                let (segment_item, continuation_segment_item_bytes) = match segment_item {
                    SegmentItem::Block(mut bytes) => {
                        let split_point = bytes.len() - spill_over;
                        let continuation_bytes = bytes[split_point..].to_vec();

                        bytes.truncate(split_point);

                        (SegmentItem::BlockStart(bytes), continuation_bytes)
                    }
                    SegmentItem::BlockStart(_) => {
                        unreachable!("Block start never is the first element in the segment; qed",);
                    }
                    SegmentItem::Continuation(mut bytes) => {
                        let split_point = bytes.len() - spill_over;
                        let continuation_bytes = bytes[split_point..].to_vec();

                        bytes.truncate(split_point);

                        (SegmentItem::Continuation(bytes), continuation_bytes)
                    }
                };

                // Push back shortened segment item
                segment.items.push(segment_item);
                // Push continuation element back into the buffer where removed segment item was
                self.buffer
                    .push_front(SegmentItem::Continuation(continuation_segment_item_bytes));
            }
        }

        Some(segment)
    }
}
