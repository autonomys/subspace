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
use std::collections::VecDeque;
use std::ops::Deref;

pub(super) struct Segment(Vec<u8>);

impl Deref for Segment {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Segment> for Vec<u8> {
    fn from(segment: Segment) -> Self {
        segment.0
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
    /// Configuration parameter defining the size of one recorded history segment
    segment_size: usize,
    /// Configuration parameter defining the size of one record (data in one piece excluding witness
    /// size)
    record_size: usize,
}

impl Archiver {
    /// Create a new instance with specified record size and recorded history segment size.
    ///
    /// Panics if:
    /// * record_size it smaller that needed to hold any information
    /// * segment size is not bigger than record size
    /// * segment size is not a multiple of record size
    pub(super) fn new(record_size: u32, segment_size: u32) -> Self {
        assert!(record_size as usize > Vec::<u8>::new().encoded_size());
        assert!(segment_size > record_size);
        assert_eq!(segment_size % record_size, 0);

        Self {
            buffer: VecDeque::default(),
            segment_size: segment_size as usize,
            record_size: record_size as usize,
        }
    }

    /// Adds new block to internal buffer, potentially producing pieces and root block headers
    pub(super) fn add_block<B: Encode>(&mut self, block: B) {
        // Append new block to the buffer
        self.buffer.push_back(SegmentItem::Block(block.encode()));

        // Try to slice buffer contents into segments if there is enough data
        while self.buffer.encoded_size() >= self.segment_size {
            let mut segment = Vec::with_capacity(self.buffer.len());

            while segment.encoded_size() < self.segment_size {
                let segment_item = self.buffer.pop_front().expect(
                    "Size of the buffer is at least as big as one segment, so this will never \
                    return None; qed",
                );
                segment.push(segment_item);
            }

            // We may have gotten more data than needed, check and move the excess into the next
            // segment
            {
                let spill_over = segment.encoded_size() - self.segment_size;

                if spill_over > 0 {
                    let segment_item = segment
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
                            unreachable!("Block start never goes into the next segment; qed")
                        }
                        SegmentItem::Continuation(mut bytes) => {
                            let split_point = bytes.len() - spill_over;
                            let continuation_bytes = bytes[split_point..].to_vec();

                            bytes.truncate(split_point);

                            (SegmentItem::Continuation(bytes), continuation_bytes)
                        }
                    };

                    // Push back shortened segment item
                    segment.push(segment_item);
                    // Push continuation element back into the buffer where removed segment item was
                    self.buffer
                        .push_front(SegmentItem::Continuation(continuation_segment_item_bytes));
                }
            }

            let segment = segment.encode();

            // TODO: Erasure coding, slice into records, build Merkle Tree, create pieces, etc.
        }
    }
}
