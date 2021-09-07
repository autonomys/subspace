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

/// Slicer for Subspace blockchain.
///
/// It takes new confirmed (at `K` depth) blocks and concatenates them into a buffer, buffer is
/// sliced into returned segments.
#[derive(Debug)]
pub(super) struct Slicer {
    /// Buffer containing blocks and other buffered items that are pending to be included into the
    /// next segment
    buffer: VecDeque<SegmentItem>,
    /// Configuration parameter defining the size of one recorded history segment
    segment_size: usize,
}

impl Slicer {
    pub(super) fn new(recorded_history_segment_size: u32) -> Self {
        Self {
            buffer: VecDeque::default(),
            segment_size: recorded_history_segment_size as usize,
        }
    }

    pub(super) fn add_block<B: Encode>(&mut self, block: B) -> Vec<Segment> {
        // Append new block to the buffer
        self.buffer.push_back(SegmentItem::Block(block.encode()));

        // Try to slice buffer contents into segments if there is enough data
        let segments = Vec::new();

        // TODO: Producer segments
        // while self.0.encoded_size() > self.segment_size {
        //     segments.push(todo);
        // }

        segments
    }
}
