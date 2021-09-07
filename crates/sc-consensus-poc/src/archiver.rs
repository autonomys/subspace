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

use sp_runtime::generic::SignedBlock;
use sp_runtime::traits::{Block as BlockT, NumberFor};

/// State associated with archiving process of Subspace blockchain (permanent storage of
/// blocks).
#[derive(Debug)]
struct RecordingHistoryState<Block: BlockT> {
    /// Last block that was included into recorded history, used to determine what blocks should be
    /// included next.
    ///
    /// NOTE: This block might be included partially if it was large enough to be split over into
    /// the next segment.
    last_recorded_block: Option<NumberFor<Block>>,
    /// How much data from `last_recorded_block` was spilled over into the next segment, such that
    /// we can extract it and prepend to the next segment.
    spill_over_offset: u32,
    /// Total amount of buffered data in bytes that is pending to be included into the next segment,
    /// will include data of the last block spilled over into the next segment.
    buffered_data: u32,
}

impl<Block: BlockT> Default for RecordingHistoryState<Block> {
    fn default() -> Self {
        Self {
            last_recorded_block: None,
            spill_over_offset: 0,
            buffered_data: 0,
        }
    }
}

pub(super) struct ArchivedSegment {
    segment: Vec<u8>,
    // TODO
    root_block_header: (),
}

pub(super) enum ArchivingResult {
    Success { segments: Vec<ArchivedSegment> },
}

#[derive(Debug)]
pub(super) struct Archiver<Block: BlockT> {
    recorded_history_segment_size: u32,
    state: RecordingHistoryState<Block>,
}

impl<Block: BlockT> Archiver<Block> {
    pub(super) fn new(recorded_history_segment_size: u32) -> Self {
        Self {
            recorded_history_segment_size,
            state: RecordingHistoryState::default(),
        }
    }

    pub(super) fn add_block(&self, block: SignedBlock<Block>) -> ArchivingResult {
        // TODO
        ArchivingResult::Success { segments: vec![] }
    }
}
