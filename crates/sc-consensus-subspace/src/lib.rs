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

//! `sc-consensus-subspace` is the core of Subspace consensus implementation.
//!
//! You should familiarize yourself with [Subnomicon](https://subnomicon.subspace.network/) and, ideally, protocol
//! specifications. Documentation here assumes decent prior knowledge of the protocol on conceptual level and will not
//! explain how the protocol works, it will instead explain how the protocol is implemented.
//!
//! All of the modules here are crucial for consensus, open each module for specific details.

#![feature(const_option, let_chains, try_blocks)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod archiver;
pub mod aux_schema;
pub mod block_import;
pub mod notification;
pub mod slot_worker;
#[cfg(test)]
mod tests;
pub mod verifier;

use crate::archiver::{ArchivedSegmentNotification, FINALIZATION_DEPTH_IN_SEGMENTS};
use crate::block_import::BlockImportingNotification;
use crate::notification::{SubspaceNotificationSender, SubspaceNotificationStream};
use crate::slot_worker::{NewSlotNotification, RewardSigningNotification};
use lru::LruCache;
use parking_lot::Mutex;
use sp_api::{BlockT, NumberFor};
use sp_consensus_subspace::ChainConstants;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::SegmentHeader;

/// State that must be shared between various consensus components.
#[derive(Clone)]
pub struct SubspaceLink<Block: BlockT> {
    new_slot_notification_sender: SubspaceNotificationSender<NewSlotNotification>,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    reward_signing_notification_sender: SubspaceNotificationSender<RewardSigningNotification>,
    reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    archived_segment_notification_sender: SubspaceNotificationSender<ArchivedSegmentNotification>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegmentNotification>,
    block_importing_notification_sender:
        SubspaceNotificationSender<BlockImportingNotification<Block>>,
    block_importing_notification_stream:
        SubspaceNotificationStream<BlockImportingNotification<Block>>,
    /// Segment headers that are expected to appear in the corresponding blocks, used for block
    /// production and validation
    segment_headers: Arc<Mutex<LruCache<NumberFor<Block>, Vec<SegmentHeader>>>>,
    chain_constants: ChainConstants,
    kzg: Kzg,
}

impl<Block: BlockT> SubspaceLink<Block> {
    /// Create new instance.
    pub fn new(chain_constants: ChainConstants, kzg: Kzg) -> Self {
        let (new_slot_notification_sender, new_slot_notification_stream) =
            notification::channel("subspace_new_slot_notification_stream");
        let (reward_signing_notification_sender, reward_signing_notification_stream) =
            notification::channel("subspace_reward_signing_notification_stream");
        let (archived_segment_notification_sender, archived_segment_notification_stream) =
            notification::channel("subspace_archived_segment_notification_stream");
        let (block_importing_notification_sender, block_importing_notification_stream) =
            notification::channel("subspace_block_importing_notification_stream");

        Self {
            new_slot_notification_sender,
            new_slot_notification_stream,
            reward_signing_notification_sender,
            reward_signing_notification_stream,
            archived_segment_notification_sender,
            archived_segment_notification_stream,
            block_importing_notification_sender,
            block_importing_notification_stream,
            segment_headers: Arc::new(Mutex::new(LruCache::new(
                FINALIZATION_DEPTH_IN_SEGMENTS.saturating_add(1),
            ))),
            chain_constants,
            kzg,
        }
    }

    /// Get stream with notifications about new slot arrival with ability to send solution back.
    pub fn new_slot_notification_stream(&self) -> SubspaceNotificationStream<NewSlotNotification> {
        self.new_slot_notification_stream.clone()
    }

    /// A stream with notifications about headers that need to be signed with ability to send
    /// signature back.
    pub fn reward_signing_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<RewardSigningNotification> {
        self.reward_signing_notification_stream.clone()
    }

    /// Get stream with notifications about archived segment creation
    pub fn archived_segment_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<ArchivedSegmentNotification> {
        self.archived_segment_notification_stream.clone()
    }

    /// Get stream with notifications about each imported block right BEFORE import actually
    /// happens.
    ///
    /// NOTE: all Subspace checks have already happened for this block, but block can still
    /// potentially fail to import in Substrate's internals.
    pub fn block_importing_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<BlockImportingNotification<Block>> {
        self.block_importing_notification_stream.clone()
    }

    /// Get blocks that are expected to be included at specified block number.
    pub fn segment_headers_for_block(&self, block_number: NumberFor<Block>) -> Vec<SegmentHeader> {
        self.segment_headers
            .lock()
            .peek(&block_number)
            .cloned()
            .unwrap_or_default()
    }

    /// Subspace chain constants.
    pub fn chain_constants(&self) -> &ChainConstants {
        &self.chain_constants
    }

    /// Access KZG instance
    pub fn kzg(&self) -> &Kzg {
        &self.kzg
    }
}
