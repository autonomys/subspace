//! `sc-consensus-subspace` is the core of Subspace consensus implementation.
//!
//! You should familiarize yourself with [Subnomicon](https://subnomicon.subspace.network/) and, ideally, protocol
//! specifications. Documentation here assumes decent prior knowledge of the protocol on conceptual level and will not
//! explain how the protocol works, it will instead explain how the protocol is implemented.
//!
//! All of the modules here are crucial for consensus, open each module for specific details.

#![feature(let_chains, try_blocks, duration_constructors)]
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

use crate::archiver::{ArchivedSegmentNotification, ObjectMappingNotification};
use crate::block_import::BlockImportingNotification;
use crate::notification::{SubspaceNotificationSender, SubspaceNotificationStream};
use crate::slot_worker::{NewSlotNotification, RewardSigningNotification};
use sp_consensus_subspace::ChainConstants;
use sp_runtime::traits::Block as BlockT;
use subspace_erasure_coding::ErasureCoding;
use subspace_kzg::Kzg;

/// State that must be shared between various consensus components.
#[derive(Clone)]
pub struct SubspaceLink<Block: BlockT> {
    new_slot_notification_sender: SubspaceNotificationSender<NewSlotNotification>,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    reward_signing_notification_sender: SubspaceNotificationSender<RewardSigningNotification>,
    reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    object_mapping_notification_sender: SubspaceNotificationSender<ObjectMappingNotification>,
    object_mapping_notification_stream: SubspaceNotificationStream<ObjectMappingNotification>,
    archived_segment_notification_sender: SubspaceNotificationSender<ArchivedSegmentNotification>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegmentNotification>,
    block_importing_notification_sender:
        SubspaceNotificationSender<BlockImportingNotification<Block>>,
    block_importing_notification_stream:
        SubspaceNotificationStream<BlockImportingNotification<Block>>,
    chain_constants: ChainConstants,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
}

impl<Block: BlockT> SubspaceLink<Block> {
    /// Create new instance.
    pub fn new(chain_constants: ChainConstants, kzg: Kzg, erasure_coding: ErasureCoding) -> Self {
        let (new_slot_notification_sender, new_slot_notification_stream) =
            notification::channel("subspace_new_slot_notification_stream");
        let (reward_signing_notification_sender, reward_signing_notification_stream) =
            notification::channel("subspace_reward_signing_notification_stream");
        let (object_mapping_notification_sender, object_mapping_notification_stream) =
            notification::channel("subspace_object_mapping_notification_stream");
        let (archived_segment_notification_sender, archived_segment_notification_stream) =
            notification::channel("subspace_archived_segment_notification_stream");
        let (block_importing_notification_sender, block_importing_notification_stream) =
            notification::channel("subspace_block_importing_notification_stream");

        Self {
            new_slot_notification_sender,
            new_slot_notification_stream,
            reward_signing_notification_sender,
            reward_signing_notification_stream,
            object_mapping_notification_sender,
            object_mapping_notification_stream,
            archived_segment_notification_sender,
            archived_segment_notification_stream,
            block_importing_notification_sender,
            block_importing_notification_stream,
            chain_constants,
            kzg,
            erasure_coding,
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

    /// Get stream with notifications about object mappings
    pub fn object_mapping_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<ObjectMappingNotification> {
        self.object_mapping_notification_stream.clone()
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

    /// Subspace chain constants.
    pub fn chain_constants(&self) -> &ChainConstants {
        &self.chain_constants
    }

    /// Access KZG instance
    pub fn kzg(&self) -> &Kzg {
        &self.kzg
    }

    /// Access erasure coding instance
    pub fn erasure_coding(&self) -> &ErasureCoding {
        &self.erasure_coding
    }
}
