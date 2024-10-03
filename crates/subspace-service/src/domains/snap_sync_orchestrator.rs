//! Provides synchronization primitives for consensus and domain chains snap sync.

use crate::sync_from_dsn::snap_sync::{DefaultTargetBlockProvider, SnapSyncTargetBlockProvider};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::Arc;
use subspace_core_primitives::BlockNumber;
use tokio::sync::Notify;
use tracing::debug;

pub(crate) fn create_target_block_provider(
    snap_sync_orchestrator: Option<Arc<SnapSyncOrchestrator>>,
) -> Arc<dyn SnapSyncTargetBlockProvider> {
    if let Some(snap_sync_orchestrator) = snap_sync_orchestrator {
        snap_sync_orchestrator
    } else {
        Arc::new(DefaultTargetBlockProvider)
    }
}

/// Synchronizes consensus and domain chain snap sync.
pub struct SnapSyncOrchestrator {
    notify_consensus_snap_sync_unblocked: Notify,
    consensus_snap_sync_block_number: Mutex<Option<BlockNumber>>,
    notify_domain_snap_sync_finished: Notify,
    domain_snap_sync_finished: Mutex<bool>,
}

#[async_trait]
impl SnapSyncTargetBlockProvider for SnapSyncOrchestrator {
    async fn target_block(&self) -> Option<BlockNumber> {
        self.consensus_snap_sync_unblocked().await;

        self.target_consensus_snap_sync_block_number()
    }
}

impl Default for SnapSyncOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapSyncOrchestrator {
    /// Constructor
    pub fn new() -> Self {
        Self {
            notify_consensus_snap_sync_unblocked: Notify::new(),
            consensus_snap_sync_block_number: Mutex::new(None),
            notify_domain_snap_sync_finished: Notify::new(),
            domain_snap_sync_finished: Mutex::new(false),
        }
    }

    /// Returns optional target block for consensus chain snap sync. None means target block is
    /// not defined yet.
    pub fn target_consensus_snap_sync_block_number(&self) -> Option<BlockNumber> {
        *self.consensus_snap_sync_block_number.lock()
    }

    /// Wait for the allowing signal for the consensus chain snap sync.
    pub async fn consensus_snap_sync_unblocked(&self) {
        debug!("Waiting for a signal to start consensus chain snap sync.");
        self.notify_consensus_snap_sync_unblocked.notified().await;
        debug!("Finished waiting for a signal to start consensus chain snap sync.");
    }

    /// Unblocks (allows) consensus chain snap sync with the given target block.
    pub fn unblock_consensus_snap_sync(&self, target_block_number: BlockNumber) {
        debug!(%target_block_number, "Allowed starting consensus chain snap sync.");
        self.consensus_snap_sync_block_number
            .lock()
            .replace(target_block_number);

        self.notify_consensus_snap_sync_unblocked.notify_waiters();
    }

    /// Returns true if domain snap sync finished.
    pub fn domain_snap_sync_finished(&self) -> bool {
        *self.domain_snap_sync_finished.lock()
    }

    /// Signal that domain snap sync finished.
    pub fn mark_domain_snap_sync_finished(&self) {
        debug!("Signal that domain snap sync finished.");
        *self.domain_snap_sync_finished.lock() = true;

        self.notify_domain_snap_sync_finished.notify_waiters();
    }

    /// Wait for a signal that domain snap sync finished.
    pub async fn domain_snap_sync_finished_blocking(&self) {
        debug!("Waiting for a signal that domain snap sync finished.");
        self.notify_domain_snap_sync_finished.notified().await;
        debug!("Finished waiting for a signal that domain snap sync finished.");
    }

    /// Unblock all processes (synchronization cancelled).
    pub fn unblock_all(&self) {
        debug!("Allow all processes (synchronization cancelled).");

        self.notify_consensus_snap_sync_unblocked.notify_waiters();
        self.notify_domain_snap_sync_finished.notify_waiters();
        *self.domain_snap_sync_finished.lock() = true;
    }
}
