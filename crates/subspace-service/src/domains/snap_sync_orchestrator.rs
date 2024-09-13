//! Provides synchronization primitives for consensus and domain chains snap sync.

use parking_lot::Mutex;
use subspace_core_primitives::BlockNumber;
use tokio::sync::Notify;
use tracing::debug;

/// Synchronizes consensus and domain chain snap sync.
pub struct SnapSyncOrchestrator {
    notify_consensus_snap_sync_unblocked: Notify,
    consensus_snap_sync_block_number: Mutex<Option<BlockNumber>>,
    notify_domain_snap_sync_unblocked: Notify,
    notify_other_consensus_sync_strategies_unblocked: Notify,
    notify_domain_snap_sync_finished: Notify,
    domain_snap_sync_finished: Mutex<bool>,
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
            notify_domain_snap_sync_unblocked: Notify::new(),
            notify_other_consensus_sync_strategies_unblocked: Notify::new(),
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

    /// Wait for the allowing signal for the domain chain snap sync.
    pub async fn domain_snap_sync_unblocked(&self) {
        debug!("Waiting for a signal to start domain chain snap sync.");

        self.notify_domain_snap_sync_unblocked.notified().await;
        debug!("Finished waiting for a signal to start domain chain snap sync.");
    }

    /// Unblocks (allows) domain chain snap sync.
    pub fn unblock_domain_snap_sync(&self) {
        debug!("Allowed starting domain chain snap sync.");
        self.notify_domain_snap_sync_unblocked.notify_waiters();
    }

    /// Returns true if domain snap sync finished.
    pub fn domain_snap_sync_finished(&self) -> bool {
        *self.domain_snap_sync_finished.lock()
    }

    /// Other consensus chain sync strategies (DSN sync or Substrate sync) are allowed.
    pub async fn resuming_other_consensus_sync_strategies_unblocked(&self) {
        debug!("Waiting for a signal to resume other sync strategies for consensus sync.");
        self.notify_other_consensus_sync_strategies_unblocked
            .notified()
            .await;
        debug!("Finished waiting for a signal to resume other sync strategies for consensus sync.");
    }

    /// Unblock other consensus chain sync strategies (DSN sync or Substrate sync).
    pub fn unblock_other_consensus_chain_sync_strategies(&self) {
        debug!("Unblocked resuming other consensus chain sync strategies.");
        self.notify_other_consensus_sync_strategies_unblocked
            .notify_waiters();
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
        self.notify_domain_snap_sync_unblocked.notify_waiters();
        self.notify_other_consensus_sync_strategies_unblocked
            .notify_waiters();

        self.notify_domain_snap_sync_finished.notify_waiters();
        *self.domain_snap_sync_finished.lock() = true;
    }
}
