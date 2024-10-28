//! Provides synchronization primitives for consensus and domain chains snap sync.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use subspace_core_primitives::BlockNumber;
use tokio::sync::broadcast;
use tokio::sync::broadcast::{Receiver, Sender};
use tracing::debug;

/// Synchronizes consensus and domain chain snap sync.
pub struct SnapSyncOrchestrator {
    consensus_snap_sync_target_block_tx: Sender<BlockNumber>,
    domain_snap_sync_finished: Arc<AtomicBool>,
}

impl Default for SnapSyncOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapSyncOrchestrator {
    /// Constructor
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1);
        Self {
            consensus_snap_sync_target_block_tx: tx,
            domain_snap_sync_finished: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Unblocks (allows) consensus chain snap sync with the given target block.
    pub fn unblock_consensus_snap_sync(&self, target_block_number: BlockNumber) {
        debug!(%target_block_number, "Allowed starting consensus chain snap sync.");

        let target_block_send_result = self
            .consensus_snap_sync_target_block_tx
            .send(target_block_number);

        debug!(
            ?target_block_send_result,
            "Target block sending result: {target_block_number}"
        );
    }

    /// Returns shared variable signaling domain snap sync finished.
    pub fn domain_snap_sync_finished(&self) -> Arc<AtomicBool> {
        self.domain_snap_sync_finished.clone()
    }

    /// Subscribes to a channel to receive target block numbers for consensus chain snap sync.
    pub fn consensus_snap_sync_target_block_receiver(&self) -> Receiver<BlockNumber> {
        self.consensus_snap_sync_target_block_tx.subscribe()
    }

    /// Signal that domain snap sync finished.
    pub fn mark_domain_snap_sync_finished(&self) {
        debug!("Signal that domain snap sync finished.");
        self.domain_snap_sync_finished
            .store(true, Ordering::Release);
    }
}
