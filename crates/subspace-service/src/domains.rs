//! This module provides features for domains integration: snap sync synchronization primitives.

#![warn(missing_docs)]

pub mod snap_sync_orchestrator;

use crate::domains::snap_sync_orchestrator::SnapSyncOrchestrator;
use crate::FullBackend;
use sc_consensus_subspace::SubspaceLink;
use sc_network::NetworkRequest;
use sc_network_sync::SyncingService;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

/// Provides parameters for domain snap sync synchronization with the consensus chain snap sync.
pub struct ConsensusChainSyncParams<Block, CNR>
where
    Block: BlockT,
    CNR: NetworkRequest + Sync + Send,
{
    /// Synchronizes consensus snap sync stages.
    pub snap_sync_orchestrator: Arc<SnapSyncOrchestrator>,
    /// Consensus chain fork ID
    pub fork_id: Option<String>,
    /// Consensus chain network service
    pub network_service: CNR,
    /// Consensus chain sync service
    pub sync_service: Arc<SyncingService<Block>>,
    /// Consensus chain backend (for obtaining offchain storage)
    pub backend: Arc<FullBackend>,
    /// Consensus chain shared state container to access block importing
    pub subspace_link: SubspaceLink<Block>,
}
