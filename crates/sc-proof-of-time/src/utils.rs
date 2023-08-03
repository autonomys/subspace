//! Common utils.

use sp_blockchain::{HeaderBackend, Info};
use sp_consensus::SyncOracle;
use sp_consensus_subspace::digests::{extract_pre_digest, PotPreDigest};
use sp_core::H256;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;
use subspace_core_primitives::{BlockHash, SlotNumber};
use tracing::trace;

/// Info extracted from the consensus tip.
#[derive(Debug)]
pub(crate) struct ConsensusTipInfo<Block: BlockT<Hash = H256>> {
    /// Block hash.
    pub(crate) block_hash: BlockHash,

    /// Block number.
    pub(crate) block_number: NumberFor<Block>,

    /// Slot number for the block.
    pub(crate) slot_number: SlotNumber,

    /// The PoT from the pre digest
    pub(crate) pot_pre_digest: PotPreDigest,
}

/// Helper to retrieve the PoT state from latest tip.
pub(crate) async fn get_consensus_tip<Block, Client, SO>(
    client: Arc<Client>,
    sync_oracle: Arc<SO>,
    chain_info_fn: Arc<dyn Fn() -> Info<Block> + Send + Sync>,
) -> Result<ConsensusTipInfo<Block>, String>
where
    Block: BlockT<Hash = H256>,
    Client: HeaderBackend<Block>,
    SO: SyncOracle + Send + Sync + Clone + 'static,
{
    let delay = tokio::time::Duration::from_secs(1);
    trace!("get_consensus_tip(): waiting for sync to complete ...");
    while sync_oracle.is_major_syncing() {
        tokio::time::sleep(delay).await;
    }

    let info = (chain_info_fn)();
    trace!("get_consensus_tip(): sync complete. chain_info = {info:?}");
    let header = client
        .header(info.best_hash)
        .map_err(|err| format!("get_consensus_tip(): failed to get hdr: {err:?}, {info:?}"))?
        .ok_or(format!("get_consensus_tip(): missing hdr: {info:?}"))?;

    let pre_digest = extract_pre_digest(&header).map_err(|err| {
        format!("get_consensus_tip_proofs(): failed to get pre digest: {err:?}, {info:?}")
    })?;

    Ok(ConsensusTipInfo {
        block_hash: info.best_hash.to_fixed_bytes(),
        block_number: info.best_number,
        slot_number: pre_digest.slot.into(),
        pot_pre_digest: pre_digest.proof_of_time.unwrap_or_default(),
    })
}
