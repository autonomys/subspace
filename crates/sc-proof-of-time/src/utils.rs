//! Common utils.

use sp_blockchain::{HeaderBackend, Info};
use sp_consensus::SyncOracle;
use sp_consensus_subspace::digests::extract_pre_digest;
use sp_runtime::traits::{Block as BlockT, Zero};
use std::sync::Arc;
use subspace_core_primitives::{NonEmptyVec, PotProof};
use tracing::info;

/// Helper to retrieve the PoT state from latest tip.
pub(crate) async fn get_consensus_tip_proofs<Block, Client, SO>(
    client: Arc<Client>,
    sync_oracle: Arc<SO>,
    chain_info_fn: Arc<dyn Fn() -> Info<Block> + Send + Sync>,
) -> Result<NonEmptyVec<PotProof>, String>
where
    Block: BlockT,
    Client: HeaderBackend<Block>,
    SO: SyncOracle + Send + Sync + Clone + 'static,
{
    // Wait for sync to complete
    let delay = tokio::time::Duration::from_secs(1);
    info!("get_consensus_tip_proofs(): waiting for sync to complete ...");
    let info = loop {
        while sync_oracle.is_major_syncing() {
            tokio::time::sleep(delay).await;
        }

        // Get the hdr of the best block hash
        let info = (chain_info_fn)();
        if !info.best_number.is_zero() {
            break info;
        }
        info!("get_consensus_tip_proofs(): chain_info: {info:?}, to retry ...");
        tokio::time::sleep(delay).await;
    };

    let header = client
        .header(info.best_hash)
        .map_err(|err| format!("get_consensus_tip_proofs(): failed to get hdr: {err:?}, {info:?}"))?
        .ok_or(format!("get_consensus_tip_proofs(): missing hdr: {info:?}"))?;

    // Get the pre-digest from the block hdr
    let _pre_digest = extract_pre_digest(&header).map_err(|err| {
        format!("get_consensus_tip_proofs(): failed to get pre digest: {err:?}, {info:?}")
    })?;

    // TODO: enable this after adding the proofs to pre-digest.
    /*
    info!(
        "get_consensus_tip_proofs(): {info:?}, pre_digest: slot = {}, num_proofs = {}",
        pre_digest.slot,
        pre_digest.proof_of_time.len()
    );
    NonEmptyVec::new(pre_digest.proof_of_time).map_err(|err| format!("{err:?}"))
     */
    Err("TODO".to_string())
}
