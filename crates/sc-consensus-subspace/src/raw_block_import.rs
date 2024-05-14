//! This module enables "raw block import" - import blocks in the blockchain bypassing checks.

use crate::aux_schema::write_block_weight;
use sc_client_api::{backend, BlockBackend, LockImportRun, ProofProvider};
use sc_consensus::{BlockImportParams, ForkChoiceStrategy, StateAction};
use sc_service::{ClientExt, Error};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi};
use sp_objects::ObjectsApi;
use sp_runtime::traits::{Block as BlockT, Header};
use sp_runtime::Justifications;
use tracing::{debug, error};

#[derive(Clone, Debug)]
/// Data container to insert the block into the BlockchainDb without checks.
pub struct RawBlockData<Block: BlockT> {
    /// Block hash
    pub hash: Block::Hash,
    /// Block header
    pub header: Block::Header,
    /// Extrinsics of the block
    pub block_body: Option<Vec<Block::Extrinsic>>,
    /// Justifications of the block
    pub justifications: Option<Justifications>,
}

/// Insert block in the blockchain bypassing checks.
pub fn import_raw_block<B, Block, Client>(
    client: &Client,
    raw_block: RawBlockData<Block>,
) -> Result<(), Error>
where
    B: backend::Backend<Block>,
    Block: BlockT,
    Client: HeaderBackend<Block>
        + ClientExt<Block, B>
        + BlockBackend<Block>
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + LockImportRun<Block, B>
        + Send
        + Sync,
    Client::Api: SubspaceApi<Block, FarmerPublicKey> + ObjectsApi<Block>,
{
    let hash = raw_block.hash;
    let number = *raw_block.header.number();
    debug!("Importing raw block: {number:?}  - {hash:?} ");

    let mut import_block =
        BlockImportParams::new(BlockOrigin::NetworkInitialSync, raw_block.header);
    import_block.justifications = raw_block.justifications;
    import_block.body = raw_block.block_body;
    import_block.state_action = StateAction::Skip;
    import_block.finalized = true;
    import_block.fork_choice = Some(ForkChoiceStrategy::LongestChain);
    import_block.import_existing = false;

    // Set zero block weight to allow the execution of the following blocks.
    write_block_weight(hash, 0, |values| {
        import_block
            .auxiliary
            .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
    });

    let result = client
        .lock_import_and_run(|operation| client.apply_block(operation, import_block, None))
        .map_err(|e| {
            error!("Error during importing of the raw block: {}", e);
            sp_consensus::Error::ClientImport(e.to_string())
        })?;

    debug!("Raw block imported: {number:?}  - {hash:?}. Result: {result:?}");

    Ok(())
}
