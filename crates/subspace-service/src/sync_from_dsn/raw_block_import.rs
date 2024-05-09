use parity_scale_codec::Encode;
use sc_client_api::{backend, BlockBackend, LockImportRun, ProofProvider};
use sc_consensus::{BlockImportParams, ForkChoiceStrategy, StateAction};
use sc_service::{ClientExt, Error};
use sp_api::ProvideRuntimeApi;
use sp_api::__private::BlockT;
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi};
use sp_objects::ObjectsApi;
use sp_runtime::traits::Header;
use sp_runtime::Justifications;
use tracing::{debug, error};

pub type BlockWeight = u128;

/// Write the cumulative chain-weight of a block ot aux storage.
fn write_block_weight<H: Encode, F, R>(block_hash: H, block_weight: BlockWeight, write_aux: F) -> R
where
    F: FnOnce(&[(Vec<u8>, &[u8])]) -> R,
{
    let key = block_weight_key(block_hash);
    block_weight.using_encoded(|s| write_aux(&[(key, s)]))
}

/// The aux storage key used to store the block weight of the given block hash.
fn block_weight_key<H: Encode>(block_hash: H) -> Vec<u8> {
    (b"block_weight", block_hash).encode()
}

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

#[allow(dead_code)] // TODO: remove after adding the usage
pub(crate) fn import_raw_block<B, Block, Client>(
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
        + Sync
        + 'static,
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
