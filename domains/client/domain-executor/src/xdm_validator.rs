use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error, HeaderBackend};
use sp_messenger::MessengerApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

/// Verifies if the xdm has the correct proof generated from known parent block.
/// This is used by Core domain nodes and also System domain nodes
/// Core domains nodes use this to verify an XDM coming from other domains.
/// System domain node use this to verify the XDM while validating fraud proof.
/// Returns either true if the XDM is valid else false.
/// Returns Error when required calls to fetch header info fails.
#[allow(dead_code)]
fn verify_xdm_with_system_domain_client<Client, Block, PBlock>(
    system_domain_client: &Arc<Client>,
    extrinsic: &Block::Extrinsic,
) -> Result<bool, Error>
where
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block> + 'static,
    Client::Api: MessengerApi<Block, NumberFor<Block>>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>,
    Block: BlockT,
    PBlock: BlockT,
{
    let api = system_domain_client.runtime_api();
    let block_id = BlockId::Hash(system_domain_client.info().best_hash);
    if let Ok(Some(state_roots)) = api.extract_xdm_proof_state_roots(&block_id, extrinsic) {
        // verify system domain state root
        let header = system_domain_client
            .header(state_roots.system_domain_block_info.block_hash)?
            .ok_or(Error::MissingHeader(format!(
                "hash: {}",
                state_roots.system_domain_block_info.block_hash
            )))?;

        if *header.number() != state_roots.system_domain_block_info.block_number {
            return Ok(false);
        }

        if *header.state_root() != state_roots.system_domain_state_root {
            return Ok(false);
        }

        // verify core domain state root if there is one
        if let Some((domain_id, core_domain_info, core_domain_state_root)) =
            state_roots.core_domain_info
        {
            if let Some(expected_core_domain_state_root) = api.core_domain_state_root_at(
                &block_id,
                domain_id,
                core_domain_info.block_number,
                core_domain_info.block_hash,
            )? {
                if expected_core_domain_state_root != core_domain_state_root {
                    return Ok(false);
                }
            }
        }
    }

    Ok(true)
}
