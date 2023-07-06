// TODO: Remove one the subsequent TODO is resolved.
#![allow(unused)]

use crate::runtime_api::StateRootExtractor;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error, HeaderBackend};
use sp_domains::{DomainId, DomainsApi};
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, CheckedSub, Header, NumberFor};
use std::sync::Arc;

/// Verifies if the xdm has the correct proof generated from known parent block.
/// This is used by the System domain to validate Extrinsics.
/// Returns either true if the XDM is valid else false.
/// Returns Error when required calls to fetch header info fails.
pub fn verify_xdm_with_consensus_client<CClient, CBlock, Block, SRE>(
    _domain_id: DomainId,
    consensus_client: &Arc<CClient>,
    at: Block::Hash,
    state_root_extractor: &SRE,
    extrinsic: &Block::Extrinsic,
) -> Result<bool, Error>
where
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + 'static,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
    Block: BlockT,
    CBlock: BlockT,
    NumberFor<CBlock>: From<NumberFor<Block>>,
    CBlock::Hash: From<Block::Hash>,
    SRE: StateRootExtractor<Block>,
{
    if let Ok(_state_roots) = state_root_extractor.extract_state_roots(at, extrinsic) {
        // verify system domain state root
        let _best_hash = consensus_client.info().best_hash;
        let _primary_runtime = consensus_client.runtime_api();
        // TODO: Add `state_root` in DomainsApi
        // if let Some(system_domain_state_root) = primary_runtime.state_root(
        // best_hash,
        // domain_id,
        // state_roots.system_domain_block_info.block_number.into(),
        // state_roots.system_domain_block_info.block_hash.into(),
        // )? {
        // if system_domain_state_root != state_roots.system_domain_state_root {
        // return Ok(false);
        // }
        // }
    }

    Ok(true)
}
