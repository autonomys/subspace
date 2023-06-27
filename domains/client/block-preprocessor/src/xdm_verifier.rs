use crate::runtime_api::StateRootExtractor;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error, HeaderBackend};
use sp_domains::DomainId;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, CheckedSub, Header, NumberFor};
use sp_settlement::SettlementApi;
use std::sync::Arc;

/// Verifies if the xdm has the correct proof generated from known parent block.
/// This is used by Core domain nodes.
/// Core domains nodes use this to verify an XDM coming from other domains.
/// Returns either true if the XDM is valid else false.
/// Returns Error when required calls to fetch header info fails.
pub fn verify_xdm_with_system_domain_client<SClient, Block, SBlock, PBlock, SRE>(
    system_domain_client: &Arc<SClient>,
    at: Block::Hash,
    extrinsic: &Block::Extrinsic,
    state_root_extractor: &SRE,
) -> Result<bool, Error>
where
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: MessengerApi<SBlock, NumberFor<SBlock>> + SettlementApi<SBlock, Block::Hash>,
    Block: BlockT,
    SBlock: BlockT,
    SBlock::Hash: From<Block::Hash>,
    NumberFor<SBlock>: From<NumberFor<Block>>,
    PBlock: BlockT,
    SRE: StateRootExtractor<Block>,
{
    if let Ok(state_roots) = state_root_extractor.extract_state_roots(at, extrinsic) {
        // verify system domain state root
        let header = system_domain_client
            .header(state_roots.system_domain_block_info.block_hash.into())?
            .ok_or(Error::MissingHeader(format!(
                "hash: {}",
                state_roots.system_domain_block_info.block_hash
            )))?;

        if *header.number() != state_roots.system_domain_block_info.block_number.into() {
            return Ok(false);
        }

        if *header.state_root() != state_roots.system_domain_state_root.into() {
            return Ok(false);
        }

        // verify core domain state root and the if the number is K-deep.
        let best_hash = system_domain_client.info().best_hash;
        let api = system_domain_client.runtime_api();
        if let Some((domain_id, core_domain_info, core_domain_state_root)) =
            state_roots.core_domain_info
        {
            let best_number = api.head_receipt_number(best_hash, domain_id)?;
            if let Some(confirmed_number) =
                best_number.checked_sub(&api.confirmation_depth(best_hash)?)
            {
                if confirmed_number < core_domain_info.block_number.into() {
                    return Ok(false);
                }
            }

            if let Some(expected_core_domain_state_root) = api.state_root(
                best_hash,
                domain_id,
                core_domain_info.block_number.into(),
                core_domain_info.block_hash.into(),
            )? {
                if expected_core_domain_state_root != core_domain_state_root {
                    return Ok(false);
                }
            }
        }
    }

    Ok(true)
}

/// Verifies if the xdm has the correct proof generated from known parent block.
/// This is used by the System domain to validate Extrinsics.
/// Returns either true if the XDM is valid else false.
/// Returns Error when required calls to fetch header info fails.
pub fn verify_xdm_with_primary_chain_client<PClient, PBlock, SBlock, SRE>(
    domain_id: DomainId,
    primary_chain_client: &Arc<PClient>,
    at: SBlock::Hash,
    state_root_extractor: &SRE,
    extrinsic: &SBlock::Extrinsic,
) -> Result<bool, Error>
where
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: SettlementApi<PBlock, SBlock::Hash>,
    SBlock: BlockT,
    PBlock: BlockT,
    NumberFor<PBlock>: From<NumberFor<SBlock>>,
    PBlock::Hash: From<SBlock::Hash>,
    SRE: StateRootExtractor<SBlock>,
{
    if let Ok(state_roots) = state_root_extractor.extract_state_roots(at, extrinsic) {
        // verify system domain state root
        let best_hash = primary_chain_client.info().best_hash;
        let primary_runtime = primary_chain_client.runtime_api();
        if let Some(system_domain_state_root) = primary_runtime.state_root(
            best_hash,
            domain_id,
            state_roots.system_domain_block_info.block_number.into(),
            state_roots.system_domain_block_info.block_hash.into(),
        )? {
            if system_domain_state_root != state_roots.system_domain_state_root {
                return Ok(false);
            }
        }
    }

    Ok(true)
}
