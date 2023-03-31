use crate::runtime_api::StateRootExtractor;
use crate::utils::extract_xdm_proof_state_roots_with_client;
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::{Error, HeaderBackend};
use sp_domains::ExecutorApi;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, CheckedSub, Header, NumberFor};
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

/// Verifies if the xdm has the correct proof generated from known parent block.
/// This is used by Core domain nodes.
/// Core domains nodes use this to verify an XDM coming from other domains.
/// Returns either true if the XDM is valid else false.
/// Returns Error when required calls to fetch header info fails.
pub fn verify_xdm_with_system_domain_client<Client, Block, SBlock, PBlock>(
    system_domain_client: &Arc<Client>,
    extrinsic: &SBlock::Extrinsic,
) -> Result<bool, Error>
where
    Client: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    Client::Api: MessengerApi<SBlock, NumberFor<SBlock>>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
{
    let api = system_domain_client.runtime_api();
    let best_hash = system_domain_client.info().best_hash;
    let messenger_api_version = api
        .api_version::<dyn MessengerApi<SBlock, NumberFor<SBlock>>>(best_hash)?
        .ok_or_else(|| {
            Error::Application(
                format!("Could not find `MessengerApi` api for block `{best_hash:?}`.").into(),
            )
        })?;
    if let Ok(Some(state_roots)) = extract_xdm_proof_state_roots_with_client(
        messenger_api_version,
        &*api,
        best_hash,
        extrinsic,
    ) {
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

        // verify core domain state root and the if the number is K-deep.
        if let Some((domain_id, core_domain_info, core_domain_state_root)) =
            state_roots.core_domain_info
        {
            let best_number = api.head_receipt_number(best_hash, domain_id)?;
            if let Some(confirmed_number) =
                best_number.checked_sub(&api.confirmation_depth(best_hash)?)
            {
                if confirmed_number < core_domain_info.block_number {
                    return Ok(false);
                }
            }

            if let Some(expected_core_domain_state_root) = api.core_domain_state_root_at(
                best_hash,
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

/// Verifies if the xdm has the correct proof generated from known parent block.
/// This is used by the System domain to validate Extrinsics.
/// Returns either true if the XDM is valid else false.
/// Returns Error when required calls to fetch header info fails.
pub fn verify_xdm_with_primary_chain_client<PClient, PBlock, SBlock, SRE>(
    primary_chain_client: &Arc<PClient>,
    at: SBlock::Hash,
    state_root_extractor: &SRE,
    extrinsic: &SBlock::Extrinsic,
) -> Result<bool, Error>
where
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, SBlock::Hash>,
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
        if let Some(system_domain_state_root) = primary_runtime.system_domain_state_root_at(
            best_hash,
            state_roots.system_domain_block_info.block_number.into(),
            state_roots.system_domain_block_info.block_hash,
        )? {
            if system_domain_state_root != state_roots.system_domain_state_root.into() {
                return Ok(false);
            }
        }
    }

    Ok(true)
}
