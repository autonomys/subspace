use codec::Encode;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error, HeaderBackend};
use sp_domains::DomainsApi;
use sp_messenger::messages::BlockInfo;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use std::sync::Arc;

/// Verifies if the xdm has the correct proof generated from known parent block.
/// This is used by the Domains to validate Extrinsics using their embeded consensus chain.
/// Returns either true if the XDM is valid else false.
/// Returns Error when required calls to fetch header info fails.
pub fn is_valid_xdm<CClient, CBlock, Block, Client>(
    consensus_client: &Arc<CClient>,
    at: Block::Hash,
    client: &Arc<Client>,
    extrinsic: &Block::Extrinsic,
) -> Result<bool, Error>
where
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + 'static,
    CClient::Api: DomainsApi<CBlock, Block::Header> + MessengerApi<CBlock, NumberFor<CBlock>>,
    Block: BlockT,
    CBlock: BlockT,
    NumberFor<CBlock>: From<NumberFor<Block>>,
    CBlock::Hash: From<Block::Hash>,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: MessengerApi<Block, NumberFor<Block>>,
{
    if let Some(state_roots) = client
        .runtime_api()
        .extract_xdm_proof_state_roots(at, extrinsic.encode())?
    {
        // verify consensus chain state root
        if let Some(header) =
            consensus_client.header(state_roots.consensus_chain_block_info.block_hash.into())?
        {
            if *header.state_root() != state_roots.consensus_chain_state_root.into() {
                return Ok(false);
            }
        }

        if let Some((domain_id, block_info, state_root)) = state_roots.domain_info {
            if !consensus_client.runtime_api().is_domain_info_confirmed(
                consensus_client.info().best_hash,
                domain_id,
                BlockInfo {
                    block_number: block_info.block_number.into(),
                    block_hash: block_info.block_hash.into(),
                },
                state_root.into(),
            )? {
                return Ok(false);
            }
        }
    }

    Ok(true)
}
