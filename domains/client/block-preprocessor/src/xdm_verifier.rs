use codec::Encode;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::Error;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;

/// Verifies if the xdm has the correct proof generated from known parent block.
/// This is used by the Domains to validate Extrinsics using their embeded consensus chain.
/// Returns either true if the XDM is valid else false.
/// Returns Error when required calls to fetch header info fails.
pub fn is_valid_xdm<Block, Client>(
    at: Block::Hash,
    client: &Arc<Client>,
    extrinsic: &Block::Extrinsic,
) -> Result<bool, Error>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: MessengerApi<Block, NumberFor<Block>>,
{
    if let Some(valid) = client.runtime_api().is_xdm_valid(at, extrinsic.encode())? {
        Ok(valid)
    } else {
        Ok(true)
    }
}
