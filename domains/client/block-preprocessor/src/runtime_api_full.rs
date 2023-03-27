use crate::runtime_api::{ExtractedStateRoots, StateRootExtractor};
use sp_api::{ApiError, BlockT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_messenger::MessengerApi;
use sp_runtime::traits::NumberFor;
use std::sync::Arc;

/// A runtime api with full backend.
pub struct RuntimeApiFull<Client> {
    client: Arc<Client>,
}

impl<Client> RuntimeApiFull<Client> {
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }
}

impl<Client> Clone for RuntimeApiFull<Client> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
        }
    }
}

impl<Client, Block> StateRootExtractor<Block> for RuntimeApiFull<Client>
where
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: MessengerApi<Block, NumberFor<Block>>,
    Block: BlockT,
{
    fn extract_state_roots(
        &self,
        best_hash: Block::Hash,
        ext: &Block::Extrinsic,
    ) -> Result<ExtractedStateRoots<Block>, ApiError> {
        let api = self.client.runtime_api();
        api.extract_xdm_proof_state_roots(best_hash, ext)
            .and_then(|maybe_state_roots| {
                maybe_state_roots.ok_or(ApiError::Application("Empty state roots".into()))
            })
    }
}
