use sp_api::{ApiError, BlockT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_messenger::messages::ExtractedStateRootsFromProof;
use sp_messenger::MessengerApi;
use sp_runtime::traits::NumberFor;
use std::sync::Arc;

type ExtractedStateRoots<Block> = ExtractedStateRootsFromProof<
    NumberFor<Block>,
    <Block as BlockT>::Hash,
    <Block as BlockT>::Hash,
>;

/// Trait to extract XDM state roots from the Extrinsic.
pub trait StateRootExtractor<Block: BlockT> {
    /// Extracts the state roots from the extrinsic.
    fn extract_state_roots(
        &self,
        ext: &Block::Extrinsic,
    ) -> Result<ExtractedStateRoots<Block>, ApiError>;
}

/// Implementation of state root extractor with system domain client.
pub struct StateRootExtractorWithSystemDomainClient<SClient> {
    client: Arc<SClient>,
}

impl<SClient> StateRootExtractorWithSystemDomainClient<SClient> {
    pub fn new(client: Arc<SClient>) -> Self {
        Self { client }
    }
}

impl<SClient> Clone for StateRootExtractorWithSystemDomainClient<SClient> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
        }
    }
}

impl<SClient, SBlock> StateRootExtractor<SBlock>
    for StateRootExtractorWithSystemDomainClient<SClient>
where
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock>,
    SClient::Api: MessengerApi<SBlock, NumberFor<SBlock>>,
    SBlock: BlockT,
{
    fn extract_state_roots(
        &self,
        ext: &SBlock::Extrinsic,
    ) -> Result<ExtractedStateRoots<SBlock>, ApiError> {
        let best_hash = self.client.info().best_hash;
        let api = self.client.runtime_api();
        api.extract_xdm_proof_state_roots(best_hash, ext)
            .and_then(|maybe_state_roots| {
                maybe_state_roots.ok_or(ApiError::Application("Empty state roots".into()))
            })
    }
}
