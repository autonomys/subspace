use crate::runtime_api::{
    CoreBundleConstructor, ExtractSignerResult, ExtractedStateRoots, SignerExtractor,
    StateRootExtractor,
};
use codec::Codec;
use domain_runtime_primitives::DomainCoreApi;
use sp_api::{ApiError, BlockT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::SignedOpaqueBundle;
use sp_messenger::MessengerApi;
use sp_runtime::traits::NumberFor;
use std::sync::Arc;
use system_runtime_primitives::SystemDomainApi;

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

impl<PBlock, Client, Block> CoreBundleConstructor<PBlock, Block> for RuntimeApiFull<Client>
where
    PBlock: BlockT,
    Block: BlockT,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>,
{
    fn construct_submit_core_bundle_extrinsics(
        &self,
        at: Block::Hash,
        signed_opaque_bundles: Vec<
            SignedOpaqueBundle<NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
        >,
    ) -> Result<Vec<Vec<u8>>, ApiError> {
        let api = self.client.runtime_api();
        api.construct_submit_core_bundle_extrinsics(at, signed_opaque_bundles)
    }
}

impl<Client, Block, AccountId> SignerExtractor<Block, AccountId> for RuntimeApiFull<Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: DomainCoreApi<Block, AccountId>,
    AccountId: Codec,
{
    fn extract_signer(
        &self,
        at: Block::Hash,
        extrinsics: Vec<<Block as BlockT>::Extrinsic>,
    ) -> Result<ExtractSignerResult<Block, AccountId>, ApiError> {
        let api = self.client.runtime_api();
        api.extract_signer(at, extrinsics)
    }
}
