use crate::runtime_api::{
    ExtractSignerResult, ExtractedStateRoots, IsInherentExtrinsic, SetCodeConstructor,
    SignerExtractor, StateRootExtractor, TimestampExtrinsicConstructor,
};
use codec::Encode;
use domain_runtime_primitives::DomainCoreApi;
use sp_api::{ApiError, BlockT, ProvideRuntimeApi};
use sp_messenger::MessengerApi;
use sp_runtime::traits::NumberFor;
use std::sync::Arc;
use subspace_runtime_primitives::Moment;

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
    Client: ProvideRuntimeApi<Block>,
    Client::Api: MessengerApi<Block, NumberFor<Block>>,
    Block: BlockT,
{
    fn extract_state_roots(
        &self,
        best_hash: Block::Hash,
        ext: &Block::Extrinsic,
    ) -> Result<ExtractedStateRoots<Block>, ApiError> {
        let maybe_state_roots = self
            .client
            .runtime_api()
            .extract_xdm_proof_state_roots(best_hash, ext.encode())?;
        maybe_state_roots.ok_or(ApiError::Application("Empty state roots".into()))
    }
}

impl<Block, Client> TimestampExtrinsicConstructor<Block> for RuntimeApiFull<Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: DomainCoreApi<Block>,
{
    fn construct_timestamp_extrinsic(
        &self,
        at: Block::Hash,
        moment: Moment,
    ) -> Result<Block::Extrinsic, ApiError> {
        let api = self.client.runtime_api();
        api.construct_timestamp_extrinsic(at, moment)
    }
}

impl<Client, Block> SignerExtractor<Block> for RuntimeApiFull<Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: DomainCoreApi<Block>,
{
    fn extract_signer(
        &self,
        at: Block::Hash,
        extrinsics: Vec<<Block as BlockT>::Extrinsic>,
    ) -> Result<ExtractSignerResult<Block>, ApiError> {
        let api = self.client.runtime_api();
        api.extract_signer(at, extrinsics)
    }
}

impl<Client, Block> SetCodeConstructor<Block> for RuntimeApiFull<Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: DomainCoreApi<Block>,
{
    fn construct_set_code_extrinsic(
        &self,
        at: Block::Hash,
        runtime_code: Vec<u8>,
    ) -> Result<Vec<u8>, ApiError> {
        let api = self.client.runtime_api();
        api.construct_set_code_extrinsic(at, runtime_code)
    }
}

impl<Client, Block> IsInherentExtrinsic<Block> for RuntimeApiFull<Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: DomainCoreApi<Block>,
{
    fn is_inherent_extrinsic(
        &self,
        at: Block::Hash,
        extrinsic: &<Block as BlockT>::Extrinsic,
    ) -> Result<bool, ApiError> {
        let api = self.client.runtime_api();
        api.is_inherent_extrinsic(at, extrinsic)
    }
}
