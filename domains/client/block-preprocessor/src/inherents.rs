//! Provides functionality of adding inherent extrinsics to the Domain.
//! Unlike Primary chain where inherent data is first derived the block author
//! and the data is verified by the on primary runtime, domains inherents
//! short circuit the derivation and verification of inherent data
//! as the inherent data is directly taken from the primary block from which
//! domain block is being built.
//!
//! One of the first use case for this is passing Timestamp data. Before building a
//! domain block using a primary block, we take the current time from the primary runtime
//! and then create an unsigned extrinsic that is put on top the bundle extrinsics.
//!
//! Deriving these extrinsics during fraud proof verification should be possible since
//! verification environment will have access to consensus chain.

use crate::runtime_api::InherentExtrinsicConstructor;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_domains::DomainsApi;
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_timestamp::InherentType;
use std::error::Error;
use std::marker::PhantomData;
use std::sync::Arc;

/// Returns required inherent extrinsics for the domain block based on the primary block.
/// Note: consensus block hash must be used to construct domain block.
pub(crate) fn construct_inherent_extrinsics<Block, DomainRuntimeApi, CBlock, CClient>(
    consensus_client: &Arc<CClient>,
    domain_runtime_api: &DomainRuntimeApi,
    consensus_block_hash: CBlock::Hash,
    domain_parent_hash: Block::Hash,
) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error>
where
    Block: BlockT,
    CBlock: BlockT,
    CClient: ProvideRuntimeApi<CBlock>,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
    DomainRuntimeApi: InherentExtrinsicConstructor<Block>,
{
    let moment = consensus_client
        .runtime_api()
        .timestamp(consensus_block_hash)?;

    let mut inherent_exts = vec![];
    if let Some(inherent_timestamp) =
        domain_runtime_api.construct_timestamp_inherent_extrinsic(domain_parent_hash, moment)?
    {
        inherent_exts.push(inherent_timestamp)
    }

    Ok(inherent_exts)
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct CreateInherentDataProvider<CClient, CBlock> {
    consensus_client: Arc<CClient>,
    _marker: PhantomData<CBlock>,
}

impl<CClient, CBlock: Clone> Clone for CreateInherentDataProvider<CClient, CBlock> {
    fn clone(&self) -> Self {
        Self {
            consensus_client: self.consensus_client.clone(),
            _marker: Default::default(),
        }
    }
}

impl<CClient, CBlock> CreateInherentDataProvider<CClient, CBlock> {
    pub fn new(consensus_client: Arc<CClient>) -> Self {
        Self {
            consensus_client,
            _marker: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl<CClient, CBlock, Block> CreateInherentDataProviders<Block, ()>
    for CreateInherentDataProvider<CClient, CBlock>
where
    Block: BlockT,
    CBlock: BlockT,
    CClient: ProvideRuntimeApi<CBlock> + HeaderBackend<CBlock>,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>,
{
    // TODO: we need to include the runtime upgrade
    type InherentDataProviders = sp_timestamp::InherentDataProvider;

    async fn create_inherent_data_providers(
        &self,
        _parent: Block::Hash,
        _extra_args: (),
    ) -> Result<Self::InherentDataProviders, Box<dyn Error + Send + Sync>> {
        let best_consensus_hash = self.consensus_client.info().best_hash;
        let runtime_api = self.consensus_client.runtime_api();
        let timestamp = runtime_api.timestamp(best_consensus_hash)?;
        Ok(sp_timestamp::InherentDataProvider::new(InherentType::new(
            timestamp,
        )))
    }
}
