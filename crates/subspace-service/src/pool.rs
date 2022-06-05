use sc_client_api::blockchain::HeaderBackend;
use sc_client_api::{BlockBackend, ExecutorProvider, UsageProvider};
use sc_service::Configuration;
use sc_transaction_pool::{BasicPool, FullChainApi};
use sp_api::ProvideRuntimeApi;
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::traits::{Block as BlockT, BlockIdTo};
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::sync::Arc;

pub(super) fn new_full<Block, Client>(
    config: &Configuration,
    spawner: impl SpawnEssentialNamed,
    client: Arc<Client>,
) -> Arc<BasicPool<FullChainApi<Client, Block>, Block>>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + ExecutorProvider<Block>
        + UsageProvider<Block>
        + BlockIdTo<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: TaggedTransactionQueue<Block>,
{
    sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        config.prometheus_registry(),
        spawner,
        client,
    )
}
