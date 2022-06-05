use sc_client_api::blockchain::HeaderBackend;
use sc_client_api::{BlockBackend, ExecutorProvider, UsageProvider};
use sc_service::Configuration;
use sc_transaction_pool::{BasicPool, FullChainApi, RevalidationType};
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
    let prometheus = config.prometheus_registry();
    let pool_api = Arc::new(FullChainApi::new(client.clone(), prometheus, &spawner));
    let pool = Arc::new(BasicPool::with_revalidation_type(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        pool_api,
        prometheus,
        RevalidationType::Full,
        spawner,
        client.usage_info().chain.best_number,
    ));

    // make transaction pool available for off-chain runtime calls.
    client
        .execution_extensions()
        .register_transaction_pool(&pool);

    pool
}
