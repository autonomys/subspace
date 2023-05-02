pub use fc_consensus::FrontierBlockImport;
pub use fc_db::frontier_database_dir;
use fc_mapping_sync::{MappingSyncWorker, SyncStrategy};
use fc_rpc::{EthTask, OverrideHandle};
pub use fc_rpc_core::types::{FeeHistoryCache, FeeHistoryCacheLimit, FilterPool};
use futures::{future, StreamExt};
use sc_client_api::{BlockchainEvents, StorageProvider};
use sc_service::error::Error as ServiceError;
use sp_api::{BlockT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::traits::{NumberFor, Zero};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Frontier DB backend type.
pub type FrontierBackend<Block> = fc_db::Backend<Block>;

/// The ethereum-compatibility configuration used to run a node.
#[derive(Clone, Debug, clap::Parser)]
pub struct EthConfiguration {
    /// Maximum number of logs in a query.
    #[arg(long, default_value = "10000")]
    pub max_past_logs: u32,

    /// Maximum fee history cache size.
    #[arg(long, default_value = "2048")]
    pub fee_history_limit: u64,

    #[arg(long)]
    pub enable_dev_signer: bool,

    /// The dynamic-fee pallet target gas price set by block author
    #[arg(long, default_value = "1")]
    pub target_gas_price: u64,

    /// Maximum allowed gas limit will be `block.gas_limit * execute_gas_limit_multiplier`
    /// when using eth_call/eth_estimateGas.
    #[arg(long, default_value = "10")]
    pub execute_gas_limit_multiplier: u64,

    /// Size of the LRU cache for block data.
    #[arg(long, default_value = "50")]
    pub eth_log_block_cache: usize,

    /// Size of the LRU cache for transactions statuses data.
    #[arg(long, default_value = "50")]
    pub eth_statuses_cache: usize,
}

pub(crate) struct FrontierPartialComponents {
    pub(crate) filter_pool: Option<FilterPool>,
    pub(crate) fee_history_cache: FeeHistoryCache,
    pub(crate) fee_history_cache_limit: FeeHistoryCacheLimit,
}

pub(crate) fn new_frontier_partial(
    fee_history_cache_limit: u64,
) -> Result<FrontierPartialComponents, ServiceError> {
    Ok(FrontierPartialComponents {
        filter_pool: Some(Arc::new(Mutex::new(BTreeMap::new()))),
        fee_history_cache: Arc::new(Mutex::new(BTreeMap::new())),
        fee_history_cache_limit,
    })
}

pub(crate) fn spawn_frontier_tasks<Block, Client, Backend, SE>(
    essential_task_spawner: SE,
    client: Arc<Client>,
    backend: Arc<Backend>,
    frontier_backend: Arc<FrontierBackend<Block>>,
    overrides: Arc<OverrideHandle<Block>>,
    frontier_partial_components: FrontierPartialComponents,
) where
    Block: BlockT,
    Backend: sc_client_api::Backend<Block> + 'static,
    Client: ProvideRuntimeApi<Block>
        + BlockchainEvents<Block>
        + HeaderBackend<Block>
        + StorageProvider<Block, Backend>
        + Send
        + Sync
        + 'static,
    Client::Api: sp_api::ApiExt<Block>
        + fp_rpc::EthereumRuntimeRPCApi<Block>
        + fp_rpc::ConvertTransactionRuntimeApi<Block>,
    SE: SpawnEssentialNamed,
{
    essential_task_spawner.spawn_essential(
        "frontier-mapping-sync-worker",
        Some("frontier"),
        Box::pin(
            MappingSyncWorker::new(
                client.import_notification_stream(),
                Duration::new(6, 0),
                client.clone(),
                backend,
                overrides.clone(),
                frontier_backend,
                3,
                NumberFor::<Block>::zero(),
                SyncStrategy::Normal,
            )
            .for_each(|()| future::ready(())),
        ),
    );

    let FrontierPartialComponents {
        filter_pool,
        fee_history_cache,
        fee_history_cache_limit,
    } = frontier_partial_components;

    // Spawn Frontier EthFilterApi maintenance task.
    if let Some(filter_pool) = filter_pool {
        // Each filter is allowed to stay in the pool for 100 blocks.
        const FILTER_RETAIN_THRESHOLD: u64 = 100;
        essential_task_spawner.spawn_essential(
            "frontier-filter-pool",
            Some("frontier"),
            Box::pin(EthTask::filter_pool_task(
                client.clone(),
                filter_pool,
                FILTER_RETAIN_THRESHOLD,
            )),
        );
    }

    // Spawn Frontier FeeHistory cache maintenance task.
    essential_task_spawner.spawn_essential(
        "frontier-fee-history",
        Some("frontier"),
        Box::pin(EthTask::fee_history_task(
            client,
            overrides,
            fee_history_cache,
            fee_history_cache_limit,
        )),
    );
}
