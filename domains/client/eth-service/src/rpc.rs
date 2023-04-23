use domain_service::rpc::FullDeps;
use fc_db::Backend as FrontierBackend;
use fc_rpc::{
    Eth, EthApiServer, EthDevSigner, EthFilter, EthFilterApiServer, EthPubSub, EthPubSubApiServer,
    EthSigner, Net, NetApiServer, Web3, Web3ApiServer,
};
pub use fc_rpc::{EthBlockDataCacheTask, EthConfig, StorageOverride};
pub use fc_rpc_core::types::{FeeHistoryCache, FeeHistoryCacheLimit, FilterPool};
pub use fc_storage::overrides_handle;
use fc_storage::OverrideHandle;
use fp_rpc::{ConvertTransaction, ConvertTransactionRuntimeApi, EthereumRuntimeRPCApi};
use jsonrpsee::RpcModule;
use sc_client_api::backend::{Backend, StorageProvider};
use sc_client_api::client::BlockchainEvents;
use sc_rpc::SubscriptionTaskExecutor;
use sc_transaction_pool::ChainApi;
use sc_transaction_pool_api::TransactionPool;
use sp_api::{CallApiAt, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

pub struct DefaultEthConfig<Client, Backend>(std::marker::PhantomData<(Client, Backend)>);

impl<Block, Client, BE> EthConfig<Block, Client> for DefaultEthConfig<Client, BE>
where
    Block: BlockT,
    Client: StorageProvider<Block, BE> + Sync + Send + 'static,
    BE: Backend<Block> + 'static,
{
    type EstimateGasAdapter = ();
    type RuntimeStorageOverride =
        fc_rpc::frontier_backend_client::SystemAccountId20StorageOverride<Block, Client, BE>;
}

/// Extra dependencies for Ethereum compatibility.
pub struct EthDeps<Client, TxPool, CA: ChainApi, CT, Block: BlockT, BE> {
    /// Full Rpc deps
    pub full_deps: FullDeps<Block, Client, TxPool, CA, BE>,
    /// Ethereum transaction converter.
    pub converter: Option<CT>,
    /// Whether to enable dev signer
    pub enable_dev_signer: bool,
    /// Frontier Backend.
    pub frontier_backend: Arc<FrontierBackend<Block>>,
    /// Ethereum data access overrides.
    pub overrides: Arc<OverrideHandle<Block>>,
    /// Cache for Ethereum block data.
    pub block_data_cache: Arc<EthBlockDataCacheTask<Block>>,
    /// EthFilterApi pool.
    pub filter_pool: Option<FilterPool>,
    /// Maximum number of logs in a query.
    pub max_past_logs: u32,
    /// Fee history cache.
    pub fee_history_cache: FeeHistoryCache,
    /// Maximum fee history cache size.
    pub fee_history_cache_limit: FeeHistoryCacheLimit,
    /// Maximum allowed gas limit will be ` block.gas_limit * execute_gas_limit_multiplier` when
    /// using eth_call/eth_estimateGas.
    pub execute_gas_limit_multiplier: u64,
}

impl<Client, TxPool, CA: ChainApi, CT: Clone, Block: BlockT, BE> Clone
    for EthDeps<Client, TxPool, CA, CT, Block, BE>
{
    fn clone(&self) -> Self {
        Self {
            full_deps: self.full_deps.clone(),
            converter: self.converter.clone(),
            enable_dev_signer: self.enable_dev_signer,
            frontier_backend: self.frontier_backend.clone(),
            overrides: self.overrides.clone(),
            block_data_cache: self.block_data_cache.clone(),
            filter_pool: self.filter_pool.clone(),
            max_past_logs: self.max_past_logs,
            fee_history_cache: self.fee_history_cache.clone(),
            fee_history_cache_limit: self.fee_history_cache_limit,
            execute_gas_limit_multiplier: self.execute_gas_limit_multiplier,
        }
    }
}

/// Instantiate Ethereum-compatible RPC extensions.
pub(crate) fn create_eth_rpc<Client, BE, TxPool, CA, CT, Block, EC: EthConfig<Block, Client>>(
    mut io: RpcModule<()>,
    deps: EthDeps<Client, TxPool, CA, CT, Block, BE>,
    subscription_task_executor: SubscriptionTaskExecutor,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    Block: BlockT,
    Client: CallApiAt<Block> + ProvideRuntimeApi<Block>,
    Client::Api:
        BlockBuilderApi<Block> + EthereumRuntimeRPCApi<Block> + ConvertTransactionRuntimeApi<Block>,
    Client: BlockchainEvents<Block> + 'static,
    Client: HeaderBackend<Block>
        + HeaderMetadata<Block, Error = BlockChainError>
        + StorageProvider<Block, BE>,
    BE: Backend<Block> + 'static,
    TxPool: TransactionPool<Block = Block> + 'static,
    CA: ChainApi<Block = Block> + 'static,
    CT: ConvertTransaction<<Block as BlockT>::Extrinsic> + Send + Sync + 'static,
{
    let EthDeps {
        full_deps,
        converter,
        enable_dev_signer,
        frontier_backend,
        overrides,
        block_data_cache,
        filter_pool,
        max_past_logs,
        fee_history_cache,
        fee_history_cache_limit,
        execute_gas_limit_multiplier,
    } = deps;

    let FullDeps {
        client,
        pool,
        graph,
        network,
        sync,
        is_authority,
        ..
    } = full_deps;

    let mut signers = Vec::new();
    if enable_dev_signer {
        signers.push(Box::new(EthDevSigner::new()) as Box<dyn EthSigner>);
    }

    io.merge(
        Eth::new(
            client.clone(),
            pool.clone(),
            graph,
            converter,
            sync.clone(),
            vec![],
            overrides.clone(),
            frontier_backend.clone(),
            is_authority,
            block_data_cache.clone(),
            fee_history_cache,
            fee_history_cache_limit,
            execute_gas_limit_multiplier,
        )
        .replace_config::<EC>()
        .into_rpc(),
    )?;

    if let Some(filter_pool) = filter_pool {
        io.merge(
            EthFilter::new(
                client.clone(),
                frontier_backend,
                filter_pool,
                500_usize, // max stored filters
                max_past_logs,
                block_data_cache,
            )
            .into_rpc(),
        )?;
    }

    io.merge(
        EthPubSub::new(
            pool,
            client.clone(),
            sync,
            subscription_task_executor,
            overrides,
        )
        .into_rpc(),
    )?;

    io.merge(
        Net::new(
            client.clone(),
            network,
            // Whether to format the `peer_count` response as Hex (default) or not.
            true,
        )
        .into_rpc(),
    )?;

    io.merge(Web3::new(client).into_rpc())?;

    Ok(io)
}
