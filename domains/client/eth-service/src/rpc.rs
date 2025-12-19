use domain_service::rpc::FullDeps;
use fc_mapping_sync::{EthereumBlockNotification, EthereumBlockNotificationSinks};
use fc_rpc::{
    Eth, EthApiServer, EthDevSigner, EthFilter, EthFilterApiServer, EthPubSub, EthPubSubApiServer,
    EthSigner, Net, NetApiServer, Web3, Web3ApiServer,
};
pub use fc_rpc::{EthBlockDataCacheTask, EthConfig};
pub use fc_rpc_core::types::{FeeHistoryCache, FeeHistoryCacheLimit, FilterPool};
use fc_storage::StorageOverride;
use fp_rpc::{ConvertTransaction, ConvertTransactionRuntimeApi, EthereumRuntimeRPCApi};
use jsonrpsee::RpcModule;
use sc_client_api::backend::{Backend, StorageProvider};
use sc_client_api::client::BlockchainEvents;
use sc_network_sync::SyncingService;
use sc_rpc::SubscriptionTaskExecutor;
use sc_transaction_pool_api::TransactionPool;
use sp_api::{CallApiAt, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_core::H256;
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::Block as BlockT;
use std::collections::BTreeMap;
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
pub struct EthDeps<Client, TxPool, CT, Block: BlockT, BE, CIDP> {
    /// Full Rpc deps
    pub full_deps: FullDeps<Block, Client, TxPool, BE, CIDP>,
    /// Ethereum transaction converter.
    pub converter: Option<CT>,
    /// Whether to enable dev signer
    pub enable_dev_signer: bool,
    /// Chain syncing service
    pub sync: Arc<SyncingService<Block>>,
    /// Frontier Backend.
    pub frontier_backend: Arc<fc_db::kv::Backend<Block, Client>>,
    /// Ethereum data access overrides.
    pub storage_override: Arc<dyn StorageOverride<Block>>,
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
    /// Mandated parent hashes for a given block hash.
    pub forced_parent_hashes: Option<BTreeMap<H256, H256>>,
    /// Pending inherent data provider
    pub pending_inherent_data_provider: CIDP,
}

impl<Client, TxPool, CT: Clone, Block: BlockT, BE, CIDP: Clone> Clone
    for EthDeps<Client, TxPool, CT, Block, BE, CIDP>
{
    fn clone(&self) -> Self {
        Self {
            full_deps: self.full_deps.clone(),
            converter: self.converter.clone(),
            enable_dev_signer: self.enable_dev_signer,
            sync: self.sync.clone(),
            frontier_backend: self.frontier_backend.clone(),
            storage_override: self.storage_override.clone(),
            block_data_cache: self.block_data_cache.clone(),
            filter_pool: self.filter_pool.clone(),
            max_past_logs: self.max_past_logs,
            fee_history_cache: self.fee_history_cache.clone(),
            fee_history_cache_limit: self.fee_history_cache_limit,
            execute_gas_limit_multiplier: self.execute_gas_limit_multiplier,
            forced_parent_hashes: self.forced_parent_hashes.clone(),
            pending_inherent_data_provider: self.pending_inherent_data_provider.clone(),
        }
    }
}

/// Instantiate Ethereum-compatible RPC extensions.
pub(crate) fn create_eth_rpc<Client, BE, TxPool, CT, Block, EC, CIDP>(
    mut io: RpcModule<()>,
    deps: EthDeps<Client, TxPool, CT, Block, BE, CIDP>,
    subscription_task_executor: SubscriptionTaskExecutor,
    pubsub_notification_sinks: Arc<
        EthereumBlockNotificationSinks<EthereumBlockNotification<Block>>,
    >,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    Block: BlockT<Hash = H256>,
    Client: CallApiAt<Block> + ProvideRuntimeApi<Block>,
    Client::Api:
        BlockBuilderApi<Block> + EthereumRuntimeRPCApi<Block> + ConvertTransactionRuntimeApi<Block>,
    Client: BlockchainEvents<Block> + 'static,
    Client: HeaderBackend<Block>
        + HeaderMetadata<Block, Error = BlockChainError>
        + StorageProvider<Block, BE>,
    BE: Backend<Block> + 'static,
    TxPool: TransactionPool<Block = Block, Hash = H256> + 'static,
    CT: ConvertTransaction<Block::Extrinsic> + Send + Sync + 'static,
    EC: EthConfig<Block, Client>,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + 'static,
{
    let EthDeps {
        full_deps,
        converter,
        enable_dev_signer,
        sync: _,
        frontier_backend,
        storage_override,
        block_data_cache,
        filter_pool,
        max_past_logs,
        fee_history_cache,
        fee_history_cache_limit,
        execute_gas_limit_multiplier,
        forced_parent_hashes,
        pending_inherent_data_provider,
    } = deps;

    let FullDeps {
        client,
        pool,
        network,
        sync,
        is_authority,
        ..
    } = full_deps;

    let mut signers = Vec::<Box<dyn EthSigner>>::new();
    if enable_dev_signer {
        signers.push(Box::new(EthDevSigner::new()));
    }

    io.merge(
        Eth::<Block, Client, TxPool, CT, BE, CIDP, EC>::new(
            client.clone(),
            pool.clone(),
            pool.clone(),
            converter,
            sync.clone(),
            signers,
            storage_override.clone(),
            frontier_backend.clone(),
            is_authority,
            block_data_cache.clone(),
            fee_history_cache,
            fee_history_cache_limit,
            execute_gas_limit_multiplier,
            forced_parent_hashes,
            pending_inherent_data_provider,
            None,
        )
        .replace_config::<EC>()
        .into_rpc(),
    )?;

    if let Some(filter_pool) = filter_pool {
        io.merge(
            EthFilter::new(
                client.clone(),
                frontier_backend,
                pool.clone(),
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
            storage_override,
            pubsub_notification_sinks,
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
