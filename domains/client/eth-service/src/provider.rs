use crate::rpc::{EthDeps, create_eth_rpc};
use crate::service::{
    EthConfiguration, FrontierPartialComponents, new_frontier_partial, spawn_frontier_tasks,
};
use clap::Parser;
use domain_runtime_primitives::{Balance, Nonce};
use domain_service::FullClient;
use domain_service::providers::{BlockImportProvider, DefaultProvider, RpcProvider};
use domain_service::rpc::FullDeps;
use fc_consensus::FrontierBlockImport;
use fc_rpc::EthConfig;
use fc_storage::StorageOverrideHandler;
use fp_rpc::{ConvertTransaction, ConvertTransactionRuntimeApi, EthereumRuntimeRPCApi};
use jsonrpsee::RpcModule;
use parity_scale_codec::{Decode, Encode};
use sc_client_api::{AuxStore, Backend, BlockBackend, BlockchainEvents, StorageProvider};
use sc_rpc::SubscriptionTaskExecutor;
use sc_rpc_server::SubscriptionIdProvider;
use sc_service::BasePath;
use sc_transaction_pool::ChainApi;
use sc_transaction_pool_api::TransactionPool;
use serde::de::DeserializeOwned;
use sp_api::{ApiExt, CallApiAt, ConstructRuntimeApi, Core, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_core::H256;
use sp_core::traits::SpawnEssentialNamed;
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::Block as BlockT;
use std::env;
use std::error::Error;
use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;
use substrate_frame_rpc_system::AccountNonceApi;

/// Ethereum specific providers.
pub struct EthProvider<CT, EC> {
    eth_config: EthConfiguration,
    base_path: Option<BasePath>,
    marker: PhantomData<(CT, EC)>,
}

impl<CT, EC> EthProvider<CT, EC> {
    pub fn new(base_path: Option<&Path>, eth_cli: impl Iterator<Item = String>) -> Self {
        let eth_config = EthConfiguration::parse_from(env::args().take(1).chain(eth_cli));
        Self::with_configuration(base_path, eth_config)
    }

    pub fn with_configuration(base_path: Option<&Path>, eth_config: EthConfiguration) -> Self {
        Self {
            eth_config,
            base_path: base_path.map(|base_path| BasePath::new(base_path.join("evm"))),
            marker: Default::default(),
        }
    }
}

impl<Block, RuntimeApi, CT, EC> BlockImportProvider<Block, FullClient<Block, RuntimeApi>>
    for EthProvider<CT, EC>
where
    Block: BlockT,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<Block, RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi:
        ApiExt<Block> + Core<Block> + BlockBuilder<Block> + EthereumRuntimeRPCApi<Block>,
{
    type BI = FrontierBlockImport<
        Block,
        Arc<FullClient<Block, RuntimeApi>>,
        FullClient<Block, RuntimeApi>,
    >;

    fn block_import(&self, client: Arc<FullClient<Block, RuntimeApi>>) -> Self::BI {
        FrontierBlockImport::new(client.clone(), client)
    }
}

impl<Block, Client, BE, TxPool, CA, AccountId, CT, EC, CIDP>
    RpcProvider<Block, Client, TxPool, CA, BE, AccountId, CIDP> for EthProvider<CT, EC>
where
    Block: BlockT<Hash = H256>,
    BE: Backend<Block> + 'static,
    Client: ProvideRuntimeApi<Block>
        + BlockchainEvents<Block>
        + StorageProvider<Block, BE>
        + HeaderBackend<Block>
        + CallApiAt<Block>
        + HeaderMetadata<Block, Error = BlockChainError>
        + BlockBackend<Block>
        + AuxStore
        + Send
        + Sync
        + 'static,
    Client::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
        + EthereumRuntimeRPCApi<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + ConvertTransactionRuntimeApi<Block>,
    Client::Api: BlockBuilder<Block>,
    Client::Api: EthereumRuntimeRPCApi<Block>,
    CT: ConvertTransaction<Block::Extrinsic> + Clone + Default + Send + Sync + 'static,
    EC: EthConfig<Block, Client>,
    TxPool: TransactionPool<Block = Block> + Sync + Send + 'static,
    CA: ChainApi<Block = Block> + 'static,
    AccountId: DeserializeOwned + Encode + Debug + Decode + Display + Clone + Sync + Send + 'static,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + Clone + 'static,
{
    type Deps = EthDeps<Client, TxPool, CA, CT, Block, BE, CIDP>;

    fn deps(
        &self,
        full_deps: FullDeps<Block, Client, TxPool, CA, BE, CIDP>,
    ) -> Result<Self::Deps, sc_service::Error> {
        let client = full_deps.client.clone();
        let storage_override = Arc::new(StorageOverrideHandler::new(client.clone()));
        let base_path = match &self.base_path {
            None => BasePath::new_temp_dir()?,
            Some(base_path) => BasePath::new(base_path.path()),
        };

        let frontier_backend = Arc::new(fc_db::kv::Backend::open(
            client,
            &full_deps.database_source,
            base_path.path(),
        )?);

        let FrontierPartialComponents {
            filter_pool,
            fee_history_cache,
            fee_history_cache_limit,
        } = new_frontier_partial(self.eth_config.fee_history_limit)?;

        Ok(EthDeps {
            full_deps: full_deps.clone(),
            converter: Some(CT::default()),
            enable_dev_signer: self.eth_config.enable_dev_signer,
            sync: full_deps.sync.clone(),
            frontier_backend,
            storage_override: storage_override.clone(),
            block_data_cache: Arc::new(fc_rpc::EthBlockDataCacheTask::new(
                full_deps.task_spawner.clone(),
                storage_override,
                self.eth_config.eth_log_block_cache,
                self.eth_config.eth_statuses_cache,
                full_deps.prometheus_registry,
            )),
            filter_pool,
            max_past_logs: self.eth_config.max_past_logs,
            fee_history_cache,
            fee_history_cache_limit,
            execute_gas_limit_multiplier: self.eth_config.execute_gas_limit_multiplier,
            forced_parent_hashes: None,
            pending_inherent_data_provider: full_deps.create_inherent_data_provider,
        })
    }

    fn rpc_id(&self) -> Option<Box<dyn SubscriptionIdProvider>> {
        Some(Box::new(fc_rpc::EthereumSubIdProvider))
    }

    fn rpc_builder<SE>(
        &self,
        deps: Self::Deps,
        subscription_task_executor: SubscriptionTaskExecutor,
        essential_task_spawner: SE,
    ) -> Result<RpcModule<()>, Box<dyn Error + Send + Sync>>
    where
        SE: SpawnEssentialNamed + Clone,
    {
        let default_provider = DefaultProvider;
        let io = default_provider.rpc_builder(
            deps.full_deps.clone(),
            subscription_task_executor.clone(),
            essential_task_spawner.clone(),
        )?;

        // Sinks for pubsub notifications.
        // Everytime a new subscription is created, a new mpsc channel is added to the sink pool.
        // The MappingSyncWorker sends through the channel on block import and the subscription emits a notification to the subscriber on receiving a message through this channel.
        // This way we avoid race conditions when using native substrate block import notification stream.
        let pubsub_notification_sinks: fc_mapping_sync::EthereumBlockNotificationSinks<
            fc_mapping_sync::EthereumBlockNotification<Block>,
        > = Default::default();
        let pubsub_notification_sinks = Arc::new(pubsub_notification_sinks);

        let io = create_eth_rpc::<Client, BE, TxPool, CA, CT, Block, EC, CIDP>(
            io,
            deps.clone(),
            subscription_task_executor,
            pubsub_notification_sinks.clone(),
        )?;

        // spawn essential rpc tasks
        spawn_frontier_tasks(
            essential_task_spawner,
            deps.full_deps.client,
            deps.full_deps.backend,
            deps.frontier_backend,
            deps.storage_override,
            FrontierPartialComponents {
                filter_pool: deps.filter_pool,
                fee_history_cache: deps.fee_history_cache,
                fee_history_cache_limit: deps.fee_history_cache_limit,
            },
            deps.sync,
            pubsub_notification_sinks,
        );
        Ok(io)
    }
}
