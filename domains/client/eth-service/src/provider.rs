use crate::rpc::{create_eth_rpc, EthDeps};
use crate::service::{
    new_frontier_partial, spawn_frontier_tasks, EthConfiguration, FrontierBackend,
    FrontierPartialComponents,
};
use clap::Parser;
use domain_runtime_primitives::{Balance, Index};
use domain_service::providers::{BlockImportProvider, DefaultProvider, RpcProvider};
use domain_service::rpc::FullDeps;
use domain_service::FullClient;
use fc_consensus::FrontierBlockImport;
use fc_rpc::EthConfig;
use fc_storage::overrides_handle;
use fp_rpc::{ConvertTransaction, ConvertTransactionRuntimeApi, EthereumRuntimeRPCApi};
use jsonrpsee::RpcModule;
use sc_client_api::{
    AuxStore, Backend, BlockBackend, BlockchainEvents, StateBackendFor, StorageProvider,
};
use sc_executor::NativeExecutionDispatch;
use sc_rpc::{RpcSubscriptionIdProvider, SubscriptionTaskExecutor};
use sc_service::{BasePath, TFullBackend};
use sc_transaction_pool::ChainApi;
use sc_transaction_pool_api::TransactionPool;
use serde::de::DeserializeOwned;
use sp_api::{ApiExt, BlockT, CallApiAt, ConstructRuntimeApi, Core, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::codec::{Decode, Encode};
use std::error::Error;
use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::sync::Arc;
use substrate_frame_rpc_system::AccountNonceApi;

/// Ethereum specific providers.
pub struct EthProvider<CT, EC> {
    eth_config: EthConfiguration,
    base_path: Option<BasePath>,
    marker: PhantomData<(CT, EC)>,
}

impl<CT, EC> EthProvider<CT, EC> {
    pub fn new(base_path: Option<BasePath>, eth_cli: impl Iterator<Item = String>) -> Self {
        let eth_config = EthConfiguration::parse_from(eth_cli);
        Self {
            eth_config,
            base_path: base_path.map(|base_path| BasePath::new(base_path.path().join("evm"))),
            marker: Default::default(),
        }
    }
}

impl<Block, RuntimeApi, ExecutorDispatch, CT, EC>
    BlockImportProvider<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>>
    for EthProvider<CT, EC>
where
    Block: BlockT,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>>
        + Send
        + Sync
        + 'static,
    RuntimeApi::RuntimeApi: ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>>
        + Core<Block>
        + BlockBuilder<Block>
        + EthereumRuntimeRPCApi<Block>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
{
    type BI = FrontierBlockImport<
        Block,
        Arc<FullClient<Block, RuntimeApi, ExecutorDispatch>>,
        FullClient<Block, RuntimeApi, ExecutorDispatch>,
    >;

    fn block_import(
        &self,
        client: Arc<FullClient<Block, RuntimeApi, ExecutorDispatch>>,
    ) -> Self::BI {
        FrontierBlockImport::new(client.clone(), client)
    }
}

impl<Block, Client, BE, TxPool, CA, AccountId, CT, EC>
    RpcProvider<Block, Client, TxPool, CA, BE, AccountId> for EthProvider<CT, EC>
where
    Block: BlockT,
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
        + AccountNonceApi<Block, AccountId, Index>
        + ConvertTransactionRuntimeApi<Block>,
    Client::Api: BlockBuilder<Block>,
    Client::Api: EthereumRuntimeRPCApi<Block>,
    CT: ConvertTransaction<<Block as BlockT>::Extrinsic> + Clone + Default + Send + Sync + 'static,
    EC: EthConfig<Block, Client>,
    TxPool: TransactionPool<Block = Block> + Sync + Send + 'static,
    CA: ChainApi<Block = Block> + 'static,
    AccountId: DeserializeOwned + Encode + Debug + Decode + Display + Clone + Sync + Send + 'static,
{
    type Deps = EthDeps<Client, TxPool, CA, CT, Block, BE>;

    fn deps(
        &self,
        full_deps: FullDeps<Block, Client, TxPool, CA, BE>,
    ) -> Result<Self::Deps, sc_service::Error> {
        let client = full_deps.client.clone();
        let overrides = overrides_handle(client.clone());
        let base_path = match &self.base_path {
            None => BasePath::new_temp_dir()?,
            Some(base_path) => BasePath::new(base_path.path()),
        };

        let frontier_backend = Arc::new(FrontierBackend::open(
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
            frontier_backend,
            overrides: overrides.clone(),
            block_data_cache: Arc::new(fc_rpc::EthBlockDataCacheTask::new(
                full_deps.task_spawner.clone(),
                overrides,
                self.eth_config.eth_log_block_cache,
                self.eth_config.eth_statuses_cache,
                full_deps.prometheus_registry,
            )),
            filter_pool,
            max_past_logs: self.eth_config.max_past_logs,
            fee_history_cache,
            fee_history_cache_limit,
            execute_gas_limit_multiplier: self.eth_config.execute_gas_limit_multiplier,
        })
    }

    fn rpc_id(&self) -> Option<Box<dyn RpcSubscriptionIdProvider>> {
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

        let io = create_eth_rpc::<Client, BE, TxPool, CA, CT, Block, EC>(
            io,
            deps.clone(),
            subscription_task_executor,
        )?;

        // spawn essential rpc tasks
        spawn_frontier_tasks(
            essential_task_spawner,
            deps.full_deps.client,
            deps.full_deps.backend,
            deps.frontier_backend,
            deps.overrides,
            FrontierPartialComponents {
                filter_pool: deps.filter_pool,
                fee_history_cache: deps.fee_history_cache,
                fee_history_cache_limit: deps.fee_history_cache_limit,
            },
        );
        Ok(io)
    }
}
