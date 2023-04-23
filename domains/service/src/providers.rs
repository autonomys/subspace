use crate::rpc::FullDeps;
use crate::FullClient;
use domain_runtime_primitives::{Balance, Index};
use frame_benchmarking::frame_support::codec::{Decode, Encode};
use frame_benchmarking::frame_support::inherent::BlockT;
use jsonrpsee::RpcModule;
use sc_client_api::{AuxStore, Backend, BlockBackend, StateBackendFor, StorageProvider};
use sc_consensus::BlockImport;
use sc_executor::NativeExecutionDispatch;
use sc_rpc::{RpcSubscriptionIdProvider, SubscriptionTaskExecutor};
use sc_service::TFullBackend;
use sc_transaction_pool::ChainApi;
use sc_transaction_pool_api::TransactionPool;
use serde::de::DeserializeOwned;
use sp_api::{ApiExt, ConstructRuntimeApi, Core, ProvideRuntimeApi, TransactionFor};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_core::traits::SpawnEssentialNamed;
use std::error::Error;
use std::fmt::{Debug, Display};
use std::sync::Arc;
use substrate_frame_rpc_system::AccountNonceApi;

pub trait BlockImportProvider<Block: BlockT, Client>
where
    Client: ProvideRuntimeApi<Block>,
{
    type BI: BlockImport<Block, Error = sp_consensus::Error, Transaction = TransactionFor<Client, Block>>
        + Send
        + Sync
        + 'static;
    fn block_import(&self, client: Arc<Client>) -> Self::BI;
}

#[derive(Clone)]
pub struct DefaultProvider;

impl<Block, RuntimeApi, ExecutorDispatch>
    BlockImportProvider<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>> for DefaultProvider
where
    Block: BlockT,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<Block, RuntimeApi, ExecutorDispatch>>
        + Send
        + Sync
        + 'static,
    RuntimeApi::RuntimeApi:
        ApiExt<Block, StateBackend = StateBackendFor<TFullBackend<Block>, Block>> + Core<Block>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
{
    type BI = Arc<FullClient<Block, RuntimeApi, ExecutorDispatch>>;

    fn block_import(
        &self,
        client: Arc<FullClient<Block, RuntimeApi, ExecutorDispatch>>,
    ) -> Self::BI {
        client
    }
}

/// Provides adding custom ID to the RPC module.
pub trait RpcProvider<Block, Client, TxPool, CA, BE, AccountId>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + StorageProvider<Block, BE>,
    Client::Api: AccountNonceApi<Block, AccountId, Index>,
    TxPool: TransactionPool<Block = Block> + Sync + Send + 'static,
    CA: ChainApi<Block = Block> + 'static,
    BE: Backend<Block> + 'static,
    AccountId: DeserializeOwned + Encode + Debug + Decode + Display + Clone + Sync + Send + 'static,
{
    type Deps: Clone;

    fn deps(
        &self,
        full_deps: FullDeps<Block, Client, TxPool, CA, BE>,
    ) -> Result<Self::Deps, sc_service::Error>;

    fn rpc_id(&self) -> Option<Box<dyn RpcSubscriptionIdProvider>>;

    fn rpc_builder<SE>(
        &self,
        deps: Self::Deps,
        subscription_task_executor: SubscriptionTaskExecutor,
        essential_task_spawner: SE,
    ) -> Result<RpcModule<()>, Box<dyn Error + Send + Sync>>
    where
        SE: SpawnEssentialNamed + Clone;
}

impl<Block, Client, BE, TxPool, CA, AccountId> RpcProvider<Block, Client, TxPool, CA, BE, AccountId>
    for DefaultProvider
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + AuxStore
        + HeaderMetadata<Block, Error = BlockChainError>
        + StorageProvider<Block, BE>
        + Send
        + Sync
        + 'static,
    Client::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
        + AccountNonceApi<Block, AccountId, Index>
        + BlockBuilder<Block>,
    CA: ChainApi,
    TxPool: TransactionPool<Block = Block> + Sync + Send + 'static,
    CA: ChainApi<Block = Block> + 'static,
    BE: Backend<Block> + 'static,
    AccountId: DeserializeOwned + Encode + Debug + Decode + Display + Clone + Sync + Send + 'static,
{
    type Deps = FullDeps<Block, Client, TxPool, CA, BE>;

    fn deps(
        &self,
        full_deps: FullDeps<Block, Client, TxPool, CA, BE>,
    ) -> Result<Self::Deps, sc_service::Error> {
        Ok(full_deps)
    }

    fn rpc_id(&self) -> Option<Box<dyn RpcSubscriptionIdProvider>> {
        None
    }

    fn rpc_builder<SE>(
        &self,
        deps: Self::Deps,
        _subscription_task_executor: SubscriptionTaskExecutor,
        _essential_task_spawner: SE,
    ) -> Result<RpcModule<()>, Box<dyn Error + Send + Sync>>
    where
        SE: SpawnEssentialNamed + Clone,
    {
        crate::rpc::create_full::<_, _, _, _, AccountId, BE>(deps).map_err(Into::into)
    }
}
