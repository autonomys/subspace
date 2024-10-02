use crate::rpc::FullDeps;
use crate::FullClient;
use domain_runtime_primitives::{Balance, Nonce};
use jsonrpsee::RpcModule;
use parity_scale_codec::{Decode, Encode};
use sc_client_api::{AuxStore, Backend, BlockBackend, StorageProvider};
use sc_consensus::BlockImport;
use sc_rpc::SubscriptionTaskExecutor;
use sc_rpc_server::SubscriptionIdProvider;
use sc_transaction_pool::ChainApi;
use sc_transaction_pool_api::TransactionPool;
use serde::de::DeserializeOwned;
use sp_api::{ApiExt, ConstructRuntimeApi, Core, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::traits::Block as BlockT;
use std::error::Error;
use std::fmt::{Debug, Display};
use std::sync::Arc;
use substrate_frame_rpc_system::AccountNonceApi;

pub trait BlockImportProvider<Block: BlockT, Client>
where
    Client: ProvideRuntimeApi<Block>,
{
    type BI: BlockImport<Block, Error = sp_consensus::Error> + Send + Sync + 'static;
    fn block_import(&self, client: Arc<Client>) -> Self::BI;
}

#[derive(Clone, Default)]
pub struct DefaultProvider;

impl<Block, RuntimeApi> BlockImportProvider<Block, FullClient<Block, RuntimeApi>>
    for DefaultProvider
where
    Block: BlockT,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<Block, RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: ApiExt<Block> + Core<Block>,
{
    type BI = Arc<FullClient<Block, RuntimeApi>>;

    fn block_import(&self, client: Arc<FullClient<Block, RuntimeApi>>) -> Self::BI {
        client
    }
}

/// Provides adding custom ID to the RPC module.
pub trait RpcProvider<Block, Client, TxPool, CA, BE, AccountId, CIDP>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + StorageProvider<Block, BE>,
    Client::Api: AccountNonceApi<Block, AccountId, Nonce>,
    TxPool: TransactionPool<Block = Block> + Sync + Send + 'static,
    CA: ChainApi<Block = Block> + 'static,
    BE: Backend<Block> + 'static,
    AccountId: DeserializeOwned + Encode + Debug + Decode + Display + Clone + Sync + Send + 'static,
{
    type Deps: Clone;

    fn deps(
        &self,
        full_deps: FullDeps<Block, Client, TxPool, CA, BE, CIDP>,
    ) -> Result<Self::Deps, sc_service::Error>;

    fn rpc_id(&self) -> Option<Box<dyn SubscriptionIdProvider>>;

    fn rpc_builder<SE>(
        &self,
        deps: Self::Deps,
        subscription_task_executor: SubscriptionTaskExecutor,
        essential_task_spawner: SE,
    ) -> Result<RpcModule<()>, Box<dyn Error + Send + Sync>>
    where
        SE: SpawnEssentialNamed + Clone;
}

impl<Block, Client, BE, TxPool, CA, AccountId, CIDP>
    RpcProvider<Block, Client, TxPool, CA, BE, AccountId, CIDP> for DefaultProvider
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
        + AccountNonceApi<Block, AccountId, Nonce>
        + BlockBuilder<Block>,
    TxPool: TransactionPool<Block = Block> + Sync + Send + 'static,
    CA: ChainApi<Block = Block> + 'static,
    BE: Backend<Block> + 'static,
    AccountId: DeserializeOwned + Encode + Debug + Decode + Display + Clone + Sync + Send + 'static,
    CIDP: Clone,
{
    type Deps = FullDeps<Block, Client, TxPool, CA, BE, CIDP>;

    fn deps(
        &self,
        full_deps: FullDeps<Block, Client, TxPool, CA, BE, CIDP>,
    ) -> Result<Self::Deps, sc_service::Error> {
        Ok(full_deps)
    }

    fn rpc_id(&self) -> Option<Box<dyn SubscriptionIdProvider>> {
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
        crate::rpc::create_full::<_, _, _, _, AccountId, BE, CIDP>(deps).map_err(Into::into)
    }
}
