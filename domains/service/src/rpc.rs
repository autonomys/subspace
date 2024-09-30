//! A collection of node-specific RPC methods.
//!
//! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
//! used by Substrate nodes. This file extends those RPC definitions with
//! capabilities that are specific to this project's runtime configuration.

#![warn(missing_docs)]

use domain_runtime_primitives::{Balance, Nonce};
use jsonrpsee::RpcModule;
use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
use sc_client_api::{AuxStore, BlockBackend};
use sc_network::NetworkService;
use sc_network_sync::SyncingService;
use sc_rpc_spec_v2::chain_spec::{ChainSpec, ChainSpecApiServer};
use sc_service::{DatabaseSource, SpawnTaskHandle};
use sc_transaction_pool::{ChainApi, Pool};
use sc_transaction_pool_api::TransactionPool;
use serde::de::DeserializeOwned;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_core::{Decode, Encode};
use sp_runtime::traits::Block as BlockT;
use std::fmt::{Debug, Display};
use std::sync::Arc;
use substrate_frame_rpc_system::{System, SystemApiServer};
use substrate_prometheus_endpoint::Registry;

/// Full RPC dependencies.
pub struct FullDeps<Block: BlockT, Client, TP, CA: ChainApi, BE, CIDP> {
    /// The client instance to use.
    pub client: Arc<Client>,
    /// The chain backend.
    pub backend: Arc<BE>,
    /// Transaction pool instance.
    pub pool: Arc<TP>,
    /// Graph pool instance.
    pub graph: Arc<Pool<CA>>,
    /// A copy of the chain spec.
    pub chain_spec: Box<dyn sc_chain_spec::ChainSpec>,
    /// Network service
    pub network: Arc<NetworkService<Block, Block::Hash>>,
    /// Chain syncing service
    pub sync: Arc<SyncingService<Block>>,
    /// Is node running as authority.
    pub is_authority: bool,
    /// Prometheus registry
    pub prometheus_registry: Option<Registry>,
    /// Database source
    pub database_source: DatabaseSource,
    /// Task Spawner.
    pub task_spawner: SpawnTaskHandle,
    /// Create inherent data provider
    pub create_inherent_data_provider: CIDP,
}

impl<Block: BlockT, Client, TP, CA: ChainApi, BE, CIDP: Clone> Clone
    for FullDeps<Block, Client, TP, CA, BE, CIDP>
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            backend: self.backend.clone(),
            pool: self.pool.clone(),
            graph: self.graph.clone(),
            chain_spec: self.chain_spec.cloned_box(),
            network: self.network.clone(),
            sync: self.sync.clone(),
            is_authority: self.is_authority,
            task_spawner: self.task_spawner.clone(),
            prometheus_registry: self.prometheus_registry.clone(),
            database_source: self.database_source.clone(),
            create_inherent_data_provider: self.create_inherent_data_provider.clone(),
        }
    }
}

/// Instantiate all RPC extensions.
pub fn create_full<Block, Client, P, CA, AccountId, BE, CIDP>(
    deps: FullDeps<Block, Client, P, CA, BE, CIDP>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + AuxStore
        + HeaderMetadata<Block, Error = BlockChainError>
        + Send
        + Sync
        + 'static,
    Client::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
        + substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>
        + BlockBuilder<Block>,
    P: TransactionPool + Sync + Send + 'static,
    CA: ChainApi,
    AccountId: DeserializeOwned + Encode + Debug + Decode + Display + Clone + Sync + Send + 'static,
{
    let mut module = RpcModule::new(());
    let FullDeps {
        client,
        pool,
        chain_spec,
        ..
    } = deps;

    let chain_name = chain_spec.name().to_string();
    let genesis_hash = client.info().genesis_hash;
    let properties = chain_spec.properties();
    module.merge(ChainSpec::new(chain_name, genesis_hash, properties).into_rpc())?;

    module.merge(System::new(client.clone(), pool).into_rpc())?;
    module.merge(TransactionPayment::new(client).into_rpc())?;

    Ok(module)
}
