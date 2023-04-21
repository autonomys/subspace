//! A collection of node-specific RPC methods.
//! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
//! used by Substrate nodes. This file extends those RPC definitions with
//! capabilities that are specific to this project's runtime configuration.

#![warn(missing_docs)]

use domain_runtime_primitives::{Balance, Index as Nonce};
use frame_benchmarking::frame_support::inherent::BlockT;
use jsonrpsee::RpcModule;
use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
use sc_client_api::{AuxStore, BlockBackend};
use sc_rpc::DenyUnsafe;
use sc_rpc_spec_v2::chain_spec::{ChainSpec, ChainSpecApiServer};
use sc_transaction_pool_api::TransactionPool;
use serde::de::DeserializeOwned;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_core::{Decode, Encode};
use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::sync::Arc;
use substrate_frame_rpc_system::{System, SystemApiServer};

/// Full client dependencies
pub struct FullDeps<C, P, AccountId> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
    /// A copy of the chain spec.
    pub chain_spec: Box<dyn sc_chain_spec::ChainSpec>,
    /// Whether to deny unsafe calls
    pub deny_unsafe: DenyUnsafe,
    _data: PhantomData<AccountId>,
}

impl<C, P, AccountId> FullDeps<C, P, AccountId> {
    pub fn new(
        client: Arc<C>,
        pool: Arc<P>,
        chain_spec: Box<dyn sc_chain_spec::ChainSpec>,
        deny_unsafe: DenyUnsafe,
    ) -> Self {
        Self {
            client,
            pool,
            chain_spec,
            deny_unsafe,
            _data: Default::default(),
        }
    }
}

/// Instantiate all RPC extensions.
pub fn create_full<Block, C, P, AccountId>(
    deps: FullDeps<C, P, AccountId>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    Block: BlockT,
    C: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + AuxStore
        + HeaderMetadata<Block, Error = BlockChainError>
        + Send
        + Sync
        + 'static,
    C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    C::Api: BlockBuilder<Block>,
    P: TransactionPool + Sync + Send + 'static,
    AccountId: DeserializeOwned + Encode + Debug + Decode + Display + Clone + Sync + Send + 'static,
{
    let mut module = RpcModule::new(());
    let FullDeps {
        client,
        pool,
        chain_spec,
        deny_unsafe,
        _data,
    } = deps;

    let chain_name = chain_spec.name().to_string();
    let genesis_hash = client.info().genesis_hash;
    let properties = chain_spec.properties();
    module.merge(ChainSpec::new(chain_name, genesis_hash, properties).into_rpc())?;

    module.merge(System::new(client.clone(), pool, deny_unsafe).into_rpc())?;
    module.merge(TransactionPayment::new(client).into_rpc())?;

    Ok(module)
}
