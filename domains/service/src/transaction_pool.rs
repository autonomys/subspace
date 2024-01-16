use domain_client_block_preprocessor::xdm_verifier::is_valid_xdm;
use futures::future::{Future, FutureExt, Ready};
use sc_client_api::blockchain::HeaderBackend;
use sc_client_api::{BlockBackend, ExecutorProvider, UsageProvider};
use sc_service::{Configuration, TaskManager};
use sc_transaction_pool::error::{Error as TxPoolError, Result as TxPoolResult};
use sc_transaction_pool::{BasicPool, ChainApi, FullChainApi, RevalidationType};
use sc_transaction_pool_api::TransactionSource;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{HeaderMetadata, TreeRoute};
use sp_domains::DomainsApi;
use sp_messenger::MessengerApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, BlockIdTo, NumberFor};
use sp_runtime::transaction_validity::TransactionValidity;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use substrate_prometheus_endpoint::Registry as PrometheusRegistry;

/// Block hash type for a pool.
type BlockHash<A> = <<A as ChainApi>::Block as BlockT>::Hash;

/// Extrinsic hash type for a pool.
type ExtrinsicHash<A> = <<A as ChainApi>::Block as BlockT>::Hash;

/// Extrinsic type for a pool.
type ExtrinsicFor<A> = <<A as ChainApi>::Block as BlockT>::Extrinsic;

/// A transaction pool for a full node.
pub type FullPool<CClient, CBlock, Block, Client> =
    BasicPool<FullChainApiWrapper<CClient, CBlock, Block, Client>, Block>;

#[derive(Clone)]
pub struct FullChainApiWrapper<CClient, CBlock, Block, Client> {
    inner: Arc<FullChainApi<Client, Block>>,
    client: Arc<Client>,
    consensus_client: Arc<CClient>,
    marker: PhantomData<CBlock>,
}

impl<CClient, CBlock, Block, Client> FullChainApiWrapper<CClient, CBlock, Block, Client>
where
    CBlock: BlockT,
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + BlockIdTo<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + Send
        + Sync
        + 'static,
    Client::Api: TaggedTransactionQueue<Block>,
{
    fn new(
        consensus_client: Arc<CClient>,
        client: Arc<Client>,
        prometheus: Option<&PrometheusRegistry>,
        task_manager: &TaskManager,
    ) -> Self {
        Self {
            inner: Arc::new(FullChainApi::new(
                client.clone(),
                prometheus,
                &task_manager.spawn_essential_handle(),
            )),
            client,
            consensus_client,
            marker: Default::default(),
        }
    }
}

pub type ValidationFuture = Pin<Box<dyn Future<Output = TxPoolResult<TransactionValidity>> + Send>>;

impl<CClient, CBlock, Block, Client> ChainApi
    for FullChainApiWrapper<CClient, CBlock, Block, Client>
where
    CBlock: BlockT,
    Block: BlockT,
    NumberFor<CBlock>: From<NumberFor<Block>>,
    CBlock::Hash: From<Block::Hash>,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + BlockIdTo<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + Send
        + Sync
        + 'static,
    Client::Api: TaggedTransactionQueue<Block> + MessengerApi<Block, NumberFor<Block>>,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + Send + Sync + 'static,
    CClient::Api: DomainsApi<CBlock, Block::Header> + MessengerApi<CBlock, NumberFor<CBlock>>,
{
    type Block = Block;
    type Error = sc_transaction_pool::error::Error;
    type ValidationFuture = ValidationFuture;
    type BodyFuture = Ready<TxPoolResult<Option<Vec<<Self::Block as BlockT>::Extrinsic>>>>;

    fn validate_transaction(
        &self,
        at: Block::Hash,
        source: TransactionSource,
        uxt: ExtrinsicFor<Self>,
    ) -> Self::ValidationFuture {
        let chain_api = self.inner.clone();
        let consensus_client = self.consensus_client.clone();
        let client = self.client.clone();
        async move {
            if !is_valid_xdm(&consensus_client, at, &client, &uxt)? {
                return Err(TxPoolError::Pool(
                    sc_transaction_pool_api::error::Error::ImmediatelyDropped,
                ));
            }

            chain_api.validate_transaction(at, source, uxt).await
        }
        .boxed()
    }

    fn block_id_to_number(
        &self,
        at: &BlockId<Self::Block>,
    ) -> TxPoolResult<Option<NumberFor<Self::Block>>> {
        self.inner.block_id_to_number(at)
    }

    fn block_id_to_hash(&self, at: &BlockId<Self::Block>) -> TxPoolResult<Option<BlockHash<Self>>> {
        self.inner.block_id_to_hash(at)
    }

    fn hash_and_length(&self, ex: &ExtrinsicFor<Self>) -> (ExtrinsicHash<Self>, usize) {
        self.inner.hash_and_length(ex)
    }

    fn block_body(&self, id: <Self::Block as BlockT>::Hash) -> Self::BodyFuture {
        self.inner.block_body(id)
    }

    fn block_header(
        &self,
        hash: <Self::Block as BlockT>::Hash,
    ) -> Result<Option<<Self::Block as BlockT>::Header>, Self::Error> {
        self.inner.block_header(hash)
    }

    fn tree_route(
        &self,
        from: <Self::Block as BlockT>::Hash,
        to: <Self::Block as BlockT>::Hash,
    ) -> Result<TreeRoute<Self::Block>, Self::Error> {
        sp_blockchain::tree_route::<Block, Client>(&*self.client, from, to).map_err(Into::into)
    }
}

pub(crate) fn new_full<CClient, CBlock, Block, Client>(
    config: &Configuration,
    task_manager: &TaskManager,
    client: Arc<Client>,
    consensus_client: Arc<CClient>,
) -> Arc<FullPool<CClient, CBlock, Block, Client>>
where
    CBlock: BlockT,
    Block: BlockT,
    NumberFor<CBlock>: From<NumberFor<Block>>,
    CBlock::Hash: From<Block::Hash>,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + ExecutorProvider<Block>
        + UsageProvider<Block>
        + BlockIdTo<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: TaggedTransactionQueue<Block> + MessengerApi<Block, NumberFor<Block>>,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + Send + Sync + 'static,
    CClient::Api: DomainsApi<CBlock, Block::Header> + MessengerApi<CBlock, NumberFor<CBlock>>,
{
    let prometheus = config.prometheus_registry();
    let pool_api = Arc::new(FullChainApiWrapper::new(
        consensus_client,
        client.clone(),
        prometheus,
        task_manager,
    ));

    let basic_pool = BasicPool::with_revalidation_type(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        pool_api,
        prometheus,
        RevalidationType::Full,
        task_manager.spawn_essential_handle(),
        client.usage_info().chain.best_number,
        client.usage_info().chain.best_hash,
        client.usage_info().chain.finalized_hash,
    );

    Arc::new(basic_pool)
}
