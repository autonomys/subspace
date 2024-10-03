use async_trait::async_trait;
use futures::future::{Future, Ready};
use sc_client_api::blockchain::HeaderBackend;
use sc_client_api::{AuxStore, BlockBackend, ExecutorProvider, UsageProvider};
use sc_service::{TaskManager, TransactionPoolOptions};
use sc_transaction_pool::error::Result as TxPoolResult;
use sc_transaction_pool::{
    BasicPool, ChainApi, FullChainApi, Pool, RevalidationType, Transaction, ValidatedTransaction,
};
use sc_transaction_pool_api::{
    ChainEvent, ImportNotificationStream, LocalTransactionPool, MaintainedTransactionPool,
    PoolFuture, PoolStatus, ReadyTransactions, TransactionFor, TransactionPool, TransactionSource,
    TransactionStatusStreamFor, TxHash,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{HeaderMetadata, TreeRoute};
use sp_consensus_subspace::SubspaceApi;
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::DomainsApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, BlockIdTo, Header as HeaderT, NumberFor};
use sp_runtime::transaction_validity::{TransactionValidity, TransactionValidityError};
use sp_runtime::SaturatedConversion;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use subspace_core_primitives::PublicKey;
use substrate_prometheus_endpoint::Registry as PrometheusRegistry;

/// Block hash type for a pool.
type BlockHash<A> = <<A as ChainApi>::Block as BlockT>::Hash;

/// Extrinsic hash type for a pool.
type ExtrinsicHash<A> = <<A as ChainApi>::Block as BlockT>::Hash;

/// Extrinsic type for a pool.
type ExtrinsicFor<A> = <<A as ChainApi>::Block as BlockT>::Extrinsic;

/// A transaction pool for a full node.
pub type FullPool<Client, Block, DomainHeader> =
    BasicPoolWrapper<Block, FullChainApiWrapper<Client, Block, DomainHeader>>;

type BoxedReadyIterator<Hash, Data> =
    Box<dyn ReadyTransactions<Item = Arc<Transaction<Hash, Data>>> + Send>;

type ReadyIteratorFor<PoolApi> = BoxedReadyIterator<ExtrinsicHash<PoolApi>, ExtrinsicFor<PoolApi>>;

type PolledIterator<PoolApi> = Pin<Box<dyn Future<Output = ReadyIteratorFor<PoolApi>> + Send>>;

pub type BlockExtrinsicOf<Block> = <Block as BlockT>::Extrinsic;

#[derive(Clone)]
pub struct FullChainApiWrapper<Client, Block: BlockT, DomainHeader: HeaderT> {
    inner: Arc<FullChainApi<Client, Block>>,
    client: Arc<Client>,
    marker: PhantomData<DomainHeader>,
}

impl<Client, Block, DomainHeader> FullChainApiWrapper<Client, Block, DomainHeader>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + BlockIdTo<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + Send
        + Sync
        + 'static,
    Client::Api: TaggedTransactionQueue<Block> + SubspaceApi<Block, PublicKey>,
    DomainHeader: HeaderT,
{
    fn new(
        client: Arc<Client>,
        prometheus: Option<&PrometheusRegistry>,
        task_manager: &TaskManager,
    ) -> sp_blockchain::Result<Self> {
        Ok(Self {
            inner: Arc::new(FullChainApi::new(
                client.clone(),
                prometheus,
                &task_manager.spawn_essential_handle(),
            )),
            client,
            marker: Default::default(),
        })
    }

    fn validate_transaction_blocking(
        &self,
        at: Block::Hash,
        source: TransactionSource,
        uxt: BlockExtrinsicOf<Block>,
    ) -> TxPoolResult<TransactionValidity> {
        self.inner.validate_transaction_blocking(at, source, uxt)
    }
}

pub type ValidationFuture = Pin<Box<dyn Future<Output = TxPoolResult<TransactionValidity>> + Send>>;

impl<Client, Block, DomainHeader> ChainApi for FullChainApiWrapper<Client, Block, DomainHeader>
where
    Block: BlockT,
    <<Block::Header as HeaderT>::Number as TryInto<u32>>::Error: std::fmt::Debug,
    Client: ProvideRuntimeApi<Block>
        + AuxStore
        + BlockBackend<Block>
        + BlockIdTo<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + Send
        + Sync
        + 'static,
    DomainHeader: HeaderT,
    Client::Api: TaggedTransactionQueue<Block>
        + SubspaceApi<Block, PublicKey>
        + DomainsApi<Block, DomainHeader>,
{
    type Block = Block;
    type Error = sc_transaction_pool::error::Error;
    type ValidationFuture = ValidationFuture;
    type BodyFuture = Ready<TxPoolResult<Option<Vec<Block::Extrinsic>>>>;

    fn validate_transaction(
        &self,
        at: Block::Hash,
        source: TransactionSource,
        uxt: ExtrinsicFor<Self>,
    ) -> Self::ValidationFuture {
        // TODO: after https://github.com/paritytech/polkadot-sdk/issues/3705 is resolved, check if
        // there is already a fraud proof with the same tag and higher priority in the tx pool, if so
        // drop the incoming fraud proof before validating it.
        self.inner.validate_transaction(at, source, uxt.clone())
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

    fn block_body(&self, id: Block::Hash) -> Self::BodyFuture {
        self.inner.block_body(id)
    }

    fn block_header(&self, hash: Block::Hash) -> Result<Option<Block::Header>, Self::Error> {
        self.inner.block_header(hash)
    }

    fn tree_route(
        &self,
        from: Block::Hash,
        to: Block::Hash,
    ) -> Result<TreeRoute<Self::Block>, Self::Error> {
        sp_blockchain::tree_route::<Block, Client>(&*self.client, from, to).map_err(Into::into)
    }
}

pub struct BasicPoolWrapper<Block, PoolApi>
where
    Block: BlockT,
    PoolApi: ChainApi<Block = Block>,
{
    inner: BasicPool<PoolApi, Block>,
}

impl<Block, PoolApi> BasicPoolWrapper<Block, PoolApi>
where
    Block: BlockT,
    PoolApi: ChainApi<Block = Block> + 'static,
{
    fn with_revalidation_type<Client, Spawn>(
        transaction_pool_options: TransactionPoolOptions,
        is_authoring_blocks: bool,
        pool_api: Arc<PoolApi>,
        prometheus: Option<&PrometheusRegistry>,
        spawner: Spawn,
        client: Arc<Client>,
    ) -> Self
    where
        Client: UsageProvider<Block>,
        Spawn: SpawnEssentialNamed,
    {
        let basic_pool = BasicPool::with_revalidation_type(
            transaction_pool_options,
            is_authoring_blocks.into(),
            pool_api,
            prometheus,
            RevalidationType::Full,
            spawner,
            client.usage_info().chain.best_number,
            client.usage_info().chain.best_hash,
            client.usage_info().chain.finalized_hash,
        );

        Self { inner: basic_pool }
    }

    /// Gets shared reference to the underlying pool.
    pub fn pool(&self) -> &Arc<Pool<PoolApi>> {
        self.inner.pool()
    }

    pub fn api(&self) -> &PoolApi {
        self.inner.api()
    }
}

impl<Block, Client, DomainHeader> LocalTransactionPool
    for BasicPoolWrapper<Block, FullChainApiWrapper<Client, Block, DomainHeader>>
where
    Block: BlockT,
    <<Block::Header as HeaderT>::Number as TryInto<u32>>::Error: std::fmt::Debug,
    DomainHeader: HeaderT,
    Client: ProvideRuntimeApi<Block>
        + AuxStore
        + BlockBackend<Block>
        + BlockIdTo<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + Send
        + Sync
        + 'static,
    Client::Api: TaggedTransactionQueue<Block>
        + SubspaceApi<Block, PublicKey>
        + DomainsApi<Block, DomainHeader>,
{
    type Block = Block;
    type Hash = ExtrinsicHash<FullChainApiWrapper<Client, Block, DomainHeader>>;
    type Error = <FullChainApiWrapper<Client, Block, DomainHeader> as ChainApi>::Error;

    fn submit_local(
        &self,
        at: Block::Hash,
        xt: sc_transaction_pool_api::LocalTransactionFor<Self>,
    ) -> Result<Self::Hash, Self::Error> {
        let validity = self
            .api()
            .validate_transaction_blocking(at, TransactionSource::Local, xt.clone())?
            .map_err(|e| {
                Self::Error::Pool(match e {
                    TransactionValidityError::Invalid(i) => {
                        sc_transaction_pool_api::error::Error::InvalidTransaction(i)
                    }
                    TransactionValidityError::Unknown(u) => {
                        sc_transaction_pool_api::error::Error::UnknownTransaction(u)
                    }
                })
            })?;
        let (hash, bytes) = self.pool().validated_pool().api().hash_and_length(&xt);
        let block_number = self
            .api()
            .block_id_to_number(&BlockId::Hash(at))?
            .ok_or_else(|| sc_transaction_pool::error::Error::BlockIdConversion(at.to_string()))?;
        let validated = ValidatedTransaction::valid_at(
            block_number.saturated_into::<u64>(),
            hash,
            TransactionSource::Local,
            xt,
            bytes,
            validity,
        );
        self.pool()
            .validated_pool()
            .submit(vec![validated])
            .remove(0)
    }
}

impl<Block, PoolApi> TransactionPool for BasicPoolWrapper<Block, PoolApi>
where
    Block: BlockT,
    PoolApi: ChainApi<Block = Block> + 'static,
{
    type Block = Block;
    type Hash = ExtrinsicHash<PoolApi>;
    type InPoolTransaction = Transaction<TxHash<Self>, TransactionFor<Self>>;
    type Error = PoolApi::Error;

    fn submit_at(
        &self,
        at: Block::Hash,
        source: TransactionSource,
        xts: Vec<TransactionFor<Self>>,
    ) -> PoolFuture<Vec<Result<TxHash<Self>, Self::Error>>, Self::Error> {
        self.inner.submit_at(at, source, xts)
    }

    fn submit_one(
        &self,
        at: Block::Hash,
        source: TransactionSource,
        xt: TransactionFor<Self>,
    ) -> PoolFuture<TxHash<Self>, Self::Error> {
        self.inner.submit_one(at, source, xt)
    }

    fn submit_and_watch(
        &self,
        at: Block::Hash,
        source: TransactionSource,
        xt: TransactionFor<Self>,
    ) -> PoolFuture<Pin<Box<TransactionStatusStreamFor<Self>>>, Self::Error> {
        self.inner.submit_and_watch(at, source, xt)
    }

    fn ready_at(&self, at: NumberFor<Self::Block>) -> PolledIterator<PoolApi> {
        self.inner.ready_at(at)
    }

    fn ready(&self) -> ReadyIteratorFor<PoolApi> {
        self.inner.ready()
    }

    fn remove_invalid(&self, hashes: &[TxHash<Self>]) -> Vec<Arc<Self::InPoolTransaction>> {
        self.inner.remove_invalid(hashes)
    }

    fn status(&self) -> PoolStatus {
        self.inner.status()
    }

    fn futures(&self) -> Vec<Self::InPoolTransaction> {
        self.inner.futures()
    }

    fn import_notification_stream(&self) -> ImportNotificationStream<TxHash<Self>> {
        self.inner.import_notification_stream()
    }

    fn on_broadcasted(&self, propagations: HashMap<TxHash<Self>, Vec<String>>) {
        self.inner.on_broadcasted(propagations)
    }

    fn hash_of(&self, xt: &TransactionFor<Self>) -> TxHash<Self> {
        self.inner.hash_of(xt)
    }

    fn ready_transaction(&self, hash: &TxHash<Self>) -> Option<Arc<Self::InPoolTransaction>> {
        self.inner.ready_transaction(hash)
    }
}

#[async_trait]
impl<Block, PoolApi> MaintainedTransactionPool for BasicPoolWrapper<Block, PoolApi>
where
    Block: BlockT,
    PoolApi: ChainApi<Block = Block> + 'static,
{
    async fn maintain(&self, event: ChainEvent<Self::Block>) {
        self.inner.maintain(event).await
    }
}

pub fn new_full<Client, Block, DomainHeader>(
    transaction_pool_options: TransactionPoolOptions,
    is_authoring_blocks: bool,
    prometheus_registry: Option<&PrometheusRegistry>,
    task_manager: &TaskManager,
    client: Arc<Client>,
) -> sp_blockchain::Result<Arc<FullPool<Client, Block, DomainHeader>>>
where
    Block: BlockT,
    <<Block::Header as HeaderT>::Number as TryInto<u32>>::Error: std::fmt::Debug,
    Client: ProvideRuntimeApi<Block>
        + AuxStore
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + ExecutorProvider<Block>
        + UsageProvider<Block>
        + BlockIdTo<Block>
        + Send
        + Sync
        + 'static,
    DomainHeader: HeaderT,
    Client::Api: TaggedTransactionQueue<Block>
        + SubspaceApi<Block, PublicKey>
        + DomainsApi<Block, DomainHeader>,
{
    let pool_api = Arc::new(FullChainApiWrapper::new(
        client.clone(),
        prometheus_registry,
        task_manager,
    )?);

    let basic_pool = Arc::new(BasicPoolWrapper::with_revalidation_type(
        transaction_pool_options,
        is_authoring_blocks,
        pool_api,
        prometheus_registry,
        task_manager.spawn_essential_handle(),
        client.clone(),
    ));

    Ok(basic_pool)
}
