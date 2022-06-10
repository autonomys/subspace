use futures::channel::oneshot;
use futures::future::{Future, FutureExt, Ready};
use sc_client_api::blockchain::HeaderBackend;
use sc_client_api::{BlockBackend, ExecutorProvider, UsageProvider};
use sc_service::{Configuration, TaskManager};
use sc_transaction_pool::error::Result as TxPoolResult;
use sc_transaction_pool::{
    BasicPool, ChainApi, FullChainApi, Pool, RevalidationType, Transaction, ValidatedTransaction,
};
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_transaction_pool_api::{
    ChainEvent, ImportNotificationStream, MaintainedTransactionPool, PoolFuture, PoolStatus,
    ReadyTransactions, TransactionFor, TransactionPool, TransactionSource,
    TransactionStatusStreamFor, TxHash,
};
use sp_api::{Core, ProvideRuntimeApi, RuntimeApiInfo};
use sp_core::traits::{SpawnEssentialNamed, SpawnNamed};
use sp_executor::ExecutorApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, BlockIdTo, NumberFor, SaturatedConversion};
use sp_runtime::transaction_validity::{
    TransactionValidity, TransactionValidityError, UnknownTransaction,
};
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use subspace_fraud_proof::VerifyFraudProof;
use substrate_prometheus_endpoint::Registry as PrometheusRegistry;

/// Block hash type for a pool.
type BlockHash<A> = <<A as ChainApi>::Block as BlockT>::Hash;

/// Extrinsic hash type for a pool.
type ExtrinsicHash<A> = <<A as ChainApi>::Block as BlockT>::Hash;

/// Extrinsic type for a pool.
type ExtrinsicFor<A> = <<A as ChainApi>::Block as BlockT>::Extrinsic;

/// A transaction pool for a full node.
pub type FullPool<Block, Client, Verifier> =
    BasicPoolWrapper<Block, FullChainApiWrapper<Block, Client, Verifier>>;

type BoxedReadyIterator<Hash, Data> =
    Box<dyn ReadyTransactions<Item = Arc<Transaction<Hash, Data>>> + Send>;

type ReadyIteratorFor<PoolApi> = BoxedReadyIterator<ExtrinsicHash<PoolApi>, ExtrinsicFor<PoolApi>>;

type PolledIterator<PoolApi> = Pin<Box<dyn Future<Output = ReadyIteratorFor<PoolApi>> + Send>>;

pub struct FullChainApiWrapper<Block, Client, Verifier> {
    inner: Arc<FullChainApi<Client, Block>>,
    client: Arc<Client>,
    verifier: Verifier,
    spawner: Box<dyn SpawnNamed>,
}

impl<Block, Client, Verifier> FullChainApiWrapper<Block, Client, Verifier>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + BlockIdTo<Block>
        + HeaderBackend<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: TaggedTransactionQueue<Block> + ExecutorApi<Block, cirrus_primitives::Hash>,
    Verifier: VerifyFraudProof + Clone + Send + Sync + 'static,
{
    fn new(
        client: Arc<Client>,
        prometheus: Option<&PrometheusRegistry>,
        task_manager: &TaskManager,
        verifier: Verifier,
    ) -> Self {
        Self {
            inner: Arc::new(FullChainApi::new(
                client.clone(),
                prometheus,
                &task_manager.spawn_essential_handle(),
            )),
            client,
            verifier,
            spawner: Box::new(task_manager.spawn_handle()),
        }
    }

    fn validate_transaction_blocking(
        &self,
        at: &BlockId<Block>,
        source: TransactionSource,
        uxt: ExtrinsicFor<Self>,
    ) -> TxPoolResult<TransactionValidity> {
        self.inner.validate_transaction_blocking(at, source, uxt)
    }
}

impl<Block, Client, Verifier> ChainApi for FullChainApiWrapper<Block, Client, Verifier>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + BlockIdTo<Block>
        + HeaderBackend<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: TaggedTransactionQueue<Block> + ExecutorApi<Block, cirrus_primitives::Hash>,
    Verifier: VerifyFraudProof + Clone + Send + Sync + 'static,
{
    type Block = Block;
    type Error = sc_transaction_pool::error::Error;
    type ValidationFuture = Pin<Box<dyn Future<Output = TxPoolResult<TransactionValidity>> + Send>>;
    type BodyFuture = Ready<TxPoolResult<Option<Vec<<Self::Block as BlockT>::Extrinsic>>>>;

    fn block_body(&self, id: &BlockId<Self::Block>) -> Self::BodyFuture {
        self.inner.block_body(id)
    }

    fn validate_transaction(
        &self,
        at: &BlockId<Self::Block>,
        source: TransactionSource,
        uxt: ExtrinsicFor<Self>,
    ) -> Self::ValidationFuture {
        let executor_api_version =
            match self
                .client
                .runtime_api()
                .version(at)
                .ok()
                .and_then(|runtime_version| {
                    runtime_version
                        .api_version(&<dyn ExecutorApi<Block, cirrus_primitives::Hash>>::ID)
                }) {
                Some(api_version) => api_version,
                None => {
                    return async move {
                        Err(sc_transaction_pool::error::Error::RuntimeApi(
                            "Unable to retrieve ExecutorApi's api version".to_string(),
                        ))
                    }
                    .boxed();
                }
            };

        // `extract_fraud_proof` is added since ExecutorApi version 2
        // TODO: reset the ExecutorApi api version and remove this check when the network is reset.
        if executor_api_version >= 2 {
            match self.client.runtime_api().extract_fraud_proof(at, &uxt) {
                Ok(maybe_fraud_proof) => {
                    if let Some(fraud_proof) = maybe_fraud_proof {
                        let inner = self.inner.clone();
                        let spawner = self.spawner.clone();
                        let fraud_proof_verifier = self.verifier.clone();
                        let at = *at;

                        return async move {
                        let (verified_result_sender, verified_result_receiver) = oneshot::channel();

                        // Verify the fraud proof in another blocking task as it might be pretty heavy.
                        spawner.spawn_blocking(
                            "txpool-fraud-proof-verification",
                            None,
                            async move {
                                let verified_result =
                                    fraud_proof_verifier.verify_fraud_proof(&fraud_proof);
                                verified_result_sender
                                    .send(verified_result)
                                    .expect("Failed to send the verified fraud proof result");
                            }
                            .boxed(),
                        );

                        match verified_result_receiver.await  {
                            Ok(verified_result) => {
                                match verified_result {
                                    Ok(_) => inner.validate_transaction(&at, source, uxt).await,
                                    Err(err) => {
                                        tracing::debug!(target: "txpool", error = ?err, "Invalid fraud proof");
                                        Err(TxPoolError::InvalidTransaction(
                                            sp_executor::InvalidTransactionCode::FraudProof.into(),
                                        )
                                        .into())
                                    }
                                }
                            }
                            Err(err) => {
                                tracing::debug!(target: "txpool", error = ?err, "Failed to receive the fraud proof verified result");
                                Err(TxPoolError::UnknownTransaction(UnknownTransaction::CannotLookup).into())
                            }
                        }
                    }
                    .boxed();
                    }
                }
                Err(err) => {
                    return async move {
                        Err(sc_transaction_pool::error::Error::Blockchain(err.into()))
                    }
                    .boxed();
                }
            }
        }

        self.inner.validate_transaction(at, source, uxt)
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

    fn block_header(
        &self,
        at: &BlockId<Self::Block>,
    ) -> Result<Option<<Self::Block as BlockT>::Header>, Self::Error> {
        self.inner.block_header(at)
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
        config: &Configuration,
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
            config.transaction_pool.clone(),
            config.role.is_authority().into(),
            pool_api,
            prometheus,
            RevalidationType::Full,
            spawner,
            client.usage_info().chain.best_number,
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

impl<Block, Client, Verifier> sc_transaction_pool_api::LocalTransactionPool
    for BasicPoolWrapper<Block, FullChainApiWrapper<Block, Client, Verifier>>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + BlockIdTo<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: TaggedTransactionQueue<Block> + ExecutorApi<Block, cirrus_primitives::Hash>,
    Verifier: VerifyFraudProof + Clone + Send + Sync + 'static,
{
    type Block = Block;
    type Hash = ExtrinsicHash<FullChainApiWrapper<Block, Client, Verifier>>;
    type Error = <FullChainApiWrapper<Block, Client, Verifier> as ChainApi>::Error;

    fn submit_local(
        &self,
        at: &BlockId<Self::Block>,
        xt: sc_transaction_pool_api::LocalTransactionFor<Self>,
    ) -> Result<Self::Hash, Self::Error> {
        let validity = self
            .api()
            .validate_transaction_blocking(at, TransactionSource::Local, xt.clone())?
            .map_err(|e| {
                Self::Error::Pool(match e {
                    TransactionValidityError::Invalid(i) => TxPoolError::InvalidTransaction(i),
                    TransactionValidityError::Unknown(u) => TxPoolError::UnknownTransaction(u),
                })
            })?;
        let (hash, bytes) = self.pool().validated_pool().api().hash_and_length(&xt);
        let block_number = self.api().block_id_to_number(at)?.ok_or_else(|| {
            sc_transaction_pool::error::Error::BlockIdConversion(format!("{:?}", at))
        })?;
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
        at: &BlockId<Self::Block>,
        source: TransactionSource,
        xts: Vec<TransactionFor<Self>>,
    ) -> PoolFuture<Vec<Result<TxHash<Self>, Self::Error>>, Self::Error> {
        self.inner.submit_at(at, source, xts)
    }

    fn submit_one(
        &self,
        at: &BlockId<Self::Block>,
        source: TransactionSource,
        xt: TransactionFor<Self>,
    ) -> PoolFuture<TxHash<Self>, Self::Error> {
        self.inner.submit_one(at, source, xt)
    }

    fn submit_and_watch(
        &self,
        at: &BlockId<Self::Block>,
        source: TransactionSource,
        xt: TransactionFor<Self>,
    ) -> PoolFuture<Pin<Box<TransactionStatusStreamFor<Self>>>, Self::Error> {
        self.inner.submit_and_watch(at, source, xt)
    }

    fn remove_invalid(&self, hashes: &[TxHash<Self>]) -> Vec<Arc<Self::InPoolTransaction>> {
        self.inner.remove_invalid(hashes)
    }

    fn status(&self) -> PoolStatus {
        self.inner.status()
    }

    fn import_notification_stream(&self) -> ImportNotificationStream<TxHash<Self>> {
        self.inner.import_notification_stream()
    }

    fn hash_of(&self, xt: &TransactionFor<Self>) -> TxHash<Self> {
        self.inner.hash_of(xt)
    }

    fn on_broadcasted(&self, propagations: HashMap<TxHash<Self>, Vec<String>>) {
        self.inner.on_broadcasted(propagations)
    }

    fn ready_transaction(&self, hash: &TxHash<Self>) -> Option<Arc<Self::InPoolTransaction>> {
        self.inner.ready_transaction(hash)
    }

    fn ready_at(&self, at: NumberFor<Self::Block>) -> PolledIterator<PoolApi> {
        self.inner.ready_at(at)
    }

    fn ready(&self) -> ReadyIteratorFor<PoolApi> {
        self.inner.ready()
    }
}

impl<Block, PoolApi> MaintainedTransactionPool for BasicPoolWrapper<Block, PoolApi>
where
    Block: BlockT,
    PoolApi: ChainApi<Block = Block> + 'static,
{
    fn maintain(&self, event: ChainEvent<Self::Block>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        self.inner.maintain(event)
    }
}

impl<Block, PoolApi> parity_util_mem::MallocSizeOf for BasicPoolWrapper<Block, PoolApi>
where
    Block: BlockT,
    PoolApi: ChainApi<Block = Block>,
{
    fn size_of(&self, ops: &mut parity_util_mem::MallocSizeOfOps) -> usize {
        self.inner.size_of(ops)
    }
}

pub(super) fn new_full<Block, Client, Verifier>(
    config: &Configuration,
    task_manager: &TaskManager,
    client: Arc<Client>,
    verifier: Verifier,
) -> Arc<BasicPoolWrapper<Block, FullChainApiWrapper<Block, Client, Verifier>>>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + ExecutorProvider<Block>
        + UsageProvider<Block>
        + BlockIdTo<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: TaggedTransactionQueue<Block> + ExecutorApi<Block, cirrus_primitives::Hash>,
    Verifier: VerifyFraudProof + Clone + Send + Sync + 'static,
{
    let prometheus = config.prometheus_registry();
    let pool_api = Arc::new(FullChainApiWrapper::new(
        client.clone(),
        prometheus,
        task_manager,
        verifier,
    ));
    let pool = Arc::new(BasicPoolWrapper::with_revalidation_type(
        config,
        pool_api,
        prometheus,
        task_manager.spawn_essential_handle(),
        client.clone(),
    ));

    // make transaction pool available for off-chain runtime calls.
    client
        .execution_extensions()
        .register_transaction_pool(&pool);

    pool
}
