use async_trait::async_trait;
use futures::future::{Future, FutureExt, Ready};
use sc_client_api::blockchain::HeaderBackend;
use sc_client_api::{AuxStore, BlockBackend, ExecutorProvider, UsageProvider};
use sc_service::{Configuration, TaskManager};
use sc_transaction_pool::error::{Error as TxPoolError, Result as TxPoolResult};
use sc_transaction_pool::{
    BasicPool, ChainApi, FullChainApi, Pool, RevalidationType, Transaction, ValidatedTransaction,
};
use sc_transaction_pool_api::{
    ChainEvent, ImportNotificationStream, LocalTransactionPool, MaintainedTransactionPool,
    OffchainTransactionPoolFactory, PoolFuture, PoolStatus, ReadyTransactions, TransactionFor,
    TransactionPool, TransactionSource, TransactionStatusStreamFor, TxHash,
};
use sp_api::{ApiExt, HeaderT, ProvideRuntimeApi};
use sp_blockchain::{HeaderMetadata, TreeRoute};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{ChainConstants, FarmerPublicKey, SubspaceApi};
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::DomainsApi;
use sp_domains_fraud_proof::bundle_equivocation::check_equivocation;
use sp_domains_fraud_proof::fraud_proof::FraudProof;
use sp_domains_fraud_proof::{FraudProofsApi, InvalidTransactionCode};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, BlockIdTo, Header, NumberFor};
use sp_runtime::transaction_validity::{TransactionValidity, TransactionValidityError};
use sp_runtime::SaturatedConversion;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use substrate_prometheus_endpoint::Registry as PrometheusRegistry;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::log::error;

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
    sync_target_block_number: Arc<AtomicU32>,
    chain_constants: ChainConstants,
    fraud_proof_submit_sink:
        UnboundedSender<FraudProof<NumberFor<Block>, Block::Hash, DomainHeader>>,
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
    Client::Api: TaggedTransactionQueue<Block> + SubspaceApi<Block, FarmerPublicKey>,
    DomainHeader: HeaderT,
{
    fn new(
        client: Arc<Client>,
        prometheus: Option<&PrometheusRegistry>,
        task_manager: &TaskManager,
        sync_target_block_number: Arc<AtomicU32>,
        fraud_proof_submit_sink: UnboundedSender<
            FraudProof<NumberFor<Block>, Block::Hash, DomainHeader>,
        >,
    ) -> sp_blockchain::Result<Self> {
        let chain_constants = client
            .runtime_api()
            .chain_constants(client.info().best_hash)?;
        Ok(Self {
            inner: Arc::new(FullChainApi::new(
                client.clone(),
                prometheus,
                &task_manager.spawn_essential_handle(),
            )),
            client,
            sync_target_block_number,
            chain_constants,
            fraud_proof_submit_sink,
            marker: Default::default(),
        })
    }

    fn validate_transaction_blocking(
        &self,
        at: &BlockId<Block>,
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
    <<<Block as BlockT>::Header as HeaderT>::Number as TryInto<u32>>::Error: std::fmt::Debug,
    Client: ProvideRuntimeApi<Block>
        + AuxStore
        + BlockBackend<Block>
        + BlockIdTo<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + Send
        + Sync
        + 'static,
    DomainHeader: Header,
    Client::Api: TaggedTransactionQueue<Block>
        + SubspaceApi<Block, FarmerPublicKey>
        + DomainsApi<Block, DomainHeader>,
{
    type Block = Block;
    type Error = sc_transaction_pool::error::Error;
    type ValidationFuture = ValidationFuture;
    type BodyFuture = Ready<TxPoolResult<Option<Vec<<Self::Block as BlockT>::Extrinsic>>>>;

    fn validate_transaction(
        &self,
        at: &BlockId<Self::Block>,
        source: TransactionSource,
        uxt: ExtrinsicFor<Self>,
    ) -> Self::ValidationFuture {
        let at = match self.client.block_hash_from_id(at) {
            Ok(Some(at)) => at,
            Ok(None) => {
                let error = sc_transaction_pool::error::Error::BlockIdConversion(format!(
                    "Failed to convert block id {at} to hash: block not found"
                ));
                return Box::pin(async move { Err(error) });
            }
            Err(error) => {
                let error = sc_transaction_pool::error::Error::BlockIdConversion(format!(
                    "Failed to convert block id {at} to hash: {error}"
                ));
                return Box::pin(async move { Err(error) });
            }
        };

        let chain_api = self.inner.clone();
        let client = self.client.clone();
        let best_block_number = TryInto::<u32>::try_into(client.info().best_number)
            .expect("Block number will always fit into u32; qed");
        let diff_in_blocks = self
            .sync_target_block_number
            .load(Ordering::Relaxed)
            .saturating_sub(best_block_number);
        let slot_probability = self.chain_constants.slot_probability();
        let fraud_proof_submit_sink = self.fraud_proof_submit_sink.clone();
        async move {
            let uxt_validity = chain_api
                .validate_transaction(&BlockId::Hash(at), source, uxt.clone())
                .await?;

            if uxt_validity.is_ok() {
                // Transaction is successfully validated.
                // If the transaction is `submit_bundle`, then extract the bundle
                // and check for equivocation.
                let runtime_api = client.runtime_api();
                let domains_api_version = runtime_api
                    .api_version::<dyn DomainsApi<Block, DomainHeader>>(at)
                    .map_err(|err| {
                        TxPoolError::RuntimeApi(format!(
                            "Failed to get `DomainsApi` version for block {at:?}: {err:?}."
                        ))
                    })?
                    // safe to return default version as 1 since there will always be version 1.
                    .unwrap_or(1);
                if domains_api_version >= 2 {
                    let maybe_opaque_bundle = runtime_api
                        .extract_bundle(at, uxt)
                        .map_err(|err| TxPoolError::RuntimeApi(err.to_string()))?;
                    if let Some(opaque_bundle) = maybe_opaque_bundle {
                        let slot = opaque_bundle
                            .sealed_header
                            .header
                            .proof_of_election
                            .slot_number
                            .into();

                        let slot_now = if diff_in_blocks > 0 {
                            slot + Slot::from(
                                u64::from(diff_in_blocks) * slot_probability.1 / slot_probability.0,
                            )
                        } else {
                            slot
                        };

                        let maybe_equivocation_fraud_proof = check_equivocation::<_, Block, _>(
                            &client,
                            slot_now,
                            opaque_bundle.sealed_header,
                        )?;

                        if let Some(equivocation_fraud_proof) = maybe_equivocation_fraud_proof {
                            let sent_result =
                                fraud_proof_submit_sink.send(equivocation_fraud_proof);
                            if let Err(err) = sent_result {
                                error!(
                                    target: "consensus-fraud-proof-sender",
                                    "failed to send fraud proof to be submitted: {err:?}"
                                );
                            }

                            return Err(TxPoolError::Pool(
                                sc_transaction_pool_api::error::Error::InvalidTransaction(
                                    InvalidTransactionCode::BundleEquivocation.into(),
                                ),
                            ));
                        }
                    }
                }
            }

            Ok(uxt_validity)
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
    <<<Block as BlockT>::Header as HeaderT>::Number as TryInto<u32>>::Error: std::fmt::Debug,
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
        + SubspaceApi<Block, FarmerPublicKey>
        + FraudProofsApi<Block, DomainHeader>
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
        let at = BlockId::Hash(at);
        let validity = self
            .api()
            .validate_transaction_blocking(&at, TransactionSource::Local, xt.clone())?
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
            .block_id_to_number(&at)?
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
    config: &Configuration,
    task_manager: &TaskManager,
    client: Arc<Client>,
    sync_target_block_number: Arc<AtomicU32>,
) -> sp_blockchain::Result<Arc<FullPool<Client, Block, DomainHeader>>>
where
    Block: BlockT,
    <<<Block as BlockT>::Header as HeaderT>::Number as TryInto<u32>>::Error: std::fmt::Debug,
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
        + SubspaceApi<Block, FarmerPublicKey>
        + FraudProofsApi<Block, DomainHeader>
        + DomainsApi<Block, DomainHeader>,
{
    let prometheus = config.prometheus_registry();
    let (fraud_proof_submit_sink, mut fraud_proof_submit_stream) = mpsc::unbounded_channel();
    let pool_api = Arc::new(FullChainApiWrapper::new(
        client.clone(),
        prometheus,
        task_manager,
        sync_target_block_number,
        fraud_proof_submit_sink,
    )?);

    let basic_pool = Arc::new(BasicPoolWrapper::with_revalidation_type(
        config,
        pool_api,
        prometheus,
        task_manager.spawn_essential_handle(),
        client.clone(),
    ));

    let offchain_tx_pool_factory = OffchainTransactionPoolFactory::new(basic_pool.clone());

    task_manager
        .spawn_essential_handle()
        .spawn_essential_blocking(
            "consensus-fraud-proof-submitter",
            None,
            Box::pin(async move {
                loop {
                    if let Some(fraud_proof) = fraud_proof_submit_stream.recv().await {
                        let mut runtime_api = client.runtime_api();
                        let best_hash = client.info().best_hash;
                        runtime_api.register_extension(
                            offchain_tx_pool_factory.offchain_transaction_pool(best_hash),
                        );
                        let result =
                            runtime_api.submit_fraud_proof_unsigned(best_hash, fraud_proof);
                        if let Err(err) = result {
                            error!(
                                target: "consensus-fraud-proof-submitter",
                                "failed to submit fraud proof: {err:?}"
                            );
                        }
                    }
                }
            }),
        );

    Ok(basic_pool)
}
