use crate::domain_block_processor::{DomainBlockProcessor, ReceiptsChecker};
use crate::domain_bundle_producer::DomainBundleProducer;
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::fraud_proof::FraudProofGenerator;
use crate::parent_chain::SystemDomainParentChain;
use crate::system_bundle_processor::SystemBundleProcessor;
use crate::{active_leaves, DomainImportNotifications, EssentialExecutorParams, TransactionFor};
use domain_runtime_primitives::DomainCoreApi;
use futures::channel::mpsc;
use futures::{FutureExt, Stream};
use sc_client_api::{
    AuxStore, BlockBackend, BlockImportNotification, BlockchainEvents, Finalizer, ProofProvider,
    StateBackendFor,
};
use sc_utils::mpsc::tracing_unbounded;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::SelectChain;
use sp_consensus_slots::Slot;
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed, SpawnNamed};
use sp_domains::{DomainId, ExecutorApi};
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, HashFor, NumberFor};
use sp_settlement::SettlementApi;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use system_runtime_primitives::SystemDomainApi;

/// System domain executor.
pub struct Executor<Block, PBlock, Client, PClient, TransactionPool, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
{
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    spawner: Box<dyn SpawnNamed + Send + Sync>,
    transaction_pool: Arc<TransactionPool>,
    backend: Arc<Backend>,
    fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, PClient, Backend, E>,
    bundle_processor: SystemBundleProcessor<Block, PBlock, Client, PClient, Backend, E>,
    domain_block_processor: DomainBlockProcessor<Block, PBlock, Client, PClient, Backend, Client>,
}

impl<Block, PBlock, Client, PClient, TransactionPool, Backend, E> Clone
    for Executor<Block, PBlock, Client, PClient, TransactionPool, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            primary_chain_client: self.primary_chain_client.clone(),
            client: self.client.clone(),
            spawner: self.spawner.clone(),
            transaction_pool: self.transaction_pool.clone(),
            backend: self.backend.clone(),
            fraud_proof_generator: self.fraud_proof_generator.clone(),
            bundle_processor: self.bundle_processor.clone(),
            domain_block_processor: self.domain_block_processor.clone(),
        }
    }
}

impl<Block, PBlock, Client, PClient, TransactionPool, Backend, E>
    Executor<Block, PBlock, Client, PClient, TransactionPool, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
    NumberFor<PBlock>: From<NumberFor<Block>> + Into<NumberFor<Block>>,
    PBlock::Hash: From<Block::Hash>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + Finalizer<Block, Backend>
        + 'static,
    Client::Api: DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<Block>>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash, Block::Hash>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    for<'b> &'b Client: sc_consensus::BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    PClient: HeaderBackend<PBlock>
        + HeaderMetadata<PBlock, Error = sp_blockchain::Error>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + BlockchainEvents<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash> + SettlementApi<PBlock, Block::Hash>,
    Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    E: CodeExecutor,
{
    /// Create a new instance.
    pub async fn new<SC, IBNS, CIBNS, NSNS>(
        spawn_essential: Box<dyn SpawnEssentialNamed>,
        select_chain: &SC,
        params: EssentialExecutorParams<
            Block,
            PBlock,
            Client,
            PClient,
            TransactionPool,
            Backend,
            E,
            IBNS,
            CIBNS,
            NSNS,
            Client,
        >,
    ) -> Result<Self, sp_consensus::Error>
    where
        SC: SelectChain<PBlock>,
        IBNS: Stream<Item = (NumberFor<PBlock>, mpsc::Sender<()>)> + Send + 'static,
        CIBNS: Stream<Item = BlockImportNotification<PBlock>> + Send + 'static,
        NSNS: Stream<Item = (Slot, Blake2b256Hash, Option<mpsc::Sender<()>>)> + Send + 'static,
    {
        let active_leaves =
            active_leaves(params.primary_chain_client.as_ref(), select_chain).await?;

        let parent_chain = SystemDomainParentChain::new(params.primary_chain_client.clone());

        let domain_bundle_proposer = DomainBundleProposer::new(
            params.client.clone(),
            params.primary_chain_client.clone(),
            params.transaction_pool.clone(),
        );

        let bundle_producer = DomainBundleProducer::new(
            DomainId::SYSTEM,
            params.client.clone(),
            params.client.clone(),
            parent_chain.clone(),
            domain_bundle_proposer,
            params.bundle_sender,
            params.keystore.clone(),
        );

        let fraud_proof_generator = FraudProofGenerator::new(
            params.client.clone(),
            params.primary_chain_client.clone(),
            params.spawner.clone(),
            params.backend.clone(),
            params.code_executor,
        );

        let domain_block_processor = DomainBlockProcessor {
            domain_id: DomainId::SYSTEM,
            client: params.client.clone(),
            primary_chain_client: params.primary_chain_client.clone(),
            backend: params.backend.clone(),
            domain_confirmation_depth: params.domain_confirmation_depth,
            block_import: params.block_import,
            import_notification_sinks: Default::default(),
        };

        let receipts_checker = ReceiptsChecker {
            domain_id: DomainId::SYSTEM,
            client: params.client.clone(),
            primary_chain_client: params.primary_chain_client.clone(),
            fraud_proof_generator: fraud_proof_generator.clone(),
            parent_chain,
            primary_network_sync_oracle: params.primary_network_sync_oracle,
            _phantom: std::marker::PhantomData,
        };

        let bundle_processor = SystemBundleProcessor::new(
            params.primary_chain_client.clone(),
            params.client.clone(),
            params.backend.clone(),
            params.keystore,
            receipts_checker,
            domain_block_processor.clone(),
        );

        spawn_essential.spawn_essential_blocking(
            "system-executor-worker",
            None,
            crate::system_domain_worker::start_worker(
                spawn_essential.clone(),
                params.primary_chain_client.clone(),
                params.client.clone(),
                params.is_authority,
                bundle_producer,
                bundle_processor.clone(),
                params.executor_streams,
                active_leaves,
            )
            .boxed(),
        );

        Ok(Self {
            primary_chain_client: params.primary_chain_client,
            client: params.client,
            spawner: params.spawner,
            transaction_pool: params.transaction_pool,
            backend: params.backend,
            fraud_proof_generator,
            bundle_processor,
            domain_block_processor,
        })
    }

    pub fn fraud_proof_generator(
        &self,
    ) -> FraudProofGenerator<Block, PBlock, Client, PClient, Backend, E> {
        self.fraud_proof_generator.clone()
    }

    /// Get system domain block import notification stream.
    ///
    /// NOTE: Unlike `BlockchainEvents::import_notification_stream()`, this notification won't be
    /// fired until the system domain block's receipt processing is done.
    pub fn import_notification_stream(&self) -> DomainImportNotifications<Block, PBlock> {
        let (sink, stream) = tracing_unbounded("mpsc_domain_import_notification_stream", 100);
        self.domain_block_processor
            .import_notification_sinks
            .lock()
            .push(sink);
        stream
    }

    /// Processes the bundles extracted from the primary block.
    // TODO: Remove this whole method, `self.bundle_processor` as a property and fix
    // `set_new_code_should_work` test to do an actual runtime upgrade
    #[doc(hidden)]
    pub async fn process_bundles(self, primary_info: (PBlock::Hash, NumberFor<PBlock>)) {
        if let Err(err) = self.bundle_processor.process_bundles(primary_info).await {
            tracing::error!(?primary_info, ?err, "Error at processing bundles.");
        }
    }
}
