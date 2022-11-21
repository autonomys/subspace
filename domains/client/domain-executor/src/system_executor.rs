use crate::domain_block_processor::DomainBlockProcessor;
use crate::fraud_proof::FraudProofGenerator;
use crate::system_bundle_processor::SystemBundleProcessor;
use crate::system_bundle_producer::SystemBundleProducer;
use crate::utils::DomainBundles;
use crate::{active_leaves, EssentialExecutorParams, TransactionFor, LOG_TARGET};
use domain_runtime_primitives::{AccountId, DomainCoreApi};
use futures::channel::mpsc;
use futures::{FutureExt, Stream};
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sc_consensus::ForkChoiceStrategy;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::SelectChain;
use sp_consensus_slots::Slot;
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed, SpawnNamed};
use sp_domains::{DomainId, ExecutorApi, OpaqueBundle};
use sp_runtime::traits::{Block as BlockT, HashFor, NumberFor};
use std::borrow::Cow;
use std::sync::Arc;
use subspace_core_primitives::{Blake2b256Hash, Randomness};
use system_runtime_primitives::SystemDomainApi;

/// The implementation of the Domain `Executor`.
pub struct Executor<Block, PBlock, Client, PClient, TransactionPool, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
{
    // TODO: no longer used in executor, revisit this with ParachainBlockImport together.
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    spawner: Box<dyn SpawnNamed + Send + Sync>,
    transaction_pool: Arc<TransactionPool>,
    backend: Arc<Backend>,
    fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, Backend, E>,
    bundle_processor: SystemBundleProcessor<Block, PBlock, Client, PClient, Backend, E>,
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
        }
    }
}

impl<Block, PBlock, Client, PClient, TransactionPool, Backend, E>
    Executor<Block, PBlock, Client, PClient, TransactionPool, Backend, E>
where
    Block: BlockT,
    PBlock: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + 'static,
    Client::Api: DomainCoreApi<Block, AccountId>
        + SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<
            Block,
            StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
        >,
    for<'b> &'b Client: sc_consensus::BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    PClient: HeaderBackend<PBlock>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + Send
        + Sync
        + 'static,
    PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    E: CodeExecutor,
{
    /// Create a new instance.
    pub async fn new<SE, SC, IBNS, NSNS>(
        spawn_essential: &SE,
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
            NSNS,
        >,
    ) -> Result<Self, sp_consensus::Error>
    where
        SE: SpawnEssentialNamed,
        SC: SelectChain<PBlock>,
        IBNS: Stream<Item = (NumberFor<PBlock>, ForkChoiceStrategy, mpsc::Sender<()>)>
            + Send
            + 'static,
        NSNS: Stream<Item = (Slot, Blake2b256Hash)> + Send + 'static,
    {
        let active_leaves =
            active_leaves(params.primary_chain_client.as_ref(), select_chain).await?;

        let bundle_producer = SystemBundleProducer::new(
            DomainId::SYSTEM,
            params.primary_chain_client.clone(),
            params.client.clone(),
            params.transaction_pool.clone(),
            params.bundle_sender,
            params.is_authority,
            params.keystore.clone(),
        );

        let fraud_proof_generator = FraudProofGenerator::new(
            params.client.clone(),
            params.spawner.clone(),
            params.backend.clone(),
            params.code_executor,
        );

        let domain_block_processor = DomainBlockProcessor::new(
            DomainId::SYSTEM,
            params.client.clone(),
            params.primary_chain_client.clone(),
            params.primary_network,
            params.backend.clone(),
            fraud_proof_generator.clone(),
        );

        let bundle_processor = SystemBundleProcessor::new(
            params.primary_chain_client.clone(),
            params.client.clone(),
            params.backend.clone(),
            params.is_authority,
            params.keystore,
            params.spawner.clone(),
            domain_block_processor,
        );

        spawn_essential.spawn_essential_blocking(
            "executor-worker",
            None,
            crate::system_domain_worker::start_worker(
                params.primary_chain_client.clone(),
                params.client.clone(),
                bundle_producer,
                bundle_processor.clone(),
                params.imported_block_notification_stream,
                params.new_slot_notification_stream,
                active_leaves,
                params.block_import_throttling_buffer_size,
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
        })
    }

    pub fn fraud_proof_generator(&self) -> FraudProofGenerator<Block, PBlock, Client, Backend, E> {
        self.fraud_proof_generator.clone()
    }

    /// Processes the bundles extracted from the primary block.
    // TODO: Remove this whole method, `self.bundle_processor` as a property and fix
    // `set_new_code_should_work` test to do an actual runtime upgrade
    #[doc(hidden)]
    pub async fn process_bundles(
        self,
        primary_info: (PBlock::Hash, NumberFor<PBlock>, ForkChoiceStrategy),
        bundles: Vec<OpaqueBundle<NumberFor<PBlock>, PBlock::Hash, Block::Hash>>,
        shuffling_seed: Randomness,
        maybe_new_runtime: Option<Cow<'static, [u8]>>,
    ) {
        if let Err(err) = self
            .bundle_processor
            .process_bundles(
                primary_info,
                DomainBundles::System(bundles, Vec::new()), // TODO: No core domain bundles in tests.
                shuffling_seed,
                maybe_new_runtime,
            )
            .await
        {
            tracing::error!(
                target: LOG_TARGET,
                ?primary_info,
                error = ?err,
                "Error at processing bundles.",
            );
        }
    }
}
