use crate::core_bundle_processor::CoreBundleProcessor;
use crate::domain_block_processor::{DomainBlockProcessor, ReceiptsChecker};
use crate::domain_bundle_producer::DomainBundleProducer;
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::fraud_proof::FraudProofGenerator;
use crate::parent_chain::CoreDomainParentChain;
use crate::{active_leaves, DomainImportNotifications, EssentialExecutorParams, TransactionFor};
use domain_runtime_primitives::{DomainCoreApi, InherentExtrinsicApi};
use futures::channel::mpsc;
use futures::{FutureExt, Stream, StreamExt};
use sc_client_api::{
    AuxStore, BlockBackend, BlockImportNotification, BlockchainEvents, Finalizer, ProofProvider,
    StateBackendFor,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::SelectChain;
use sp_consensus_slots::Slot;
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed};
use sp_domains::{DomainId, ExecutorApi};
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, HashFor, NumberFor};
use sp_settlement::SettlementApi;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use system_runtime_primitives::SystemDomainApi;

/// Core domain executor.
pub struct Executor<
    Block,
    SBlock,
    PBlock,
    Client,
    SClient,
    PClient,
    TransactionPool,
    Backend,
    E,
    BI,
> {
    primary_chain_client: Arc<PClient>,
    client: Arc<Client>,
    transaction_pool: Arc<TransactionPool>,
    backend: Arc<Backend>,
    fraud_proof_generator: FraudProofGenerator<Block, PBlock, Client, PClient, Backend, E>,
    _phantom_data: PhantomData<(SBlock, SClient, BI)>,
}

impl<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E, BI> Clone
    for Executor<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E, BI>
{
    fn clone(&self) -> Self {
        Self {
            primary_chain_client: self.primary_chain_client.clone(),
            client: self.client.clone(),
            transaction_pool: self.transaction_pool.clone(),
            backend: self.backend.clone(),
            fraud_proof_generator: self.fraud_proof_generator.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E, BI>
    Executor<Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E, BI>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    SBlock::Hash: From<Block::Hash>,
    NumberFor<Block>: From<NumberFor<PBlock>> + Into<NumberFor<PBlock>>,
    NumberFor<SBlock>: From<NumberFor<Block>> + Into<NumberFor<Block>>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + Finalizer<Block, Backend>
        + 'static,
    Client::Api: DomainCoreApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + MessengerApi<Block, NumberFor<Block>>
        + InherentExtrinsicApi<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    for<'b> &'b BI: sc_consensus::BlockImport<
        Block,
        Transaction = sp_api::TransactionFor<Client, Block>,
        Error = sp_consensus::Error,
    >,
    BI: Sync + Send + 'static,
    SClient: HeaderBackend<SBlock>
        + BlockBackend<SBlock>
        + ProvideRuntimeApi<SBlock>
        + ProofProvider<SBlock>
        + 'static,
    SClient::Api: DomainCoreApi<SBlock>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash, Block::Hash>
        + MessengerApi<SBlock, NumberFor<SBlock>>
        + SettlementApi<SBlock, Block::Hash>,
    PClient: HeaderBackend<PBlock>
        + HeaderMetadata<PBlock, Error = sp_blockchain::Error>
        + BlockBackend<PBlock>
        + ProvideRuntimeApi<PBlock>
        + BlockchainEvents<PBlock>
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
    pub async fn new<SC, IBNS, CIBNS, NSNS>(
        domain_id: DomainId,
        system_domain_client: Arc<SClient>,
        mut system_domain_block_import_notifications: DomainImportNotifications<SBlock, PBlock>,
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
            BI,
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

        let parent_chain = CoreDomainParentChain::new(domain_id, system_domain_client.clone());

        let domain_bundle_proposer = DomainBundleProposer::new(
            params.client.clone(),
            params.primary_chain_client.clone(),
            params.transaction_pool.clone(),
        );

        let bundle_producer = DomainBundleProducer::new(
            domain_id,
            system_domain_client.clone(),
            params.client.clone(),
            parent_chain.clone(),
            domain_bundle_proposer,
            params.bundle_sender,
            params.keystore.clone(),
        );

        let fraud_proof_generator = FraudProofGenerator::new(
            params.client.clone(),
            params.primary_chain_client.clone(),
            params.backend.clone(),
            params.code_executor,
        );

        let domain_block_processor = DomainBlockProcessor {
            domain_id,
            client: params.client.clone(),
            primary_chain_client: params.primary_chain_client.clone(),
            backend: params.backend.clone(),
            domain_confirmation_depth: params.domain_confirmation_depth,
            block_import: params.block_import,
            import_notification_sinks: Default::default(),
        };

        let core_domain_receipts_checker = ReceiptsChecker {
            domain_id,
            client: params.client.clone(),
            primary_chain_client: params.primary_chain_client.clone(),
            fraud_proof_generator: fraud_proof_generator.clone(),
            parent_chain,
            primary_network_sync_oracle: params.primary_network_sync_oracle,
            _phantom: std::marker::PhantomData,
        };

        let bundle_processor = CoreBundleProcessor::new(
            domain_id,
            params.primary_chain_client.clone(),
            system_domain_client.clone(),
            params.client.clone(),
            params.backend.clone(),
            params.keystore,
            domain_block_processor,
        );

        spawn_essential.spawn_essential_blocking(
            "core-executor-worker",
            None,
            crate::core_domain_worker::start_worker(
                spawn_essential.clone(),
                params.primary_chain_client.clone(),
                params.client.clone(),
                params.is_authority,
                bundle_producer,
                bundle_processor,
                params.executor_streams,
                active_leaves,
            )
            .boxed(),
        );

        spawn_essential.spawn_essential_blocking(
            "core-domain-receipts-checker",
            None,
            async move {
                while let Some(system_domain_block_import) =
                    system_domain_block_import_notifications.next().await
                {
                    tracing::debug!(
                        ?system_domain_block_import,
                        "Checking core domain state transition"
                    );

                    if let Err(err) = core_domain_receipts_checker
                        .check_state_transition(system_domain_block_import.domain_block_hash)
                    {
                        tracing::error!(
                            ?err,
                            "Error occurred at checking core domain state transition"
                        );
                        return;
                    }
                }
            }
            .boxed(),
        );

        Ok(Self {
            primary_chain_client: params.primary_chain_client,
            client: params.client,
            transaction_pool: params.transaction_pool,
            backend: params.backend,
            fraud_proof_generator,
            _phantom_data: PhantomData,
        })
    }

    pub fn fraud_proof_generator(
        &self,
    ) -> FraudProofGenerator<Block, PBlock, Client, PClient, Backend, E> {
        self.fraud_proof_generator.clone()
    }
}
