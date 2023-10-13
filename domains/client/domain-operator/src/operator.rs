use crate::bundle_processor::BundleProcessor;
use crate::domain_block_processor::{DomainBlockProcessor, ReceiptsChecker};
use crate::domain_bundle_producer::DomainBundleProducer;
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::fraud_proof::FraudProofGenerator;
use crate::parent_chain::DomainParentChain;
use crate::{DomainImportNotifications, NewSlotNotification, OperatorParams};
use domain_runtime_primitives::DomainCoreApi;
use futures::channel::mpsc;
use futures::{FutureExt, Stream};
use sc_client_api::{
    AuxStore, BlockBackend, BlockImportNotification, BlockchainEvents, Finalizer, ProofProvider,
};
use sc_utils::mpsc::tracing_unbounded;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed};
use sp_core::H256;
use sp_domains::{BundleProducerElectionApi, DomainsApi};
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;
use subspace_runtime_primitives::Balance;

/// Domain operator.
pub struct Operator<Block, CBlock, Client, CClient, TransactionPool, Backend, E>
where
    Block: BlockT,
    CBlock: BlockT,
{
    consensus_client: Arc<CClient>,
    client: Arc<Client>,
    transaction_pool: Arc<TransactionPool>,
    backend: Arc<Backend>,
    fraud_proof_generator: FraudProofGenerator<Block, CBlock, Client, CClient, Backend, E>,
    bundle_processor: BundleProcessor<Block, CBlock, Client, CClient, Backend, E>,
    domain_block_processor: DomainBlockProcessor<Block, CBlock, Client, CClient, Backend>,
}

impl<Block, CBlock, Client, CClient, TransactionPool, Backend, E> Clone
    for Operator<Block, CBlock, Client, CClient, TransactionPool, Backend, E>
where
    Block: BlockT,
    CBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            consensus_client: self.consensus_client.clone(),
            client: self.client.clone(),
            transaction_pool: self.transaction_pool.clone(),
            backend: self.backend.clone(),
            fraud_proof_generator: self.fraud_proof_generator.clone(),
            bundle_processor: self.bundle_processor.clone(),
            domain_block_processor: self.domain_block_processor.clone(),
        }
    }
}

impl<Block, CBlock, Client, CClient, TransactionPool, Backend, E>
    Operator<Block, CBlock, Client, CClient, TransactionPool, Backend, E>
where
    Block: BlockT,
    CBlock: BlockT,
    NumberFor<CBlock>: From<NumberFor<Block>> + Into<NumberFor<Block>>,
    CBlock::Hash: From<Block::Hash>,
    Block::Hash: Into<H256>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + Finalizer<Block, Backend>
        + 'static,
    Client::Api: DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<Block>>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block>,
    CClient: HeaderBackend<CBlock>
        + HeaderMetadata<CBlock, Error = sp_blockchain::Error>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + ProofProvider<CBlock>
        + BlockchainEvents<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api: DomainsApi<CBlock, NumberFor<Block>, Block::Hash>
        + MessengerApi<CBlock, NumberFor<CBlock>>
        + BundleProducerElectionApi<CBlock, Balance>,
    Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
    TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block> + 'static,
    E: CodeExecutor,
{
    /// Create a new instance.
    pub async fn new<IBNS, CIBNS, NSNS, ASS>(
        spawn_essential: Box<dyn SpawnEssentialNamed>,
        params: OperatorParams<
            Block,
            CBlock,
            Client,
            CClient,
            TransactionPool,
            Backend,
            E,
            IBNS,
            CIBNS,
            NSNS,
            ASS,
        >,
    ) -> Result<Self, sp_consensus::Error>
    where
        IBNS: Stream<Item = (NumberFor<CBlock>, mpsc::Sender<()>)> + Send + 'static,
        CIBNS: Stream<Item = BlockImportNotification<CBlock>> + Send + 'static,
        NSNS: Stream<Item = NewSlotNotification> + Send + 'static,
        ASS: Stream<Item = mpsc::Sender<()>> + Send + 'static,
    {
        let parent_chain =
            DomainParentChain::new(params.domain_id, params.consensus_client.clone());

        let domain_bundle_proposer = DomainBundleProposer::new(
            params.client.clone(),
            params.consensus_client.clone(),
            params.transaction_pool.clone(),
        );

        let bundle_producer = DomainBundleProducer::new(
            params.domain_id,
            params.consensus_client.clone(),
            params.client.clone(),
            parent_chain.clone(),
            domain_bundle_proposer,
            params.bundle_sender,
            params.keystore.clone(),
        );

        let fraud_proof_generator = FraudProofGenerator::new(
            params.client.clone(),
            params.consensus_client.clone(),
            params.backend.clone(),
            params.code_executor,
        );

        let domain_block_processor = DomainBlockProcessor {
            domain_id: params.domain_id,
            domain_created_at: params.domain_created_at,
            client: params.client.clone(),
            consensus_client: params.consensus_client.clone(),
            backend: params.backend.clone(),
            domain_confirmation_depth: params.domain_confirmation_depth,
            block_import: params.block_import,
            import_notification_sinks: Default::default(),
        };

        let receipts_checker = ReceiptsChecker {
            domain_id: params.domain_id,
            client: params.client.clone(),
            consensus_client: params.consensus_client.clone(),
            fraud_proof_generator: fraud_proof_generator.clone(),
            parent_chain,
            consensus_network_sync_oracle: params.consensus_network_sync_oracle,
            _phantom: std::marker::PhantomData,
        };

        let bundle_processor = BundleProcessor::new(
            params.domain_id,
            params.consensus_client.clone(),
            params.client.clone(),
            params.backend.clone(),
            params.keystore,
            receipts_checker,
            domain_block_processor.clone(),
        );

        spawn_essential.spawn_essential_blocking(
            "domain-operator-worker",
            None,
            crate::domain_worker_starter::start_worker(
                spawn_essential.clone(),
                params.consensus_client.clone(),
                params.consensus_offchain_tx_pool_factory.clone(),
                params.is_authority,
                bundle_producer,
                bundle_processor.clone(),
                params.operator_streams,
            )
            .boxed(),
        );

        Ok(Self {
            consensus_client: params.consensus_client,
            client: params.client,
            transaction_pool: params.transaction_pool,
            backend: params.backend,
            fraud_proof_generator,
            bundle_processor,
            domain_block_processor,
        })
    }

    pub fn fraud_proof_generator(
        &self,
    ) -> FraudProofGenerator<Block, CBlock, Client, CClient, Backend, E> {
        self.fraud_proof_generator.clone()
    }

    /// Get system domain block import notification stream.
    ///
    /// NOTE: Unlike `BlockchainEvents::import_notification_stream()`, this notification won't be
    /// fired until the system domain block's receipt processing is done.
    pub fn import_notification_stream(&self) -> DomainImportNotifications<Block, CBlock> {
        let (sink, stream) = tracing_unbounded("mpsc_domain_import_notification_stream", 100);
        self.domain_block_processor
            .import_notification_sinks
            .lock()
            .push(sink);
        stream
    }

    /// Processes the bundles extracted from the consensus block.
    // TODO: Remove this whole method, `self.bundle_processor` as a property and fix
    // `set_new_code_should_work` test to do an actual runtime upgrade
    #[doc(hidden)]
    pub async fn process_bundles(
        self,
        consensus_block_info: (CBlock::Hash, NumberFor<CBlock>, bool),
    ) {
        if let Err(err) = self
            .bundle_processor
            .process_bundles(consensus_block_info)
            .await
        {
            tracing::error!(?consensus_block_info, ?err, "Error at processing bundles.");
        }
    }
}
