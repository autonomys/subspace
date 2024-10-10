use crate::bundle_processor::BundleProcessor;
use crate::domain_block_processor::{DomainBlockProcessor, ReceiptsChecker};
use crate::domain_bundle_producer::DomainBundleProducer;
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::fraud_proof::FraudProofGenerator;
use crate::snap_sync::SyncParams;
use crate::{DomainImportNotifications, NewSlotNotification, OperatorParams};
use futures::channel::mpsc;
use futures::{FutureExt, Stream};
use sc_client_api::{
    AuxStore, BlockBackend, BlockImportNotification, BlockchainEvents, Finalizer, ProofProvider,
};
use sc_consensus::BlockImport;
use sc_network::NetworkRequest;
use sc_utils::mpsc::tracing_unbounded;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed};
use sp_core::H256;
use sp_domains::core_api::DomainCoreApi;
use sp_domains::{BundleProducerElectionApi, DomainsApi};
use sp_domains_fraud_proof::FraudProofApi;
use sp_keystore::KeystorePtr;
use sp_messenger::MessengerApi;
use sp_mmr_primitives::MmrApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
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
    pub transaction_pool: Arc<TransactionPool>,
    backend: Arc<Backend>,
    fraud_proof_generator: FraudProofGenerator<Block, CBlock, Client, CClient, Backend, E>,
    bundle_processor: BundleProcessor<Block, CBlock, Client, CClient, Backend, E>,
    domain_block_processor: DomainBlockProcessor<Block, CBlock, Client, CClient, Backend>,
    pub keystore: KeystorePtr,
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
            keystore: self.keystore.clone(),
        }
    }
}

impl<Block, CBlock, Client, CClient, TransactionPool, Backend, E>
    Operator<Block, CBlock, Client, CClient, TransactionPool, Backend, E>
where
    Block: BlockT,
    Block::Hash: Into<H256>,
    CBlock: BlockT,
    NumberFor<CBlock>: From<NumberFor<Block>> + Into<NumberFor<Block>>,
    CBlock::Hash: From<Block::Hash>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + Finalizer<Block, Backend>
        + BlockImport<Block>
        + BlockchainEvents<Block>
        + 'static,
    for<'a> &'a Client: BlockImport<Block>,
    Client::Api: DomainCoreApi<Block>
        + MessengerApi<Block, NumberFor<CBlock>, CBlock::Hash>
        + sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block>
        + TaggedTransactionQueue<Block>,
    CClient: HeaderBackend<CBlock>
        + HeaderMetadata<CBlock, Error = sp_blockchain::Error>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + ProofProvider<CBlock>
        + BlockchainEvents<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api: DomainsApi<CBlock, Block::Header>
        + MessengerApi<CBlock, NumberFor<CBlock>, CBlock::Hash>
        + BundleProducerElectionApi<CBlock, Balance>
        + FraudProofApi<CBlock, Block::Header>
        + MmrApi<CBlock, H256, NumberFor<CBlock>>,
    Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
    TransactionPool:
        sc_transaction_pool_api::TransactionPool<Block = Block, Hash = Block::Hash> + 'static,
    E: CodeExecutor,
{
    /// Create a new instance.
    #[allow(clippy::type_complexity)]
    pub async fn new<IBNS, CIBNS, NSNS, ASS, NR, CNR, AS>(
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
            NR,
            CNR,
            AS,
        >,
    ) -> Result<Self, sp_consensus::Error>
    where
        IBNS: Stream<Item = (NumberFor<CBlock>, mpsc::Sender<()>)> + Send + 'static,
        CIBNS: Stream<Item = BlockImportNotification<CBlock>> + Send + 'static,
        NSNS: Stream<Item = NewSlotNotification> + Send + 'static,
        ASS: Stream<Item = mpsc::Sender<()>> + Send + 'static,
        NR: NetworkRequest + Send + Sync + 'static,
        CNR: NetworkRequest + Send + Sync + 'static,
        AS: AuxStore + Send + Sync + 'static,
    {
        let domain_bundle_proposer = DomainBundleProposer::<Block, _, CBlock, _, _>::new(
            params.domain_id,
            params.client.clone(),
            params.consensus_client.clone(),
            params.transaction_pool.clone(),
        );

        let bundle_producer = DomainBundleProducer::new(
            params.domain_id,
            params.consensus_client.clone(),
            params.client.clone(),
            domain_bundle_proposer,
            params.bundle_sender,
            params.keystore.clone(),
            params.skip_empty_bundle_production,
            params.skip_out_of_order_slot,
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
            consensus_network_sync_oracle: params.consensus_network_sync_oracle.clone(),
        };

        let receipts_checker = ReceiptsChecker {
            domain_id: params.domain_id,
            client: params.client.clone(),
            consensus_client: params.consensus_client.clone(),
            fraud_proof_generator: fraud_proof_generator.clone(),
            consensus_network_sync_oracle: params.consensus_network_sync_oracle,
            consensus_offchain_tx_pool_factory: params.consensus_offchain_tx_pool_factory.clone(),
        };

        let bundle_processor = BundleProcessor::new(
            params.domain_id,
            params.consensus_client.clone(),
            params.client.clone(),
            params.backend.clone(),
            receipts_checker,
            domain_block_processor.clone(),
        );

        let sync_params = params
            .consensus_chain_sync_params
            .map(|consensus_sync_params| SyncParams {
                domain_client: params.client.clone(),
                domain_network_service_handle: params.domain_network_service_handle,
                sync_service: params.sync_service,
                consensus_client: params.consensus_client.clone(),
                domain_block_downloader: params.block_downloader.clone(),
                consensus_chain_sync_params: consensus_sync_params,
                domain_fork_id: params.domain_fork_id,
            });

        spawn_essential.spawn_essential_blocking(
            "domain-operator-worker",
            None,
            crate::domain_worker::start_worker(
                spawn_essential.clone(),
                params.consensus_client.clone(),
                params.consensus_offchain_tx_pool_factory.clone(),
                params.maybe_operator_id,
                bundle_producer,
                bundle_processor.clone(),
                params.operator_streams,
                sync_params,
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
            keystore: params.keystore,
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
