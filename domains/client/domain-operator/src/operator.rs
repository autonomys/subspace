use crate::bundle_processor::BundleProcessor;
use crate::domain_block_processor::{DomainBlockProcessor, ReceiptsChecker};
use crate::domain_bundle_producer::{
    uses_default_bundle_producer_params, BundleProducer, DomainBundleProducer, TestBundleProducer,
};
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::fraud_proof::FraudProofGenerator;
use crate::snap_sync::{snap_sync, SyncParams, LOG_TARGET};
use crate::{NewSlotNotification, OperatorParams};
use futures::channel::mpsc;
use futures::future::pending;
use futures::{FutureExt, SinkExt, Stream, StreamExt};
use sc_client_api::{
    AuxStore, BlockBackend, BlockImportNotification, BlockchainEvents, ExecutorProvider, Finalizer,
    ProofProvider,
};
use sc_consensus::BlockImport;
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
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::sync::Arc;
use subspace_runtime_primitives::Balance;
use tracing::{error, info, trace, warn};

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
    domain_block_processor: DomainBlockProcessor<Block, CBlock, Client, CClient, Backend, E>,
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
        + ExecutorProvider<Block>
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
    pub async fn new<IBNS, CIBNS, NSNS, ASS>(
        spawn_essential: Box<dyn SpawnEssentialNamed>,
        mut params: OperatorParams<
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
        IBNS: Stream<Item = (NumberFor<CBlock>, mpsc::Sender<()>)> + Send + Unpin + 'static,
        CIBNS: Stream<Item = BlockImportNotification<CBlock>> + Send + Unpin + 'static,
        NSNS: Stream<Item = NewSlotNotification> + Send + 'static,
        ASS: Stream<Item = mpsc::Sender<()>> + Send + 'static,
    {
        let domain_bundle_proposer = DomainBundleProposer::<Block, _, CBlock, _, _>::new(
            params.domain_id,
            params.client.clone(),
            params.consensus_client.clone(),
            params.transaction_pool.clone(),
        );

        let bundle_producer = if uses_default_bundle_producer_params(
            params.skip_empty_bundle_production,
            params.skip_out_of_order_slot,
        ) {
            Box::new(DomainBundleProducer::new(
                params.domain_id,
                params.consensus_client.clone(),
                params.client.clone(),
                domain_bundle_proposer,
                params.bundle_sender,
                params.keystore.clone(),
            )) as Box<dyn BundleProducer<Block, CBlock> + Send>
        } else {
            // TODO: only allow the test bundle producer in tests (ticket #3162)
            warn!("Using test bundle producer...");
            Box::new(TestBundleProducer::new(
                params.domain_id,
                params.consensus_client.clone(),
                params.client.clone(),
                domain_bundle_proposer,
                params.bundle_sender,
                params.keystore.clone(),
                params.skip_empty_bundle_production,
                params.skip_out_of_order_slot,
            )) as Box<dyn BundleProducer<Block, CBlock> + Send>
        };

        let fraud_proof_generator = FraudProofGenerator::new(
            params.client.clone(),
            params.consensus_client.clone(),
            params.backend.clone(),
            params.code_executor.clone(),
        );

        let domain_block_processor = DomainBlockProcessor {
            domain_id: params.domain_id,
            domain_created_at: params.domain_created_at,
            client: params.client.clone(),
            consensus_client: params.consensus_client.clone(),
            backend: params.backend.clone(),
            block_import: params.block_import,
            import_notification_sinks: Default::default(),
            domain_sync_oracle: params.domain_sync_oracle.clone(),
            domain_executor: params.code_executor.clone(),
            challenge_period: params.challenge_period,
        };

        let receipts_checker = ReceiptsChecker {
            domain_id: params.domain_id,
            client: params.client.clone(),
            consensus_client: params.consensus_client.clone(),
            fraud_proof_generator: fraud_proof_generator.clone(),
            domain_sync_oracle: params.domain_sync_oracle,
            consensus_offchain_tx_pool_factory: params.consensus_offchain_tx_pool_factory.clone(),
        };

        let bundle_processor = BundleProcessor::new(
            params.domain_id,
            params.consensus_client.clone(),
            params.client.clone(),
            params.backend.clone(),
            receipts_checker,
            domain_block_processor.clone(),
            params.consensus_confirmation_depth_k,
        );

        let target_block_number = params
            .consensus_chain_sync_params
            .as_ref()
            .map(|p| p.last_domain_block_er.consensus_block_number);

        let sync_params = params
            .consensus_chain_sync_params
            .map(|consensus_sync_params| SyncParams {
                domain_client: params.client.clone(),
                domain_network_service_handle: params.domain_network_service_handle,
                sync_service: params.sync_service,
                domain_block_downloader: params.block_downloader.clone(),
                consensus_chain_sync_params: consensus_sync_params,
                domain_fork_id: params.domain_fork_id,
                challenge_period: params.challenge_period,
            });

        if let Some(sync_params) = sync_params {
            let domain_sync_task = {
                async move {
                    let info = sync_params.domain_client.info();
                    // Only attempt snap sync with genesis state
                    // TODO: Support snap sync from any state once
                    //  https://github.com/paritytech/polkadot-sdk/issues/5366 is resolved
                    if info.best_hash == info.genesis_hash {
                        info!(target: LOG_TARGET, "Starting domain snap sync...");

                        let result = snap_sync(sync_params).await;

                        match result {
                            Ok(_) => {
                                info!(target: LOG_TARGET, "Domain snap sync completed.");
                            }
                            Err(err) => {
                                error!(target: LOG_TARGET, %err, "Domain snap sync failed.");
                                info!(target: LOG_TARGET, "Wipe the DB and restart the application with --sync=full.");

                                // essential task failed
                                return;
                            }
                        };
                    } else {
                        error!(target: LOG_TARGET, "Snap sync can only work with genesis state.");
                        info!(target: LOG_TARGET, "Wipe the DB and restart the application with --sync=full.");

                        // essential task failed
                        return;
                    }

                    // Don't exit essential task.
                    pending().await
                }
            };

            spawn_essential.spawn_essential("domain-sync", None, Box::pin(domain_sync_task));
        }

        let start_worker_task = {
            let consensus_client = params.consensus_client.clone();
            let spawn_essential = spawn_essential.clone();
            let bundle_processor = bundle_processor.clone();
            async move {
                // Wait for the target block to import if we are snap syncing
                if let Some(target_block_number) = target_block_number {
                    // Wait for Subspace block importing notifications
                    let block_importing_notification_stream =
                        &mut params.operator_streams.block_importing_notification_stream;

                    while let Some((block_number, mut acknowledgement_sender)) =
                        block_importing_notification_stream.next().await
                    {
                        trace!(%block_number, "Acknowledged block import from consensus chain.");
                        if acknowledgement_sender.send(()).await.is_err() {
                            error!("Can't acknowledge block import #{}", block_number);
                            return Err(());
                        }

                        if block_number >= target_block_number {
                            break;
                        }
                    }

                    // Drain Substrate block imported notifications
                    let imported_block_notification_stream =
                        &mut params.operator_streams.imported_block_notification_stream;

                    while let Some(import_notification) =
                        imported_block_notification_stream.next().await
                    {
                        let block_number = *import_notification.header.number();
                        trace!(%block_number, "Block imported from consensus chain.");

                        if block_number >= target_block_number {
                            break;
                        }
                    }
                }

                crate::domain_worker::start_worker(
                    spawn_essential.clone(),
                    consensus_client,
                    params.consensus_offchain_tx_pool_factory.clone(),
                    params.maybe_operator_id,
                    bundle_producer,
                    bundle_processor.clone(),
                    params.operator_streams,
                )
                .await;

                Ok(())
            }
        };

        spawn_essential.spawn_essential_blocking(
            "domain-operator-worker",
            None,
            Box::pin(start_worker_task.map(|_| ())),
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
