use crate::node_config;
use futures::channel::mpsc;
use futures::StreamExt;
use sc_consensus::block_import::{
    BlockCheckParams, BlockImportParams, ForkChoiceStrategy, ImportResult,
};
use sc_consensus::{BlockImport, BoxBlockImport};
use sc_executor::NativeElseWasmExecutor;
use sc_service::{BasePath, TaskManager};
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use sp_api::{ApiExt, HeaderT, NumberFor, ProvideRuntimeApi, TransactionFor};
use sp_blockchain::HeaderBackend;
use sp_consensus::{CacheKeyId, Error as ConsensusError, NoNetwork, SyncOracle};
use sp_consensus_slots::Slot;
use sp_keyring::Sr25519Keyring;
use sp_runtime::traits::Block as BlockT;
use std::collections::HashMap;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use subspace_runtime_primitives::opaque::Block;
use subspace_runtime_primitives::Hash;
use subspace_service::FullSelectChain;
use subspace_test_client::{Backend, Client, FraudProofVerifier, TestExecutorDispatch};
use subspace_test_runtime::RuntimeApi;
use subspace_transaction_pool::bundle_validator::BundleValidator;
use subspace_transaction_pool::FullPool;

/// A mock Subspace primary node instance used for testing.
pub struct MockPrimaryNode {
    /// `TaskManager`'s instance.
    pub task_manager: TaskManager,
    /// Client's instance.
    pub client: Arc<Client>,
    /// Backend.
    pub backend: Arc<Backend>,
    /// Code executor.
    pub executor: NativeElseWasmExecutor<TestExecutorDispatch>,
    /// Transaction pool.
    pub transaction_pool:
        Arc<FullPool<Block, Client, FraudProofVerifier, BundleValidator<Block, Client>>>,
    /// The SelectChain Strategy
    pub select_chain: FullSelectChain,
    /// The next slot number
    next_slot: u64,
    /// The slot notification subscribers
    new_slot_notification_subscribers: Vec<TracingUnboundedSender<(Slot, Blake2b256Hash)>>,
    /// Block import pipeline
    block_import:
        MockBlockImport<BoxBlockImport<Block, TransactionFor<Client, Block>>, Client, Block>,
}

impl MockPrimaryNode {
    /// Run a mock primary node
    pub fn run_mock_primary_node(
        tokio_handle: tokio::runtime::Handle,
        key: Sr25519Keyring,
        base_path: BasePath,
    ) -> MockPrimaryNode {
        let config = node_config(tokio_handle, key, vec![], false, false, false, base_path);

        let executor = NativeElseWasmExecutor::<TestExecutorDispatch>::new(
            config.wasm_method,
            config.default_heap_pages,
            config.max_runtime_instances,
            config.runtime_cache_size,
        );

        let (client, backend, _, task_manager) =
            sc_service::new_full_parts::<Block, RuntimeApi, _>(&config, None, executor.clone())
                .expect("Fail to new full parts");

        let client = Arc::new(client);

        let select_chain = sc_consensus::LongestChain::new(backend.clone());

        let bundle_validator = BundleValidator::new(client.clone());

        let proof_verifier = subspace_fraud_proof::ProofVerifier::new(
            client.clone(),
            executor.clone(),
            task_manager.spawn_handle(),
            subspace_fraud_proof::PrePostStateRootVerifier::new(client.clone()),
        );
        let transaction_pool = subspace_transaction_pool::new_full(
            &config,
            &task_manager,
            client.clone(),
            proof_verifier.clone(),
            bundle_validator,
        );

        let fraud_proof_block_import =
            sc_consensus_fraud_proof::block_import(client.clone(), client.clone(), proof_verifier);

        let block_import = MockBlockImport::<
            BoxBlockImport<Block, TransactionFor<Client, Block>>,
            _,
            _,
        >::new(Box::new(fraud_proof_block_import), client.clone());

        MockPrimaryNode {
            task_manager,
            client,
            backend,
            executor,
            transaction_pool,
            select_chain,
            next_slot: 1,
            new_slot_notification_subscribers: Vec::new(),
            block_import,
        }
    }

    /// Sync oracle for `MockPrimaryNode`
    pub fn sync_oracle() -> Arc<dyn SyncOracle + Send + Sync> {
        Arc::new(NoNetwork)
    }

    /// Return the next slot number
    pub fn next_slot(&self) -> u64 {
        self.next_slot
    }

    /// Produce slot
    pub fn produce_slot(&mut self) -> Slot {
        let slot = Slot::from(self.next_slot);
        self.next_slot += 1;

        let value = (slot, Hash::random().into());
        self.new_slot_notification_subscribers
            .retain(|subscriber| subscriber.unbounded_send(value).is_ok());

        slot
    }

    /// Subscribe the new slot notification
    pub fn new_slot_notification_stream(
        &mut self,
    ) -> TracingUnboundedReceiver<(Slot, Blake2b256Hash)> {
        let (tx, rx) = tracing_unbounded("subspace_new_slot_notification_stream", 100);
        self.new_slot_notification_subscribers.push(tx);
        rx
    }

    /// Subscribe the block import notification
    pub fn imported_block_notification_stream(
        &mut self,
    ) -> TracingUnboundedReceiver<(NumberFor<Block>, mpsc::Sender<()>)> {
        let (tx, rx) = tracing_unbounded("subspace_new_slot_notification_stream", 100);
        self.block_import
            .imported_block_notification_subscribers
            .push(tx);
        rx
    }
}

// `MockBlockImport` is mostly port from `sc-consensus-subspace::SubspaceBlockImport` with all
// the consensus related logic removed.
struct MockBlockImport<Inner, Client, Block: BlockT> {
    inner: Inner,
    client: Arc<Client>,
    imported_block_notification_subscribers:
        Vec<TracingUnboundedSender<(NumberFor<Block>, mpsc::Sender<()>)>>,
}

impl<Inner, Client, Block: BlockT> MockBlockImport<Inner, Client, Block> {
    fn new(inner: Inner, client: Arc<Client>) -> Self {
        MockBlockImport {
            inner,
            client,
            imported_block_notification_subscribers: Vec::new(),
        }
    }
}

#[async_trait::async_trait]
impl<Inner, Client, Block> BlockImport<Block> for MockBlockImport<Inner, Client, Block>
where
    Block: BlockT,
    Inner: BlockImport<Block, Transaction = TransactionFor<Client, Block>, Error = ConsensusError>
        + Send
        + Sync,
    Inner::Error: Into<ConsensusError>,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    Client::Api: ApiExt<Block>,
{
    type Error = ConsensusError;
    type Transaction = TransactionFor<Client, Block>;

    async fn import_block(
        &mut self,
        mut block: BlockImportParams<Block, Self::Transaction>,
        new_cache: HashMap<CacheKeyId, Vec<u8>>,
    ) -> Result<ImportResult, Self::Error> {
        let block_number = *block.header.number();
        let current_best_number = self.client.info().best_number;
        block.fork_choice = Some(ForkChoiceStrategy::Custom(
            block_number > current_best_number,
        ));

        let import_result = self.inner.import_block(block, new_cache).await?;
        let (block_import_acknowledgement_sender, mut block_import_acknowledgement_receiver) =
            mpsc::channel(0);

        // Must drop `block_import_acknowledgement_sender` after the notification otherwise the receiver
        // will block forever as there is still a sender not closed.
        {
            let value = (block_number, block_import_acknowledgement_sender);
            self.imported_block_notification_subscribers
                .retain(|subscriber| subscriber.unbounded_send(value.clone()).is_ok());
        }

        while (block_import_acknowledgement_receiver.next().await).is_some() {
            // Wait for all the acknowledgements to progress.
        }

        Ok(import_result)
    }

    async fn check_block(
        &mut self,
        block: BlockCheckParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        self.inner.check_block(block).await.map_err(Into::into)
    }
}
