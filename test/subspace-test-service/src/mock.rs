use crate::node_config;
use sc_executor::NativeElseWasmExecutor;
use sc_service::{BasePath, TaskManager};
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use sp_consensus::{NoNetwork, SyncOracle};
use sp_consensus_slots::Slot;
use sp_keyring::Sr25519Keyring;
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
            proof_verifier,
            bundle_validator,
        );

        MockPrimaryNode {
            task_manager,
            client,
            backend,
            executor,
            transaction_pool,
            select_chain,
            next_slot: 1,
            new_slot_notification_subscribers: Vec::new(),
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
}
