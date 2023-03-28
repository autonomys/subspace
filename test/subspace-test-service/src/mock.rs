use crate::node_config;
use futures::channel::mpsc;
use futures::{select, FutureExt, StreamExt};
use sc_block_builder::BlockBuilderProvider;
use sc_client_api::backend;
use sc_consensus::block_import::{
    BlockCheckParams, BlockImportParams, ForkChoiceStrategy, ImportResult,
};
use sc_consensus::{BlockImport, BoxBlockImport, StateAction};
use sc_executor::NativeElseWasmExecutor;
use sc_service::{BasePath, InPoolTransaction, TaskManager, TransactionPool};
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use sp_api::{ApiExt, HashT, HeaderT, ProvideRuntimeApi, TransactionFor};
use sp_application_crypto::UncheckedFrom;
use sp_blockchain::HeaderBackend;
use sp_consensus::{BlockOrigin, CacheKeyId, Error as ConsensusError, NoNetwork, SyncOracle};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{CompatibleDigestItem, PreDigest};
use sp_consensus_subspace::FarmerPublicKey;
use sp_inherents::{InherentData, InherentDataProvider};
use sp_keyring::Sr25519Keyring;
use sp_runtime::generic::Digest;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, NumberFor};
use sp_runtime::DigestItem;
use sp_timestamp::Timestamp;
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::time;
use subspace_core_primitives::{Blake2b256Hash, Solution};
use subspace_runtime_primitives::opaque::Block;
use subspace_runtime_primitives::{AccountId, Hash};
use subspace_service::FullSelectChain;
use subspace_solving::create_chunk_signature;
use subspace_test_client::{Backend, Client, FraudProofVerifier, TestExecutorDispatch};
use subspace_test_runtime::{RuntimeApi, SLOT_DURATION};
use subspace_transaction_pool::bundle_validator::BundleValidator;
use subspace_transaction_pool::FullPool;

type StorageChanges = sp_api::StorageChanges<backend::StateBackendFor<Backend, Block>, Block>;

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
    #[allow(clippy::type_complexity)]
    new_slot_notification_subscribers:
        Vec<TracingUnboundedSender<(Slot, Blake2b256Hash, Option<mpsc::Sender<()>>)>>,
    /// Block import pipeline
    block_import:
        MockBlockImport<BoxBlockImport<Block, TransactionFor<Client, Block>>, Client, Block>,
    /// Mock subspace solution used to mock the subspace `PreDigest`
    mock_solution: Solution<FarmerPublicKey, AccountId>,
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

        let mock_solution = {
            let mut gs = Solution::genesis_solution(
                FarmerPublicKey::unchecked_from(key.public().0),
                key.to_account_id(),
            );
            gs.chunk_signature = create_chunk_signature(&key.pair().into(), &gs.chunk.to_bytes());
            gs
        };

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
            mock_solution,
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

        let value = (slot, Hash::random().into(), None);
        self.new_slot_notification_subscribers
            .retain(|subscriber| subscriber.unbounded_send(value).is_ok());

        slot
    }

    /// Subscribe the new slot notification
    pub fn new_slot_notification_stream(
        &mut self,
    ) -> TracingUnboundedReceiver<(Slot, Blake2b256Hash, Option<mpsc::Sender<()>>)> {
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

impl MockPrimaryNode {
    async fn collect_txn_from_pool(
        &self,
        parent_number: NumberFor<Block>,
    ) -> Vec<<Block as BlockT>::Extrinsic> {
        let mut t1 = self.transaction_pool.ready_at(parent_number).fuse();
        let mut t2 = futures_timer::Delay::new(time::Duration::from_micros(100)).fuse();
        let pending_iterator = select! {
            res = t1 => res,
            _ = t2 => {
                tracing::warn!(
                    "Timeout fired waiting for transaction pool at #{}, proceeding with production.",
                    parent_number,
                );
                self.transaction_pool.ready()
            }
        };
        let pushing_duration = time::Duration::from_micros(500);
        let start = time::Instant::now();
        let mut extrinsics = Vec::new();
        for pending_tx in pending_iterator {
            if start.elapsed() >= pushing_duration {
                break;
            }
            let pending_tx_data = pending_tx.data().clone();
            extrinsics.push(pending_tx_data);
        }
        extrinsics
    }

    async fn mock_inherent_data(slot: Slot) -> Result<InherentData, Box<dyn Error>> {
        let timestamp = sp_timestamp::InherentDataProvider::new(Timestamp::new(
            <Slot as Into<u64>>::into(slot) * SLOT_DURATION,
        ));
        let subspace_inherents =
            sp_consensus_subspace::inherents::InherentDataProvider::new(slot, vec![]);

        let inherent_data = (subspace_inherents, timestamp)
            .create_inherent_data()
            .await?;

        Ok(inherent_data)
    }

    fn mock_subspace_digest(&self, slot: Slot) -> Digest {
        let pre_digest: PreDigest<FarmerPublicKey, AccountId> = PreDigest {
            slot,
            solution: self.mock_solution.clone(),
        };
        let mut digest = Digest::default();
        digest.push(DigestItem::subspace_pre_digest(&pre_digest));
        digest
    }

    /// Build block
    async fn build_block(
        &self,
        slot: Slot,
        parent_hash: <Block as BlockT>::Hash,
        extrinsics: Vec<<Block as BlockT>::Extrinsic>,
    ) -> Result<(Block, StorageChanges), Box<dyn Error>> {
        let digest = self.mock_subspace_digest(slot);
        let inherent_data = Self::mock_inherent_data(slot).await?;

        let mut block_builder = self.client.new_block_at(parent_hash, digest, false)?;

        let inherent_txns = block_builder.create_inherents(inherent_data)?;

        for tx in inherent_txns.into_iter().chain(extrinsics) {
            sc_block_builder::BlockBuilder::push(&mut block_builder, tx)?;
        }

        let (block, storage_changes, _) = block_builder.build()?.into_inner();
        Ok((block, storage_changes))
    }

    /// Import block
    async fn import_block(
        &mut self,
        block: Block,
        storage_changes: Option<StorageChanges>,
    ) -> Result<(), Box<dyn Error>> {
        let (header, body) = block.deconstruct();
        let block_import_params = {
            let mut import_block = BlockImportParams::new(BlockOrigin::Own, header);
            import_block.body = Some(body);
            import_block.state_action = match storage_changes {
                Some(changes) => {
                    StateAction::ApplyChanges(sc_consensus::StorageChanges::Changes(changes))
                }
                None => StateAction::Execute,
            };
            import_block
        };

        let import_result = self
            .block_import
            .import_block(block_import_params, Default::default())
            .await?;

        match import_result {
            ImportResult::Imported(_) | ImportResult::AlreadyInChain => Ok(()),
            bad_res => Err(format!("Fail to import block due to {bad_res:?}").into()),
        }
    }

    /// Produce block based on the current best block and the extrinsics in pool
    pub async fn produce_block(&mut self) -> Result<(), Box<dyn Error>> {
        let block_timer = time::Instant::now();

        let slot = self.produce_slot();

        let parent_hash = self.client.info().best_hash;
        let parent_number = self.client.info().best_number;

        let extrinsics = self.collect_txn_from_pool(parent_number).await;

        let (block, storage_changes) = self.build_block(slot, parent_hash, extrinsics).await?;

        tracing::info!(
			"🎁 Prepared block for proposing at {} ({} ms) [hash: {:?}; parent_hash: {}; extrinsics ({}): [{}]]",
			block.header().number(),
			block_timer.elapsed().as_millis(),
			block.header().hash(),
			block.header().parent_hash(),
			block.extrinsics().len(),
			block.extrinsics()
				.iter()
				.map(|xt| BlakeTwo256::hash_of(xt).to_string())
				.collect::<Vec<_>>()
				.join(", ")
		);

        self.import_block(block, Some(storage_changes)).await?;

        Ok(())
    }

    /// Produce `n` number of blocks.
    pub async fn produce_n_blocks(&mut self, n: u64) -> Result<(), Box<dyn Error>> {
        for _ in 0..n {
            self.produce_block().await?;
        }
        Ok(())
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
