use crate::node_config;
use codec::{Decode, Encode};
use futures::channel::mpsc;
use futures::{select, FutureExt, SinkExt, StreamExt};
use sc_block_builder::BlockBuilderProvider;
use sc_client_api::{backend, BlockchainEvents};
use sc_consensus::block_import::{
    BlockCheckParams, BlockImportParams, ForkChoiceStrategy, ImportResult,
};
use sc_consensus::{BlockImport, BoxBlockImport, StateAction};
use sc_executor::NativeElseWasmExecutor;
use sc_service::{BasePath, InPoolTransaction, TaskManager, TransactionPool};
use sc_transaction_pool::error::Error as PoolError;
use sc_transaction_pool_api::TransactionSource;
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use sp_api::{ApiExt, HashT, HeaderT, ProvideRuntimeApi, TransactionFor};
use sp_application_crypto::UncheckedFrom;
use sp_blockchain::HeaderBackend;
use sp_consensus::{BlockOrigin, Error as ConsensusError, NoNetwork, SyncOracle};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{CompatibleDigestItem, PreDigest};
use sp_consensus_subspace::FarmerPublicKey;
use sp_core::H256;
use sp_domains::SignedOpaqueBundle;
use sp_inherents::{InherentData, InherentDataProvider};
use sp_keyring::Sr25519Keyring;
use sp_runtime::generic::{BlockId, Digest};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, NumberFor};
use sp_runtime::{DigestItem, OpaqueExtrinsic};
use sp_timestamp::Timestamp;
use std::error::Error;
use std::sync::Arc;
use std::time;
use subspace_core_primitives::{Blake2b256Hash, Solution};
use subspace_fraud_proof::domain_extrinsics_builder::SystemDomainExtrinsicsBuilder;
use subspace_fraud_proof::invalid_state_transition_proof::{
    InvalidStateTransitionProofVerifier, PrePostStateRootVerifier,
};
use subspace_runtime_primitives::opaque::Block;
use subspace_runtime_primitives::{AccountId, Hash};
use subspace_service::tx_pre_validator::PrimaryChainTxPreValidator;
use subspace_service::FullSelectChain;
use subspace_solving::create_chunk_signature;
use subspace_test_client::{Backend, Client, FraudProofVerifier, TestExecutorDispatch};
use subspace_test_runtime::{RuntimeApi, RuntimeCall, UncheckedExtrinsic, SLOT_DURATION};
use subspace_transaction_pool::bundle_validator::BundleValidator;
use subspace_transaction_pool::FullPool;

type StorageChanges = sp_api::StorageChanges<backend::StateBackendFor<Backend, Block>, Block>;

pub(super) type TxPreValidator =
    PrimaryChainTxPreValidator<Block, Client, FraudProofVerifier, BundleValidator<Block, Client>>;

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
    pub transaction_pool: Arc<FullPool<Block, Client, TxPreValidator>>,
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
    log_prefix: &'static str,
}

impl MockPrimaryNode {
    /// Run a mock primary node
    pub fn run_mock_primary_node(
        tokio_handle: tokio::runtime::Handle,
        key: Sr25519Keyring,
        base_path: BasePath,
    ) -> MockPrimaryNode {
        let log_prefix = key.into();

        let mut config = node_config(tokio_handle, key, vec![], false, false, false, base_path);

        // Set `transaction_pool.ban_time` to 0 such that duplicated tx will not immediately rejected
        // by `TemporarilyBanned`
        config.transaction_pool.ban_time = time::Duration::from_millis(0);

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

        let mut bundle_validator = BundleValidator::new(client.clone());

        let proof_verifier = subspace_fraud_proof::ProofVerifier::new(Arc::new(
            InvalidStateTransitionProofVerifier::new(
                client.clone(),
                executor.clone(),
                task_manager.spawn_handle(),
                PrePostStateRootVerifier::new(client.clone()),
                SystemDomainExtrinsicsBuilder::new(client.clone(), Arc::new(executor.clone())),
            ),
        ));
        let tx_pre_validator = PrimaryChainTxPreValidator::new(
            client.clone(),
            Box::new(task_manager.spawn_handle()),
            proof_verifier.clone(),
            bundle_validator.clone(),
        );

        let transaction_pool = subspace_transaction_pool::new_full(
            &config,
            &task_manager,
            client.clone(),
            tx_pre_validator,
        );

        let fraud_proof_block_import =
            sc_consensus_fraud_proof::block_import(client.clone(), client.clone(), proof_verifier);

        let mut block_import = MockBlockImport::<
            BoxBlockImport<Block, TransactionFor<Client, Block>>,
            _,
            _,
        >::new(Box::new(fraud_proof_block_import), client.clone());

        // The `maintain-bundles-stored-in-last-k` worker here is different from the one in the production code
        // that it subscribes the `block_importing_notification_stream`, which is intended to ensure the bundle
        // validator's `recent_stored_bundles` info must be updated when a new primary block is produced, this
        // will help the test to be more deterministic.
        let mut imported_blocks_stream = client.import_notification_stream();
        let mut block_importing_stream = block_import.block_importing_notification_stream();
        task_manager.spawn_handle().spawn(
            "maintain-bundles-stored-in-last-k",
            None,
            Box::pin(async move {
                loop {
                    tokio::select! {
                        biased;
                        maybe_block_imported = imported_blocks_stream.next() => {
                            match maybe_block_imported {
                                Some(block) => if block.is_new_best {
                                    bundle_validator.update_recent_stored_bundles(block.hash);
                                }
                                None => break,
                            }
                        },
                        maybe_block_importing = block_importing_stream.next() => {
                            match maybe_block_importing {
                                Some((_, mut acknowledgement_sender)) => {
                                    let _ = acknowledgement_sender.send(()).await;
                                }
                                None => break,
                            }
                        }
                    }
                }
            }),
        );

        // Inform the tx pool about imported and finalized blocks and remove the tx of these
        // blocks from the tx pool.
        task_manager.spawn_handle().spawn(
            "txpool-notifications",
            Some("transaction-pool"),
            sc_transaction_pool::notification_future(client.clone(), transaction_pool.clone()),
        );

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
            log_prefix,
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

    /// Produce a slot only, without waiting for the potential slot handlers.
    pub fn produce_slot(&mut self) -> Slot {
        let slot = Slot::from(self.next_slot);
        self.next_slot += 1;
        slot
    }

    /// Notify the executor about the new slot and wait for the bundle produced at this slot.
    pub async fn notify_new_slot_and_wait_for_bundle(
        &mut self,
        slot: Slot,
    ) -> Option<SignedOpaqueBundle<NumberFor<Block>, Hash, H256>> {
        let (slot_acknowledgement_sender, mut slot_acknowledgement_receiver) = mpsc::channel(0);

        // Must drop `slot_acknowledgement_sender` after the notification otherwise the receiver
        // will block forever as there is still a sender not closed.
        {
            let value = (
                slot,
                Hash::random().into(),
                Some(slot_acknowledgement_sender),
            );
            self.new_slot_notification_subscribers
                .retain(|subscriber| subscriber.unbounded_send(value.clone()).is_ok());
        }

        // Wait for all the acknowledgements to progress and proactively drop closed subscribers.
        loop {
            select! {
                res = slot_acknowledgement_receiver.next() => if res.is_none() {
                    break;
                },
                // TODO: Workaround for https://github.com/smol-rs/async-channel/issues/23, remove once fix is released
                _ = futures_timer::Delay::new(time::Duration::from_millis(500)).fuse() => {
                    self.new_slot_notification_subscribers.retain(|subscriber| !subscriber.is_closed());
                }
            }
        }

        self.get_bundle_from_tx_pool(slot.into())
    }

    /// Produce a new slot and wait for a bundle produced at this slot.
    pub async fn produce_slot_and_wait_for_bundle_submission(
        &mut self,
    ) -> (
        Slot,
        Option<SignedOpaqueBundle<NumberFor<Block>, Hash, H256>>,
    ) {
        let slot = self.produce_slot();

        let bundle = self.notify_new_slot_and_wait_for_bundle(slot).await;

        (slot, bundle)
    }

    /// Subscribe the new slot notification
    pub fn new_slot_notification_stream(
        &mut self,
    ) -> TracingUnboundedReceiver<(Slot, Blake2b256Hash, Option<mpsc::Sender<()>>)> {
        let (tx, rx) = tracing_unbounded("subspace_new_slot_notification_stream", 100);
        self.new_slot_notification_subscribers.push(tx);
        rx
    }

    /// Subscribe the block importing notification
    pub fn block_importing_notification_stream(
        &mut self,
    ) -> TracingUnboundedReceiver<(NumberFor<Block>, mpsc::Sender<()>)> {
        self.block_import.block_importing_notification_stream()
    }

    /// Get the bundle that created at `slot` from the transaction pool
    pub fn get_bundle_from_tx_pool(
        &self,
        slot: u64,
    ) -> Option<SignedOpaqueBundle<NumberFor<Block>, Hash, H256>> {
        for ready_tx in self.transaction_pool.ready() {
            let ext = UncheckedExtrinsic::decode(&mut ready_tx.data.encode().as_slice())
                .expect("should be able to decode");
            if let RuntimeCall::Domains(pallet_domains::Call::submit_bundle {
                signed_opaque_bundle,
            }) = ext.function
            {
                if signed_opaque_bundle.bundle.header.slot_number == slot {
                    return Some(signed_opaque_bundle);
                }
            }
        }
        None
    }

    /// Submit a tx to the tx pool
    pub async fn submit_transaction(&self, tx: OpaqueExtrinsic) -> Result<H256, PoolError> {
        self.transaction_pool
            .submit_one(
                &BlockId::Hash(self.client.info().best_hash),
                TransactionSource::External,
                tx,
            )
            .await
    }

    /// Remove tx from tx pool
    pub fn remove_tx_from_tx_pool(&self, tx: &OpaqueExtrinsic) -> Result<(), Box<dyn Error>> {
        self.transaction_pool
            .remove_invalid(&[self.transaction_pool.hash_of(tx)]);
        self.transaction_pool
            .pool()
            .validated_pool()
            .clear_stale(&BlockId::Number(self.client.info().best_number))?;
        Ok(())
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
    ) -> Result<<Block as BlockT>::Hash, Box<dyn Error>> {
        let (header, body) = block.deconstruct();

        let header_hash = header.hash();

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

        let import_result = self.block_import.import_block(block_import_params).await?;

        match import_result {
            ImportResult::Imported(_) | ImportResult::AlreadyInChain => Ok(header_hash),
            bad_res => Err(format!("Fail to import block due to {bad_res:?}").into()),
        }
    }

    /// Produce a new block with the slot on top of `parent_hash`, with optional
    /// specified extrinsic list.
    #[sc_tracing::logging::prefix_logs_with(self.log_prefix)]
    pub async fn produce_block_with_slot_at(
        &mut self,
        slot: Slot,
        parent_hash: <Block as BlockT>::Hash,
        maybe_extrinsics: Option<Vec<<Block as BlockT>::Extrinsic>>,
    ) -> Result<<Block as BlockT>::Hash, Box<dyn Error>> {
        let block_timer = time::Instant::now();

        let parent_number =
            self.client
                .number(parent_hash)?
                .ok_or(sp_blockchain::Error::Backend(format!(
                    "Number for {parent_hash} not found"
                )))?;

        let extrinsics = match maybe_extrinsics {
            Some(extrinsics) => extrinsics,
            None => self.collect_txn_from_pool(parent_number).await,
        };

        let (block, storage_changes) = self.build_block(slot, parent_hash, extrinsics).await?;

        log_new_block(&block, block_timer.elapsed().as_millis());

        self.import_block(block, Some(storage_changes)).await
    }

    /// Produce a new block on top of the current best block, with the extrinsics collected from
    /// the transaction pool.
    #[sc_tracing::logging::prefix_logs_with(self.log_prefix)]
    pub async fn produce_block_with_slot(&mut self, slot: Slot) -> Result<(), Box<dyn Error>> {
        self.produce_block_with_slot_at(slot, self.client.info().best_hash, None)
            .await?;
        Ok(())
    }

    /// Produce a new block on top of the current best block, with the specificed extrinsics.
    #[sc_tracing::logging::prefix_logs_with(self.log_prefix)]
    pub async fn produce_block_with_extrinsics(
        &mut self,
        extrinsics: Vec<<Block as BlockT>::Extrinsic>,
    ) -> Result<(), Box<dyn Error>> {
        let (slot, _) = self.produce_slot_and_wait_for_bundle_submission().await;
        self.produce_block_with_slot_at(slot, self.client.info().best_hash, Some(extrinsics))
            .await?;
        Ok(())
    }

    /// Produce `n` number of blocks.
    #[sc_tracing::logging::prefix_logs_with(self.log_prefix)]
    pub async fn produce_blocks(&mut self, n: u64) -> Result<(), Box<dyn Error>> {
        for _ in 0..n {
            let (slot, _) = self.produce_slot_and_wait_for_bundle_submission().await;
            self.produce_block_with_slot(slot).await?;
        }
        Ok(())
    }
}

fn log_new_block(block: &Block, used_time_ms: u128) {
    tracing::info!(
        "🎁 Prepared block for proposing at {} ({} ms) [hash: {:?}; parent_hash: {}; extrinsics ({}): [{}]]",
        block.header().number(),
        used_time_ms,
        block.header().hash(),
        block.header().parent_hash(),
        block.extrinsics().len(),
        block.extrinsics()
            .iter()
            .map(|xt| BlakeTwo256::hash_of(xt).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

// `MockBlockImport` is mostly port from `sc-consensus-subspace::SubspaceBlockImport` with all
// the consensus related logic removed.
struct MockBlockImport<Inner, Client, Block: BlockT> {
    inner: Inner,
    client: Arc<Client>,
    block_importing_notification_subscribers:
        Vec<TracingUnboundedSender<(NumberFor<Block>, mpsc::Sender<()>)>>,
}

impl<Inner, Client, Block: BlockT> MockBlockImport<Inner, Client, Block> {
    fn new(inner: Inner, client: Arc<Client>) -> Self {
        MockBlockImport {
            inner,
            client,
            block_importing_notification_subscribers: Vec::new(),
        }
    }

    // Subscribe the block importing notification
    fn block_importing_notification_stream(
        &mut self,
    ) -> TracingUnboundedReceiver<(NumberFor<Block>, mpsc::Sender<()>)> {
        let (tx, rx) = tracing_unbounded("subspace_new_slot_notification_stream", 100);
        self.block_importing_notification_subscribers.push(tx);
        rx
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
    ) -> Result<ImportResult, Self::Error> {
        let block_number = *block.header.number();
        block.fork_choice = Some(ForkChoiceStrategy::LongestChain);

        let import_result = self.inner.import_block(block).await?;
        let (acknowledgement_sender, mut acknowledgement_receiver) = mpsc::channel(0);

        // Must drop `block_import_acknowledgement_sender` after the notification otherwise the receiver
        // will block forever as there is still a sender not closed.
        {
            let value = (block_number, acknowledgement_sender);
            self.block_importing_notification_subscribers
                .retain(|subscriber| {
                    // It is necessary to notify the subscriber twice for each importing block in the test to ensure
                    // the imported block must be fully processed by the executor when all acknowledgements responded.
                    // This is because the `futures::channel::mpsc::channel` used in the executor have 1 slot even the
                    // `primary_block_import_throttling_buffer_size` is set to 0 in the test, notify one more time can
                    // ensure the previously sent `block_imported` notification must be fully processed by the executor
                    // when the second acknowledgements responded.
                    // Please see https://github.com/subspace/subspace/pull/1363#discussion_r1162571291 for more details.
                    subscriber
                        .unbounded_send(value.clone())
                        .and_then(|_| subscriber.unbounded_send(value.clone()))
                        .is_ok()
                });
        }

        // Wait for all the acknowledgements to progress and proactively drop closed subscribers.
        loop {
            select! {
                res = acknowledgement_receiver.next() => if res.is_none() {
                    break;
                },
                // TODO: Workaround for https://github.com/smol-rs/async-channel/issues/23, remove once fix is released
                _ = futures_timer::Delay::new(time::Duration::from_millis(500)).fuse() => {
                    self.block_importing_notification_subscribers.retain(|subscriber| !subscriber.is_closed());
                }
            }
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
