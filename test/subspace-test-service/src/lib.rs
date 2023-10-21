// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Subspace test service only.

#![warn(missing_docs, unused_crate_dependencies)]

use codec::{Decode, Encode};
use cross_domain_message_gossip::GossipWorkerBuilder;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use domain_runtime_primitives::BlockNumber as DomainNumber;
use futures::channel::mpsc;
use futures::{select, FutureExt, StreamExt};
use jsonrpsee::RpcModule;
use parking_lot::Mutex;
use sc_block_builder::BlockBuilderProvider;
use sc_client_api::execution_extensions::ExtensionsFactory;
use sc_client_api::{BlockBackend, ExecutorProvider};
use sc_consensus::block_import::{
    BlockCheckParams, BlockImportParams, ForkChoiceStrategy, ImportResult,
};
use sc_consensus::{
    BasicQueue, BlockImport, SharedBlockImport, StateAction, Verifier as VerifierT,
};
use sc_executor::NativeElseWasmExecutor;
use sc_network::config::{NetworkConfiguration, TransportConfig};
use sc_network::multiaddr;
use sc_service::config::{
    DatabaseSource, KeystoreConfig, MultiaddrWithPeerId, WasmExecutionMethod,
    WasmtimeInstantiationStrategy,
};
use sc_service::{
    BasePath, BlocksPruning, Configuration, InPoolTransaction, NetworkStarter, Role,
    SpawnTasksParams, TaskManager, TransactionPool,
};
use sc_transaction_pool::error::Error as PoolError;
use sc_transaction_pool_api::TransactionSource;
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use sp_api::{ApiExt, HashT, HeaderT, ProvideRuntimeApi};
use sp_application_crypto::UncheckedFrom;
use sp_blockchain::HeaderBackend;
use sp_consensus::{BlockOrigin, Error as ConsensusError};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{CompatibleDigestItem, PreDigest, PreDigestPotInfo};
use sp_consensus_subspace::FarmerPublicKey;
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed};
use sp_core::H256;
use sp_domains::{DomainsApi, OpaqueBundle};
use sp_domains_fraud_proof::{FraudProofExtension, FraudProofHostFunctionsImpl};
use sp_externalities::Extensions;
use sp_inherents::{InherentData, InherentDataProvider};
use sp_keyring::Sr25519Keyring;
use sp_runtime::generic::{BlockId, Digest};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, NumberFor};
use sp_runtime::{DigestItem, OpaqueExtrinsic};
use sp_timestamp::Timestamp;
use std::error::Error;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time;
use subspace_core_primitives::{Randomness, Solution};
use subspace_fraud_proof::invalid_transaction_proof::InvalidTransactionProofVerifier;
use subspace_fraud_proof::verifier_api::VerifierClient;
use subspace_runtime_primitives::opaque::Block;
use subspace_runtime_primitives::{AccountId, Balance, Hash};
use subspace_service::tx_pre_validator::ConsensusChainTxPreValidator;
use subspace_service::FullSelectChain;
use subspace_test_client::{chain_spec, Backend, Client, FraudProofVerifier, TestExecutorDispatch};
use subspace_test_runtime::{RuntimeApi, RuntimeCall, UncheckedExtrinsic, SLOT_DURATION};
use subspace_transaction_pool::FullPool;

/// Create a Subspace `Configuration`.
///
/// By default an in-memory socket will be used, therefore you need to provide boot
/// nodes if you want the future node to be connected to other nodes.
pub fn node_config(
    tokio_handle: tokio::runtime::Handle,
    key: Sr25519Keyring,
    boot_nodes: Vec<MultiaddrWithPeerId>,
    run_farmer: bool,
    force_authoring: bool,
    force_synced: bool,
    base_path: BasePath,
) -> Configuration {
    let root = base_path.path();
    let role = if run_farmer {
        Role::Authority
    } else {
        Role::Full
    };
    let key_seed = key.to_seed();
    let spec = chain_spec::subspace_local_testnet_config();

    let mut network_config = NetworkConfiguration::new(
        key_seed.to_string(),
        "network/test/0.1",
        Default::default(),
        None,
    );

    network_config.boot_nodes = boot_nodes;

    network_config.allow_non_globals_in_dht = true;

    let addr: multiaddr::Multiaddr = multiaddr::Protocol::Memory(rand::random()).into();
    network_config.listen_addresses.push(addr.clone());

    network_config.public_addresses.push(addr);

    network_config.transport = TransportConfig::MemoryOnly;

    network_config.force_synced = force_synced;

    Configuration {
        impl_name: "subspace-test-node".to_string(),
        impl_version: "0.1".to_string(),
        role,
        tokio_handle,
        transaction_pool: Default::default(),
        network: network_config,
        keystore: KeystoreConfig::InMemory,
        database: DatabaseSource::ParityDb {
            path: root.join("paritydb"),
        },
        trie_cache_maximum_size: Some(64 * 1024 * 1024),
        state_pruning: Default::default(),
        blocks_pruning: BlocksPruning::KeepAll,
        chain_spec: Box::new(spec),
        wasm_method: WasmExecutionMethod::Compiled {
            instantiation_strategy: WasmtimeInstantiationStrategy::PoolingCopyOnWrite,
        },
        wasm_runtime_overrides: Default::default(),
        rpc_addr: None,
        rpc_max_request_size: 0,
        rpc_max_response_size: 0,
        rpc_id_provider: None,
        rpc_max_subs_per_conn: 0,
        rpc_port: 0,
        rpc_max_connections: 0,
        rpc_cors: None,
        rpc_methods: Default::default(),
        prometheus_config: None,
        telemetry_endpoints: None,
        default_heap_pages: None,
        offchain_worker: Default::default(),
        force_authoring,
        disable_grandpa: false,
        dev_key_seed: Some(key_seed),
        tracing_targets: None,
        tracing_receiver: Default::default(),
        max_runtime_instances: 8,
        announce_block: true,
        data_path: base_path.path().into(),
        base_path,
        informant_output_format: Default::default(),
        runtime_cache_size: 2,
    }
}

type StorageChanges = sp_api::StorageChanges<Block>;

type TxPreValidator = ConsensusChainTxPreValidator<Block, Client, FraudProofVerifier>;

struct MockExtensionsFactory<Client, DomainBlock, Executor> {
    consensus_client: Arc<Client>,
    executor: Arc<Executor>,
    _phantom: PhantomData<DomainBlock>,
}

impl<Client, DomainBlock, Executor> MockExtensionsFactory<Client, DomainBlock, Executor> {
    fn new(consensus_client: Arc<Client>, executor: Arc<Executor>) -> Self {
        Self {
            consensus_client,
            executor,
            _phantom: Default::default(),
        }
    }
}

impl<Block, Client, DomainBlock, Executor> ExtensionsFactory<Block>
    for MockExtensionsFactory<Client, DomainBlock, Executor>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    DomainBlock: BlockT,
    DomainBlock::Hash: From<H256>,
    Client: BlockBackend<Block> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainsApi<Block, NumberFor<DomainBlock>, DomainBlock::Hash>,
    Executor: CodeExecutor + sc_executor::RuntimeVersionOf,
{
    fn extensions_for(
        &self,
        _block_hash: Block::Hash,
        _block_number: NumberFor<Block>,
    ) -> Extensions {
        let mut exts = Extensions::new();
        exts.register(FraudProofExtension::new(Arc::new(
            FraudProofHostFunctionsImpl::<_, _, DomainBlock, Executor>::new(
                self.consensus_client.clone(),
                self.executor.clone(),
            ),
        )));
        exts
    }
}
/// A mock Subspace consensus node instance used for testing.
pub struct MockConsensusNode {
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
    /// Network service.
    pub network_service: Arc<sc_network::NetworkService<Block, <Block as BlockT>::Hash>>,
    /// Sync service.
    pub sync_service: Arc<sc_network_sync::SyncingService<Block>>,
    /// RPC handlers.
    pub rpc_handlers: sc_service::RpcHandlers,
    /// Network starter
    pub network_starter: Option<NetworkStarter>,
    /// The next slot number
    next_slot: u64,
    /// The slot notification subscribers
    #[allow(clippy::type_complexity)]
    new_slot_notification_subscribers: Vec<TracingUnboundedSender<(Slot, Randomness)>>,
    /// The acknowledgement sender subscribers
    #[allow(clippy::type_complexity)]
    acknowledgement_sender_subscribers: Vec<TracingUnboundedSender<mpsc::Sender<()>>>,
    /// Block import pipeline
    #[allow(clippy::type_complexity)]
    block_import: MockBlockImport<Client, Block>,
    xdm_gossip_worker_builder: Option<GossipWorkerBuilder>,
    /// Mock subspace solution used to mock the subspace `PreDigest`
    mock_solution: Solution<FarmerPublicKey, AccountId>,
    log_prefix: &'static str,
}

impl MockConsensusNode {
    /// Run a mock consensus node
    pub fn run(
        tokio_handle: tokio::runtime::Handle,
        key: Sr25519Keyring,
        base_path: BasePath,
    ) -> MockConsensusNode {
        let log_prefix = key.into();

        let mut config = node_config(tokio_handle, key, vec![], false, false, false, base_path);

        // Set `transaction_pool.ban_time` to 0 such that duplicated tx will not immediately rejected
        // by `TemporarilyBanned`
        config.transaction_pool.ban_time = time::Duration::from_millis(0);

        config.network.node_name = format!("{} (Consensus)", config.network.node_name);
        let span = sc_tracing::tracing::info_span!(
            sc_tracing::logging::PREFIX_LOG_SPAN,
            name = config.network.node_name.as_str()
        );
        let _enter = span.enter();

        let executor = sc_service::new_native_or_wasm_executor(&config);

        let (client, backend, keystore_container, mut task_manager) =
            sc_service::new_full_parts::<Block, RuntimeApi, _>(&config, None, executor.clone())
                .expect("Fail to new full parts");

        let client = Arc::new(client);
        client
            .execution_extensions()
            .set_extensions_factory(MockExtensionsFactory::<_, DomainBlock, _>::new(
                client.clone(),
                Arc::new(executor.clone()),
            ));

        let select_chain = sc_consensus::LongestChain::new(backend.clone());

        let invalid_transaction_proof_verifier = InvalidTransactionProofVerifier::new(
            client.clone(),
            Arc::new(executor.clone()),
            VerifierClient::new(client.clone()),
        );

        let proof_verifier =
            subspace_fraud_proof::ProofVerifier::new(Arc::new(invalid_transaction_proof_verifier));

        let tx_pre_validator = ConsensusChainTxPreValidator::new(
            client.clone(),
            Box::new(task_manager.spawn_handle()),
            proof_verifier.clone(),
        );

        let transaction_pool = subspace_transaction_pool::new_full(
            &config,
            &task_manager,
            client.clone(),
            tx_pre_validator,
        );

        let block_import = MockBlockImport::<_, _>::new(client.clone());

        let net_config = sc_network::config::FullNetworkConfiguration::new(&config.network);

        let (network_service, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
            sc_service::build_network(sc_service::BuildNetworkParams {
                config: &config,
                net_config,
                client: client.clone(),
                transaction_pool: transaction_pool.clone(),
                spawn_handle: task_manager.spawn_handle(),
                import_queue: mock_import_queue(
                    block_import.clone(),
                    &task_manager.spawn_essential_handle(),
                ),
                block_announce_validator_builder: None,
                warp_sync_params: None,
                block_relay: None,
            })
            .expect("Should be able to build network");

        let rpc_handlers = sc_service::spawn_tasks(SpawnTasksParams {
            network: network_service.clone(),
            client: client.clone(),
            keystore: keystore_container.keystore(),
            task_manager: &mut task_manager,
            transaction_pool: transaction_pool.clone(),
            rpc_builder: Box::new(|_, _| Ok(RpcModule::new(()))),
            backend: backend.clone(),
            system_rpc_tx,
            config,
            telemetry: None,
            tx_handler_controller,
            sync_service: sync_service.clone(),
        })
        .expect("Should be able to spawn tasks");

        let mock_solution = Solution::genesis_solution(
            FarmerPublicKey::unchecked_from(key.public().0),
            key.to_account_id(),
        );

        MockConsensusNode {
            task_manager,
            client,
            backend,
            executor,
            transaction_pool,
            select_chain,
            network_service,
            sync_service,
            rpc_handlers,
            network_starter: Some(network_starter),
            next_slot: 1,
            new_slot_notification_subscribers: Vec::new(),
            acknowledgement_sender_subscribers: Vec::new(),
            block_import,
            xdm_gossip_worker_builder: Some(GossipWorkerBuilder::new()),
            mock_solution,
            log_prefix,
        }
    }

    /// Start the mock consensus node network
    pub fn start_network(&mut self) {
        self.network_starter
            .take()
            .expect("mock consensus node network have not started yet")
            .start_network();
    }

    /// Get the cross domain gossip message worker builder
    pub fn xdm_gossip_worker_builder(&mut self) -> &mut GossipWorkerBuilder {
        self.xdm_gossip_worker_builder
            .as_mut()
            .expect("gossip message worker have not started yet")
    }

    /// Start the cross domain gossip message worker.
    pub fn start_cross_domain_gossip_message_worker(&mut self) {
        let xdm_gossip_worker_builder = self
            .xdm_gossip_worker_builder
            .take()
            .expect("gossip message worker have not started yet");
        let cross_domain_message_gossip_worker = xdm_gossip_worker_builder
            .build::<Block, _, _>(self.network_service.clone(), self.sync_service.clone());
        self.task_manager
            .spawn_essential_handle()
            .spawn_essential_blocking(
                "cross-domain-gossip-message-worker",
                None,
                Box::pin(cross_domain_message_gossip_worker.run()),
            );
    }

    /// Return the next slot number
    pub fn next_slot(&self) -> u64 {
        self.next_slot
    }

    /// Set the next slot number
    pub fn set_next_slot(&mut self, next_slot: u64) {
        self.next_slot = next_slot;
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
    ) -> Option<OpaqueBundle<NumberFor<Block>, Hash, DomainNumber, H256, Balance>> {
        let value = (slot, Randomness::from(Hash::random().to_fixed_bytes()));
        self.new_slot_notification_subscribers
            .retain(|subscriber| subscriber.unbounded_send(value).is_ok());

        self.confirm_acknowledgement().await;
        self.get_bundle_from_tx_pool(slot.into())
    }

    /// Produce a new slot and wait for a bundle produced at this slot.
    pub async fn produce_slot_and_wait_for_bundle_submission(
        &mut self,
    ) -> (
        Slot,
        Option<OpaqueBundle<NumberFor<Block>, Hash, DomainNumber, H256, Balance>>,
    ) {
        let slot = self.produce_slot();

        let bundle = self.notify_new_slot_and_wait_for_bundle(slot).await;

        (slot, bundle)
    }

    /// Subscribe the new slot notification
    pub fn new_slot_notification_stream(&mut self) -> TracingUnboundedReceiver<(Slot, Randomness)> {
        let (tx, rx) = tracing_unbounded("subspace_new_slot_notification_stream", 100);
        self.new_slot_notification_subscribers.push(tx);
        rx
    }

    /// Subscribe the acknowledgement sender stream
    pub fn new_acknowledgement_sender_stream(
        &mut self,
    ) -> TracingUnboundedReceiver<mpsc::Sender<()>> {
        let (tx, rx) = tracing_unbounded("subspace_acknowledgement_sender_stream", 100);
        self.acknowledgement_sender_subscribers.push(tx);
        rx
    }

    /// Wait for all the acknowledgements before return
    ///
    /// It is used to wait for the acknowledgement of the domain worker to ensure it have
    /// finish all the previous tasks before return
    pub async fn confirm_acknowledgement(&mut self) {
        let (acknowledgement_sender, mut acknowledgement_receiver) = mpsc::channel(0);

        // Must drop `acknowledgement_sender` after the notification otherwise the receiver
        // will block forever as there is still a sender not closed.
        {
            self.acknowledgement_sender_subscribers
                .retain(|subscriber| {
                    subscriber
                        .unbounded_send(acknowledgement_sender.clone())
                        .is_ok()
                });
            drop(acknowledgement_sender);
        }

        // Wait for all the acknowledgements to progress and proactively drop closed subscribers.
        loop {
            select! {
                res = acknowledgement_receiver.next() => if res.is_none() {
                    break;
                },
                // TODO: Workaround for https://github.com/smol-rs/async-channel/issues/23, remove once fix is released
                _ = futures_timer::Delay::new(time::Duration::from_millis(500)).fuse() => {
                    self.acknowledgement_sender_subscribers.retain(|subscriber| !subscriber.is_closed());
                }
            }
        }
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
    ) -> Option<OpaqueBundle<NumberFor<Block>, Hash, DomainNumber, H256, Balance>> {
        for ready_tx in self.transaction_pool.ready() {
            let ext = UncheckedExtrinsic::decode(&mut ready_tx.data.encode().as_slice())
                .expect("should be able to decode");
            if let RuntimeCall::Domains(pallet_domains::Call::submit_bundle { opaque_bundle }) =
                ext.function
            {
                if opaque_bundle.sealed_header.slot_number() == slot {
                    return Some(opaque_bundle);
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

    /// Remove all tx from the tx pool
    pub async fn clear_tx_pool(&self) -> Result<(), Box<dyn Error>> {
        let txs: Vec<_> = self
            .transaction_pool
            .ready()
            .map(|t| self.transaction_pool.hash_of(&t.data))
            .collect();
        self.prune_txs_from_pool(txs.as_slice()).await
    }

    /// Remove a ready transaction from transaction pool.
    pub async fn prune_tx_from_pool(&self, tx: &OpaqueExtrinsic) -> Result<(), Box<dyn Error>> {
        self.prune_txs_from_pool(&[self.transaction_pool.hash_of(tx)])
            .await
    }

    async fn prune_txs_from_pool(
        &self,
        tx_hashes: &[<Block as BlockT>::Hash],
    ) -> Result<(), Box<dyn Error>> {
        self.transaction_pool
            .pool()
            .prune_known(&BlockId::Hash(self.client.info().best_hash), tx_hashes)?;
        // `ban_time` have set to 0, explicitly wait 1ms here to ensure `clear_stale` will remove
        // all the bans as the ban time must be passed.
        tokio::time::sleep(time::Duration::from_millis(1)).await;
        self.transaction_pool
            .pool()
            .validated_pool()
            .clear_stale(&BlockId::Number(self.client.info().best_number))?;
        Ok(())
    }
}

impl MockConsensusNode {
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
        let pre_digest: PreDigest<FarmerPublicKey, AccountId> = PreDigest::V0 {
            slot,
            solution: self.mock_solution.clone(),
            pot_info: PreDigestPotInfo::V0 {
                proof_of_time: Default::default(),
                future_proof_of_time: Default::default(),
            },
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
        let tx_hashes: Vec<_> = extrinsics
            .iter()
            .map(|t| self.transaction_pool.hash_of(t))
            .collect();

        let (block, storage_changes) = self.build_block(slot, parent_hash, extrinsics).await?;

        log_new_block(&block, block_timer.elapsed().as_millis());

        let res = match self.import_block(block, Some(storage_changes)).await {
            Ok(hash) => {
                // Remove the tx of the imported block from the tx pool incase re-include them
                // in the future block by accident.
                self.prune_txs_from_pool(tx_hashes.as_slice()).await?;
                Ok(hash)
            }
            err => err,
        };
        self.confirm_acknowledgement().await;
        res
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

fn mock_import_queue<Block: BlockT, I>(
    block_import: I,
    spawner: &impl SpawnEssentialNamed,
) -> BasicQueue<Block>
where
    I: BlockImport<Block, Error = ConsensusError> + Send + Sync + 'static,
{
    BasicQueue::new(
        MockVerifier::default(),
        SharedBlockImport::new(block_import),
        None,
        spawner,
        None,
    )
}

struct MockVerifier<Block> {
    _marker: PhantomData<Block>,
}

impl<Block> Default for MockVerifier<Block> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<Block> VerifierT<Block> for MockVerifier<Block>
where
    Block: BlockT,
{
    async fn verify(
        &self,
        block_params: BlockImportParams<Block>,
    ) -> Result<BlockImportParams<Block>, String> {
        Ok(block_params)
    }
}

// `MockBlockImport` is mostly port from `sc-consensus-subspace::SubspaceBlockImport` with all
// the consensus related logic removed.
#[allow(clippy::type_complexity)]
struct MockBlockImport<Client, Block: BlockT> {
    inner: Arc<Client>,
    block_importing_notification_subscribers:
        Arc<Mutex<Vec<TracingUnboundedSender<(NumberFor<Block>, mpsc::Sender<()>)>>>>,
}

impl<Client, Block: BlockT> MockBlockImport<Client, Block> {
    fn new(inner: Arc<Client>) -> Self {
        MockBlockImport {
            inner,
            block_importing_notification_subscribers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    // Subscribe the block importing notification
    fn block_importing_notification_stream(
        &mut self,
    ) -> TracingUnboundedReceiver<(NumberFor<Block>, mpsc::Sender<()>)> {
        let (tx, rx) = tracing_unbounded("subspace_new_slot_notification_stream", 100);
        self.block_importing_notification_subscribers
            .lock()
            .push(tx);
        rx
    }
}

impl<Client, Block: BlockT> MockBlockImport<Client, Block> {
    fn clone(&self) -> Self {
        MockBlockImport {
            inner: self.inner.clone(),
            block_importing_notification_subscribers: self
                .block_importing_notification_subscribers
                .clone(),
        }
    }
}

#[async_trait::async_trait]
impl<Client, Block> BlockImport<Block> for MockBlockImport<Client, Block>
where
    Block: BlockT,
    for<'r> &'r Client: BlockImport<Block, Error = ConsensusError> + Send + Sync,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
    Client::Api: ApiExt<Block>,
{
    type Error = ConsensusError;

    async fn import_block(
        &mut self,
        mut block: BlockImportParams<Block>,
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
                .lock()
                .retain(|subscriber| {
                    // It is necessary to notify the subscriber twice for each importing block in the test to ensure
                    // the imported block must be fully processed by the executor when all acknowledgements responded.
                    // This is because the `futures::channel::mpsc::channel` used in the executor have 1 slot even the
                    // `consensus_block_import_throttling_buffer_size` is set to 0 in the test, notify one more time can
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
                    self.block_importing_notification_subscribers.lock().retain(|subscriber| !subscriber.is_closed());
                }
            }
        }

        Ok(import_result)
    }

    async fn check_block(
        &self,
        block: BlockCheckParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        self.inner.check_block(block).await.map_err(Into::into)
    }
}

/// Produce the given number of blocks for both the primary node and the domain nodes
#[macro_export]
macro_rules! produce_blocks {
    ($primary_node:ident, $operator_node:ident, $count: literal $(, $domain_node:ident)*) => {
        {
            $operator_node.send_system_remark().await;
            async {
                let domain_fut = {
                    let mut futs: Vec<std::pin::Pin<Box<dyn futures::Future<Output = ()>>>> = Vec::new();
                    futs.push(Box::pin($operator_node.wait_for_blocks($count)));
                    $( futs.push( Box::pin( $domain_node.wait_for_blocks($count) ) ); )*
                    futures::future::join_all(futs)
                };
                $primary_node.produce_blocks($count).await?;
                domain_fut.await;
                Ok::<(), Box<dyn std::error::Error>>(())
            }
        }
    };
}

/// Producing one block for both the primary node and the domain nodes, where the primary node can
/// use the `produce_block_with_xxx` function (i.e. `produce_block_with_slot`) to produce block
#[macro_export]
macro_rules! produce_block_with {
    ($primary_node_produce_block:expr, $operator_node:ident $(, $domain_node:ident)*) => {
        {
            $operator_node.send_system_remark().await;
            async {
                let domain_fut = {
                    let mut futs: Vec<std::pin::Pin<Box<dyn futures::Future<Output = ()>>>> = Vec::new();
                    futs.push(Box::pin($operator_node.wait_for_blocks(1)));
                    $( futs.push( Box::pin( $domain_node.wait_for_blocks(1) ) ); )*
                    futures::future::join_all(futs)
                };
                $primary_node_produce_block.await?;
                domain_fut.await;
                Ok::<(), Box<dyn std::error::Error>>(())
            }
        }
    };
}

/// Keep producing block with a fixed interval until the given condition become `true`
#[macro_export]
macro_rules! produce_blocks_until {
    ($primary_node:ident, $operator_node:ident, $condition: block $(, $domain_node:ident)*) => {
        async {
            while !$condition {
                produce_blocks!($primary_node, $operator_node, 1 $(, $domain_node),*).await?;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        }
    };
}
