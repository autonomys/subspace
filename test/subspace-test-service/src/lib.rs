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

#![feature(trait_upcasting)]
#![warn(missing_docs, unused_crate_dependencies)]

use codec::{Decode, Encode};
use cross_domain_message_gossip::{xdm_gossip_peers_set_config, GossipWorkerBuilder};
use domain_runtime_primitives::opaque::{Block as DomainBlock, Header as DomainHeader};
use frame_system::pallet_prelude::BlockNumberFor;
use futures::channel::mpsc;
use futures::{Future, StreamExt};
use jsonrpsee::RpcModule;
use parking_lot::Mutex;
use sc_block_builder::BlockBuilderBuilder;
use sc_client_api::execution_extensions::ExtensionsFactory;
use sc_client_api::{Backend as BackendT, BlockBackend, ExecutorProvider, Finalizer};
use sc_consensus::block_import::{
    BlockCheckParams, BlockImportParams, ForkChoiceStrategy, ImportResult,
};
use sc_consensus::{
    BasicQueue, BlockImport, SharedBlockImport, StateAction, Verifier as VerifierT,
};
use sc_domains::ExtensionsFactory as DomainsExtensionFactory;
use sc_network::config::{NetworkConfiguration, TransportConfig};
use sc_network::service::traits::NetworkService;
use sc_network::{multiaddr, NetworkWorker, NotificationMetrics, NotificationService};
use sc_service::config::{
    DatabaseSource, KeystoreConfig, MultiaddrWithPeerId, OffchainWorkerConfig,
    RpcBatchRequestConfig, WasmExecutionMethod, WasmtimeInstantiationStrategy,
};
use sc_service::{
    BasePath, BlocksPruning, Configuration, NetworkStarter, Role, SpawnTasksParams, TaskManager,
};
use sc_transaction_pool::error::Error as PoolError;
use sc_transaction_pool_api::{InPoolTransaction, TransactionPool, TransactionSource};
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_application_crypto::UncheckedFrom;
use sp_blockchain::HeaderBackend;
use sp_consensus::{BlockOrigin, Error as ConsensusError};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    extract_pre_digest, CompatibleDigestItem, PreDigest, PreDigestPotInfo,
};
use sp_consensus_subspace::{FarmerPublicKey, PotExtension, SubspaceApi};
use sp_core::offchain::storage::OffchainDb;
use sp_core::offchain::OffchainDbExt;
use sp_core::traits::{CodeExecutor, SpawnEssentialNamed};
use sp_core::H256;
use sp_domains::{BundleProducerElectionApi, ChainId, DomainsApi, OpaqueBundle};
use sp_domains_fraud_proof::fraud_proof::FraudProof;
use sp_domains_fraud_proof::{FraudProofExtension, FraudProofHostFunctionsImpl};
use sp_externalities::Extensions;
use sp_inherents::{InherentData, InherentDataProvider};
use sp_keyring::Sr25519Keyring;
use sp_messenger::MessengerApi;
use sp_messenger_host_functions::{MessengerExtension, MessengerHostFunctionsImpl};
use sp_mmr_primitives::MmrApi;
use sp_runtime::generic::{BlockId, Digest, SignedPayload};
use sp_runtime::traits::{
    BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT, NumberFor,
};
use sp_runtime::{generic, DigestItem, MultiAddress, OpaqueExtrinsic, SaturatedConversion};
use sp_subspace_mmr::host_functions::{SubspaceMmrExtension, SubspaceMmrHostFunctionsImpl};
use sp_timestamp::Timestamp;
use std::collections::HashMap;
use std::error::Error;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::time;
use subspace_core_primitives::{BlockNumber, PotOutput, Solution};
use subspace_runtime_primitives::opaque::Block;
use subspace_runtime_primitives::{AccountId, Balance, Hash, Signature};
use subspace_service::transaction_pool::FullPool;
use subspace_service::{FullSelectChain, RuntimeExecutor};
use subspace_test_client::{chain_spec, Backend, Client};
use subspace_test_primitives::OnchainStateApi;
use subspace_test_runtime::{
    Runtime, RuntimeApi, RuntimeCall, SignedExtra, UncheckedExtrinsic, SLOT_DURATION,
};
use substrate_frame_rpc_system::AccountNonceApi;
use substrate_test_client::{RpcHandlersExt, RpcTransactionError, RpcTransactionOutput};

type FraudProofFor<Block, DomainBlock> =
    FraudProof<NumberFor<Block>, <Block as BlockT>::Hash, <DomainBlock as BlockT>::Header, H256>;

const MAX_PRODUCE_BUNDLE_TRY: usize = 10;

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
    let spec = chain_spec::subspace_local_testnet_config().unwrap();

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
        rpc_message_buffer_capacity: 0,
        rpc_batch_config: RpcBatchRequestConfig::Disabled,
        rpc_max_connections: 0,
        rpc_cors: None,
        rpc_methods: Default::default(),
        rpc_rate_limit: None,
        rpc_rate_limit_whitelisted_ips: vec![],
        rpc_rate_limit_trust_proxy_headers: false,
        prometheus_config: None,
        telemetry_endpoints: None,
        default_heap_pages: None,
        offchain_worker: OffchainWorkerConfig {
            enabled: false,
            indexing_enabled: true,
        },
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

struct MockExtensionsFactory<Client, DomainBlock, Executor, CBackend> {
    consensus_client: Arc<Client>,
    consensus_backend: Arc<CBackend>,
    executor: Arc<Executor>,
    mock_pot_verifier: Arc<MockPotVerfier>,
    confirmation_depth_k: BlockNumber,
    _phantom: PhantomData<DomainBlock>,
}

impl<Client, DomainBlock, Executor, CBackend>
    MockExtensionsFactory<Client, DomainBlock, Executor, CBackend>
{
    fn new(
        consensus_client: Arc<Client>,
        executor: Arc<Executor>,
        mock_pot_verifier: Arc<MockPotVerfier>,
        consensus_backend: Arc<CBackend>,
        confirmation_depth_k: BlockNumber,
    ) -> Self {
        Self {
            consensus_client,
            consensus_backend,
            executor,
            mock_pot_verifier,
            confirmation_depth_k,
            _phantom: Default::default(),
        }
    }
}

#[derive(Default)]
struct MockPotVerfier(Mutex<HashMap<u64, PotOutput>>);

impl MockPotVerfier {
    fn is_valid(&self, slot: u64, pot: PotOutput) -> bool {
        self.0.lock().get(&slot).map(|p| *p == pot).unwrap_or(false)
    }

    fn inject_pot(&self, slot: u64, pot: PotOutput) {
        self.0.lock().insert(slot, pot);
    }
}

impl<Block, Client, DomainBlock, Executor, CBackend> ExtensionsFactory<Block>
    for MockExtensionsFactory<Client, DomainBlock, Executor, CBackend>
where
    Block: BlockT,
    Block::Hash: From<H256> + Into<H256>,
    DomainBlock: BlockT,
    DomainBlock::Hash: Into<H256> + From<H256>,
    Client: BlockBackend<Block> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainsApi<Block, DomainBlock::Header>
        + BundleProducerElectionApi<Block, Balance>
        + MessengerApi<Block, NumberFor<Block>, Block::Hash>
        + MmrApi<Block, H256, NumberFor<Block>>,
    Executor: CodeExecutor + sc_executor::RuntimeVersionOf,
    CBackend: BackendT<Block> + 'static,
{
    fn extensions_for(
        &self,
        _block_hash: Block::Hash,
        _block_number: NumberFor<Block>,
    ) -> Extensions {
        let confirmation_depth_k = self.confirmation_depth_k;
        let mut exts = Extensions::new();
        exts.register(FraudProofExtension::new(Arc::new(
            FraudProofHostFunctionsImpl::<_, _, DomainBlock, Executor, _>::new(
                self.consensus_client.clone(),
                self.executor.clone(),
                move |client, executor| {
                    let extension_factory =
                        DomainsExtensionFactory::<_, Block, DomainBlock, _>::new(
                            client,
                            executor,
                            confirmation_depth_k,
                        );
                    Box::new(extension_factory) as Box<dyn ExtensionsFactory<DomainBlock>>
                },
            ),
        )));
        exts.register(SubspaceMmrExtension::new(Arc::new(
            SubspaceMmrHostFunctionsImpl::<Block, _>::new(
                self.consensus_client.clone(),
                confirmation_depth_k,
            ),
        )));
        exts.register(MessengerExtension::new(Arc::new(
            MessengerHostFunctionsImpl::<Block, _, DomainBlock, _>::new(
                self.consensus_client.clone(),
                self.executor.clone(),
            ),
        )));

        if let Some(offchain_storage) = self.consensus_backend.offchain_storage() {
            let offchain_db = OffchainDb::new(offchain_storage);
            exts.register(OffchainDbExt::new(offchain_db));
        }
        exts.register(PotExtension::new({
            let client = Arc::clone(&self.consensus_client);
            let mock_pot_verifier = Arc::clone(&self.mock_pot_verifier);
            Box::new(
                move |parent_hash, slot, proof_of_time, _quick_verification| {
                    let parent_hash = {
                        let mut converted_parent_hash = Block::Hash::default();
                        converted_parent_hash.as_mut().copy_from_slice(&parent_hash);
                        converted_parent_hash
                    };

                    let parent_header = match client.header(parent_hash) {
                        Ok(Some(parent_header)) => parent_header,
                        _ => return false,
                    };
                    let parent_pre_digest = match extract_pre_digest(&parent_header) {
                        Ok(parent_pre_digest) => parent_pre_digest,
                        _ => return false,
                    };

                    let parent_slot = parent_pre_digest.slot();
                    if slot <= *parent_slot {
                        return false;
                    }

                    mock_pot_verifier.is_valid(slot, proof_of_time)
                },
            )
        }));
        exts
    }
}

type NewSlot = (Slot, PotOutput);

/// A mock Subspace consensus node instance used for testing.
pub struct MockConsensusNode {
    /// `TaskManager`'s instance.
    pub task_manager: TaskManager,
    /// Client's instance.
    pub client: Arc<Client>,
    /// Backend.
    pub backend: Arc<Backend>,
    /// Code executor.
    pub executor: RuntimeExecutor,
    /// Transaction pool.
    pub transaction_pool: Arc<FullPool<Client, Block, DomainHeader>>,
    /// The SelectChain Strategy
    pub select_chain: FullSelectChain,
    /// Network service.
    pub network_service: Arc<dyn NetworkService + Send + Sync>,
    /// Cross-domain gossip notification service.
    pub xdm_gossip_notification_service: Option<Box<dyn NotificationService>>,
    /// Sync service.
    pub sync_service: Arc<sc_network_sync::SyncingService<Block>>,
    /// RPC handlers.
    pub rpc_handlers: sc_service::RpcHandlers,
    /// Network starter
    pub network_starter: Option<NetworkStarter>,
    /// The next slot number
    next_slot: u64,
    /// The mock pot verifier
    mock_pot_verifier: Arc<MockPotVerfier>,
    /// The slot notification subscribers
    new_slot_notification_subscribers: Vec<mpsc::UnboundedSender<(Slot, PotOutput)>>,
    /// The acknowledgement sender subscribers
    acknowledgement_sender_subscribers: Vec<TracingUnboundedSender<mpsc::Sender<()>>>,
    /// Block import pipeline
    block_import: MockBlockImport<Client, Block>,
    xdm_gossip_worker_builder: Option<GossipWorkerBuilder>,
    /// Mock subspace solution used to mock the subspace `PreDigest`
    mock_solution: Solution<FarmerPublicKey, AccountId>,
    log_prefix: &'static str,
    /// Ferdie key
    pub key: Sr25519Keyring,
    finalize_block_depth: Option<NumberFor<Block>>,
}

impl MockConsensusNode {
    /// Run a mock consensus node
    pub fn run(
        tokio_handle: tokio::runtime::Handle,
        key: Sr25519Keyring,
        base_path: BasePath,
    ) -> MockConsensusNode {
        Self::run_with_finalization_depth(tokio_handle, key, base_path, None)
    }

    /// Run a mock consensus node with finalization depth
    pub fn run_with_finalization_depth(
        tokio_handle: tokio::runtime::Handle,
        key: Sr25519Keyring,
        base_path: BasePath,
        finalize_block_depth: Option<NumberFor<Block>>,
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

        let executor = sc_service::new_wasm_executor(&config);

        let (client, backend, keystore_container, mut task_manager) =
            sc_service::new_full_parts::<Block, RuntimeApi, _>(&config, None, executor.clone())
                .expect("Fail to new full parts");

        let domain_executor = Arc::new(sc_service::new_wasm_executor(&config));
        let client = Arc::new(client);
        let mock_pot_verifier = Arc::new(MockPotVerfier::default());
        let chain_constants = client
            .runtime_api()
            .chain_constants(client.info().best_hash)
            .expect("Fail to get chain constants");
        client
            .execution_extensions()
            .set_extensions_factory(MockExtensionsFactory::<
                _,
                DomainBlock,
                sc_domains::RuntimeExecutor,
                _,
            >::new(
                client.clone(),
                domain_executor.clone(),
                Arc::clone(&mock_pot_verifier),
                backend.clone(),
                chain_constants.confirmation_depth_k(),
            ));

        let select_chain = sc_consensus::LongestChain::new(backend.clone());
        let transaction_pool = subspace_service::transaction_pool::new_full(
            config.transaction_pool.clone(),
            config.role.is_authority(),
            config.prometheus_registry(),
            &task_manager,
            client.clone(),
        )
        .expect("failed to create transaction pool");

        let block_import = MockBlockImport::<_, _>::new(client.clone());

        let mut net_config =
            sc_network::config::FullNetworkConfiguration::<_, _, NetworkWorker<_, _>>::new(
                &config.network,
            );
        let (xdm_gossip_notification_config, xdm_gossip_notification_service) =
            xdm_gossip_peers_set_config();
        net_config.add_notification_protocol(xdm_gossip_notification_config);

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
                metrics: NotificationMetrics::new(None),
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

        let mut gossip_builder = GossipWorkerBuilder::new();

        task_manager
            .spawn_essential_handle()
            .spawn_essential_blocking(
                "consensus-chain-channel-update-worker",
                None,
                Box::pin(
                    domain_client_message_relayer::worker::gossip_channel_updates::<_, _, Block, _>(
                        ChainId::Consensus,
                        client.clone(),
                        sync_service.clone(),
                        gossip_builder.gossip_msg_sink(),
                    ),
                ),
            );

        let (consensus_msg_sink, consensus_msg_receiver) =
            tracing_unbounded("consensus_message_channel", 100);

        // Start cross domain message listener for Consensus chain to receive messages from domains in the network
        let consensus_listener = cross_domain_message_gossip::start_cross_chain_message_listener::<
            _,
            _,
            _,
            _,
            _,
            DomainBlock,
            _,
            _,
        >(
            ChainId::Consensus,
            client.clone(),
            client.clone(),
            transaction_pool.clone(),
            network_service.clone(),
            consensus_msg_receiver,
            domain_executor,
            sync_service.clone(),
        );

        task_manager
            .spawn_essential_handle()
            .spawn_essential_blocking(
                "consensus-message-listener",
                None,
                Box::pin(consensus_listener),
            );

        gossip_builder.push_chain_sink(ChainId::Consensus, consensus_msg_sink);

        task_manager.spawn_essential_handle().spawn_blocking(
            "mmr-gadget",
            None,
            mmr_gadget::MmrGadget::start(
                client.clone(),
                backend.clone(),
                sp_mmr_primitives::INDEXING_PREFIX.to_vec(),
            ),
        );

        MockConsensusNode {
            task_manager,
            client,
            backend,
            executor,
            transaction_pool,
            select_chain,
            network_service,
            xdm_gossip_notification_service: Some(xdm_gossip_notification_service),
            sync_service,
            rpc_handlers,
            network_starter: Some(network_starter),
            next_slot: 1,
            mock_pot_verifier,
            new_slot_notification_subscribers: Vec::new(),
            acknowledgement_sender_subscribers: Vec::new(),
            block_import,
            xdm_gossip_worker_builder: Some(gossip_builder),
            mock_solution,
            log_prefix,
            key,
            finalize_block_depth,
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
        let cross_domain_message_gossip_worker = xdm_gossip_worker_builder.build::<Block, _, _>(
            self.network_service.clone(),
            self.xdm_gossip_notification_service
                .take()
                .expect("XDM gossip notification service must be used only once"),
            self.sync_service.clone(),
        );
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
    pub fn produce_slot(&mut self) -> NewSlot {
        let slot = Slot::from(self.next_slot);
        let proof_of_time = PotOutput::from(
            <&[u8] as TryInto<[u8; 16]>>::try_into(&Hash::random().to_fixed_bytes()[..16])
                .expect("slice with length of 16 must able convert into [u8; 16]; qed"),
        );
        self.mock_pot_verifier.inject_pot(*slot, proof_of_time);
        self.next_slot += 1;

        (slot, proof_of_time)
    }

    /// Notify the executor about the new slot and wait for the bundle produced at this slot.
    pub async fn notify_new_slot_and_wait_for_bundle(
        &mut self,
        new_slot: NewSlot,
    ) -> Option<OpaqueBundle<NumberFor<Block>, Hash, DomainHeader, Balance>> {
        self.new_slot_notification_subscribers
            .retain(|subscriber| subscriber.unbounded_send(new_slot).is_ok());

        self.confirm_acknowledgement().await;
        self.get_bundle_from_tx_pool(new_slot)
    }

    /// Produce a new slot and wait for a bundle produced at this slot.
    pub async fn produce_slot_and_wait_for_bundle_submission(
        &mut self,
    ) -> (
        NewSlot,
        OpaqueBundle<NumberFor<Block>, Hash, DomainHeader, Balance>,
    ) {
        let slot = self.produce_slot();
        for _ in 0..MAX_PRODUCE_BUNDLE_TRY {
            if let Some(bundle) = self.notify_new_slot_and_wait_for_bundle(slot).await {
                return (slot, bundle);
            }
        }
        panic!("Failed to produce bundle after {MAX_PRODUCE_BUNDLE_TRY:?} tries, something must be wrong");
    }

    /// Subscribe the new slot notification
    pub fn new_slot_notification_stream(&mut self) -> mpsc::UnboundedReceiver<(Slot, PotOutput)> {
        let (tx, rx) = mpsc::unbounded();
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
        while acknowledgement_receiver.next().await.is_some() {
            // Wait for all the acknowledgements to finish.
        }
    }

    /// Wait for the operator finish processing the consensus block before return
    pub async fn confirm_block_import_processed(&mut self) {
        // Send one more notification to ensure the previous consensus block import notificaion
        // have received by the operator
        let (acknowledgement_sender, mut acknowledgement_receiver) = mpsc::channel(0);
        {
            // Must drop `block_import_acknowledgement_sender` after the notification otherwise
            // the receiver will block forever as there is still a sender not closed.
            // NOTE: it is okay to use the default block number since it is ignored in the consumer side.
            let value = (NumberFor::<Block>::default(), acknowledgement_sender);
            self.block_import
                .block_importing_notification_subscribers
                .lock()
                .retain(|subscriber| subscriber.unbounded_send(value.clone()).is_ok());
        }
        while acknowledgement_receiver.next().await.is_some() {
            // Wait for all the acknowledgements to finish.
        }

        // Ensure the operator finish processing the consensus block
        self.confirm_acknowledgement().await;
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
        new_slot: NewSlot,
    ) -> Option<OpaqueBundle<NumberFor<Block>, Hash, DomainHeader, Balance>> {
        for ready_tx in self.transaction_pool.ready() {
            let ext = UncheckedExtrinsic::decode(&mut ready_tx.data.encode().as_slice())
                .expect("should be able to decode");
            if let RuntimeCall::Domains(pallet_domains::Call::submit_bundle { opaque_bundle }) =
                ext.function
            {
                if opaque_bundle.sealed_header.slot_number() == *new_slot.0 {
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
                self.client.info().best_hash,
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

    /// Return if the given ER exist in the consensus state
    pub fn does_receipt_exist(
        &self,
        er_hash: <DomainBlock as BlockT>::Hash,
    ) -> Result<bool, Box<dyn Error>> {
        Ok(self
            .client
            .runtime_api()
            .execution_receipt(self.client.info().best_hash, er_hash)?
            .is_some())
    }

    /// Return a future that only resolve if a fraud proof that the given `fraud_proof_predict`
    /// return true is submitted to the consensus tx pool
    pub fn wait_for_fraud_proof<FP>(
        &self,
        fraud_proof_predict: FP,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>>
    where
        FP: Fn(&FraudProofFor<Block, DomainBlock>) -> bool + Send + 'static,
    {
        let tx_pool = self.transaction_pool.clone();
        let mut import_tx_stream = self.transaction_pool.import_notification_stream();
        Box::pin(async move {
            while let Some(ready_tx_hash) = import_tx_stream.next().await {
                let ready_tx = tx_pool
                    .ready_transaction(&ready_tx_hash)
                    .expect("Just get the ready tx hash from import stream; qed");
                let ext = subspace_test_runtime::UncheckedExtrinsic::decode(
                    &mut ready_tx.data.encode().as_slice(),
                )
                .expect("Decode tx must success");
                if let subspace_test_runtime::RuntimeCall::Domains(
                    pallet_domains::Call::submit_fraud_proof { fraud_proof },
                ) = ext.function
                {
                    if fraud_proof_predict(&fraud_proof) {
                        break;
                    }
                }
            }
        })
    }

    /// Get the free balance of the given account
    pub fn free_balance(&self, account_id: AccountId) -> subspace_runtime_primitives::Balance {
        self.client
            .runtime_api()
            .free_balance(self.client.info().best_hash, account_id)
            .expect("Fail to get account free balance")
    }
}

impl MockConsensusNode {
    async fn collect_txn_from_pool(
        &self,
        parent_number: NumberFor<Block>,
    ) -> Vec<<Block as BlockT>::Extrinsic> {
        self.transaction_pool
            .ready_at(parent_number)
            .await
            .map(|pending_tx| pending_tx.data().clone())
            .collect()
    }

    async fn mock_inherent_data(slot: Slot) -> Result<InherentData, Box<dyn Error>> {
        let timestamp = sp_timestamp::InherentDataProvider::new(Timestamp::new(
            <Slot as Into<u64>>::into(slot) * SLOT_DURATION,
        ));
        let subspace_inherents =
            sp_consensus_subspace::inherents::InherentDataProvider::new(vec![]);

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
        let inherent_digest = self.mock_subspace_digest(slot);

        let inherent_data = Self::mock_inherent_data(slot).await?;

        let mut block_builder = BlockBuilderBuilder::new(self.client.as_ref())
            .on_parent_block(parent_hash)
            .fetch_parent_block_number(self.client.as_ref())?
            .with_inherent_digests(inherent_digest)
            .build()
            .expect("Creates new block builder");

        let inherent_txns = block_builder.create_inherents(inherent_data)?;

        for tx in inherent_txns.into_iter().chain(extrinsics) {
            if let Err(err) = sc_block_builder::BlockBuilder::push(&mut block_builder, tx) {
                tracing::error!("Invalid transaction while building block: {}", err);
            }
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
        let header_number = header.number;

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

        if let Some(finalized_block_hash) = self
            .finalize_block_depth
            .and_then(|depth| header_number.checked_sub(depth))
            .and_then(|block_to_finalize| {
                self.client
                    .hash(block_to_finalize)
                    .expect("Block hash not found for number: {block_to_finalize:?}")
            })
        {
            self.client
                .finalize_block(finalized_block_hash, None, true)
                .unwrap();
        }

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
        new_slot: NewSlot,
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

        let (block, storage_changes) = self
            .build_block(new_slot.0, parent_hash, extrinsics)
            .await?;

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
        self.confirm_block_import_processed().await;
        res
    }

    /// Produce a new block on top of the current best block, with the extrinsics collected from
    /// the transaction pool.
    #[sc_tracing::logging::prefix_logs_with(self.log_prefix)]
    pub async fn produce_block_with_slot(&mut self, slot: NewSlot) -> Result<(), Box<dyn Error>> {
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
        let slot = self.produce_slot();
        self.produce_block_with_slot_at(slot, self.client.info().best_hash, Some(extrinsics))
            .await?;
        Ok(())
    }

    /// Produce `n` number of blocks.
    #[sc_tracing::logging::prefix_logs_with(self.log_prefix)]
    pub async fn produce_blocks(&mut self, n: u64) -> Result<(), Box<dyn Error>> {
        for _ in 0..n {
            let slot = self.produce_slot();
            self.produce_block_with_slot(slot).await?;
        }
        Ok(())
    }

    /// Produce `n` number of blocks and wait for bundle submitted to the block.
    #[sc_tracing::logging::prefix_logs_with(self.log_prefix)]
    pub async fn produce_blocks_with_bundles(&mut self, n: u64) -> Result<(), Box<dyn Error>> {
        for _ in 0..n {
            let (slot, _) = self.produce_slot_and_wait_for_bundle_submission().await;
            self.produce_block_with_slot(slot).await?;
        }
        Ok(())
    }

    /// Get the nonce of the node account
    pub fn account_nonce(&self) -> u32 {
        self.client
            .runtime_api()
            .account_nonce(self.client.info().best_hash, self.key.to_account_id())
            .expect("Fail to get account nonce")
    }

    /// Construct an extrinsic.
    pub fn construct_extrinsic(
        &mut self,
        nonce: u32,
        function: impl Into<<Runtime as frame_system::Config>::RuntimeCall>,
    ) -> UncheckedExtrinsic {
        construct_extrinsic_generic(&self.client, function, self.key, false, nonce, 0)
    }

    /// Construct and send extrinsic through rpc
    pub async fn construct_and_send_extrinsic_with(
        &mut self,
        function: impl Into<<Runtime as frame_system::Config>::RuntimeCall>,
    ) -> Result<RpcTransactionOutput, RpcTransactionError> {
        let nonce = self.account_nonce();
        let extrinsic = self.construct_extrinsic(nonce, function);
        self.rpc_handlers.send_transaction(extrinsic.into()).await
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

        let (acknowledgement_sender, mut acknowledgement_receiver) = mpsc::channel(0);

        // Must drop `block_import_acknowledgement_sender` after the notification otherwise the receiver
        // will block forever as there is still a sender not closed.
        {
            let value = (block_number, acknowledgement_sender);
            self.block_importing_notification_subscribers
                .lock()
                .retain(|subscriber| subscriber.unbounded_send(value.clone()).is_ok());
        }

        while acknowledgement_receiver.next().await.is_some() {
            // Wait for all the acknowledgements to finish.
        }

        self.inner.import_block(block).await
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
            async {
                let domain_fut = {
                    let mut futs: Vec<std::pin::Pin<Box<dyn futures::Future<Output = ()>>>> = Vec::new();
                    futs.push(Box::pin($operator_node.wait_for_blocks($count)));
                    $( futs.push( Box::pin( $domain_node.wait_for_blocks($count) ) ); )*
                    futures::future::join_all(futs)
                };
                $primary_node.produce_blocks_with_bundles($count).await?;
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

type BalanceOf<T> = <<T as pallet_transaction_payment::Config>::OnChargeTransaction as pallet_transaction_payment::OnChargeTransaction<T>>::Balance;

fn construct_extrinsic_raw_payload<Client>(
    client: impl AsRef<Client>,
    function: <Runtime as frame_system::Config>::RuntimeCall,
    immortal: bool,
    nonce: u32,
    tip: BalanceOf<Runtime>,
) -> (
    SignedPayload<<Runtime as frame_system::Config>::RuntimeCall, SignedExtra>,
    SignedExtra,
)
where
    BalanceOf<Runtime>: Send + Sync + From<u64> + sp_runtime::FixedPointOperand,
    u64: From<BlockNumberFor<Runtime>>,
    Client: HeaderBackend<subspace_runtime_primitives::opaque::Block>,
{
    let current_block_hash = client.as_ref().info().best_hash;
    let current_block = client.as_ref().info().best_number.saturated_into();
    let genesis_block = client.as_ref().hash(0).unwrap().unwrap();
    let period = u64::from(<<Runtime as frame_system::Config>::BlockHashCount>::get())
        .checked_next_power_of_two()
        .map(|c| c / 2)
        .unwrap_or(2);
    let extra: SignedExtra = (
        frame_system::CheckNonZeroSender::<Runtime>::new(),
        frame_system::CheckSpecVersion::<Runtime>::new(),
        frame_system::CheckTxVersion::<Runtime>::new(),
        frame_system::CheckGenesis::<Runtime>::new(),
        frame_system::CheckMortality::<Runtime>::from(if immortal {
            generic::Era::Immortal
        } else {
            generic::Era::mortal(period, current_block)
        }),
        frame_system::CheckNonce::<Runtime>::from(nonce),
        frame_system::CheckWeight::<Runtime>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip),
    );
    (
        generic::SignedPayload::<
            <Runtime as frame_system::Config>::RuntimeCall,
            SignedExtra,
        >::from_raw(
            function,
            extra.clone(),
            ((), 100, 1, genesis_block, current_block_hash, (), (), ()),
        ),
        extra,
    )
}

/// Construct an extrinsic that can be applied to the test runtime.
fn construct_extrinsic_generic<Client>(
    client: impl AsRef<Client>,
    function: impl Into<<Runtime as frame_system::Config>::RuntimeCall>,
    caller: Sr25519Keyring,
    immortal: bool,
    nonce: u32,
    tip: BalanceOf<Runtime>,
) -> UncheckedExtrinsic
where
    BalanceOf<Runtime>: Send + Sync + From<u64> + sp_runtime::FixedPointOperand,
    u64: From<BlockNumberFor<Runtime>>,
    Client: HeaderBackend<subspace_runtime_primitives::opaque::Block>,
{
    let function = function.into();
    let (raw_payload, extra) =
        construct_extrinsic_raw_payload(client, function.clone(), immortal, nonce, tip);
    let signature = raw_payload.using_encoded(|e| caller.sign(e));
    UncheckedExtrinsic::new_signed(
        function,
        MultiAddress::Id(caller.to_account_id()),
        Signature::Sr25519(signature),
        extra,
    )
}
