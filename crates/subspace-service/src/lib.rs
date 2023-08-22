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

//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.
#![feature(
    impl_trait_in_assoc_type,
    int_roundings,
    type_alias_impl_trait,
    type_changing_struct_update
)]

pub mod dsn;
mod metrics;
pub mod rpc;
mod sync_from_dsn;
pub mod tx_pre_validator;

use crate::dsn::{create_dsn_instance, DsnConfigurationError};
use crate::metrics::NodeMetrics;
use crate::tx_pre_validator::ConsensusChainTxPreValidator;
use cross_domain_message_gossip::cdm_gossip_peers_set_config;
use derive_more::{Deref, DerefMut, Into};
use domain_runtime_primitives::{BlockNumber as DomainNumber, Hash as DomainHash};
pub use dsn::DsnConfig;
use frame_system_rpc_runtime_api::AccountNonceApi;
use futures::channel::oneshot;
use jsonrpsee::RpcModule;
use pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi;
use parking_lot::Mutex;
use sc_basic_authorship::ProposerFactory;
use sc_client_api::execution_extensions::ExtensionsFactory;
use sc_client_api::{
    BlockBackend, BlockchainEvents, ExecutorProvider, HeaderBackend, StateBackendFor,
};
use sc_consensus::{BlockImport, DefaultImportQueue, ImportQueue};
use sc_consensus_slots::SlotProportion;
use sc_consensus_subspace::archiver::{create_subspace_archiver, SegmentHeadersStore};
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::{
    ArchivedSegmentNotification, BlockImportingNotification, NewSlotNotification,
    RewardSigningNotification, SubspaceLink, SubspaceParams, SubspaceSyncOracle,
};
use sc_executor::{NativeElseWasmExecutor, NativeExecutionDispatch};
use sc_network::NetworkService;
use sc_proof_of_time::gossip::{pot_gossip_peers_set_config, PotGossipWorker};
use sc_proof_of_time::{PotComponents, PotConfig, TimeKeeper};
use sc_service::error::Error as ServiceError;
use sc_service::{Configuration, NetworkStarter, SpawnTasksParams, TaskManager};
use sc_subspace_block_relay::{build_consensus_relay, NetworkWrapper};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sp_api::{ApiExt, ConstructRuntimeApi, Metadata, ProvideRuntimeApi, TransactionFor};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderMetadata;
use sp_consensus::Error as ConsensusError;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{FarmerPublicKey, KzgExtension, PosExtension, SubspaceApi};
use sp_core::offchain;
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::transaction::PreValidationObjectApi;
use sp_domains::{DomainsApi, GenerateGenesisStateRoot, GenesisReceiptExtension};
use sp_externalities::Extensions;
use sp_objects::ObjectsApi;
use sp_offchain::OffchainWorkerApi;
use sp_runtime::traits::{Block as BlockT, BlockIdTo, NumberFor};
use sp_session::SessionKeys;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use static_assertions::const_assert;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{PotKey, PotSeed};
use subspace_fraud_proof::verifier_api::VerifierClient;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::Node;
use subspace_proof_of_space::Table;
use subspace_runtime_primitives::opaque::Block;
use subspace_runtime_primitives::{AccountId, Balance, Hash, Index as Nonce};
use subspace_transaction_pool::{FullPool, PreValidateTransaction};
use tracing::{debug, error, info, Instrument};

// There are multiple places where it is assumed that node is running on 64-bit system, refuse to
// compile otherwise
const_assert!(std::mem::size_of::<usize>() >= std::mem::size_of::<u64>());

/// Error type for Subspace service.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// IO error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Address parsing error.
    #[error(transparent)]
    AddrFormatInvalid(#[from] std::net::AddrParseError),

    /// Substrate service error.
    #[error(transparent)]
    Sub(#[from] sc_service::Error),

    /// Substrate consensus error.
    #[error(transparent)]
    Consensus(#[from] sp_consensus::Error),

    /// Telemetry error.
    #[error(transparent)]
    Telemetry(#[from] sc_telemetry::Error),

    /// Prometheus error.
    #[error(transparent)]
    Prometheus(#[from] substrate_prometheus_endpoint::PrometheusError),

    /// Subspace networking (DSN) error.
    #[error(transparent)]
    SubspaceDsn(#[from] DsnConfigurationError),

    /// Other.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

/// Subspace-like full client.
pub type FullClient<RuntimeApi, ExecutorDispatch> =
    sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;

pub type FullBackend = sc_service::TFullBackend<Block>;
pub type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

pub type InvalidTransactionProofVerifier<RuntimeApi, ExecutorDispatch> =
    subspace_fraud_proof::invalid_transaction_proof::InvalidTransactionProofVerifier<
        Block,
        FullClient<RuntimeApi, ExecutorDispatch>,
        Hash,
        NativeElseWasmExecutor<ExecutorDispatch>,
        VerifierClient<FullClient<RuntimeApi, ExecutorDispatch>, Block>,
    >;

pub type InvalidStateTransitionProofVerifier<RuntimeApi, ExecutorDispatch> =
    subspace_fraud_proof::invalid_state_transition_proof::InvalidStateTransitionProofVerifier<
        Block,
        FullClient<RuntimeApi, ExecutorDispatch>,
        NativeElseWasmExecutor<ExecutorDispatch>,
        Hash,
        VerifierClient<FullClient<RuntimeApi, ExecutorDispatch>, Block>,
    >;

pub type FraudProofVerifier<RuntimeApi, ExecutorDispatch> = subspace_fraud_proof::ProofVerifier<
    Block,
    InvalidTransactionProofVerifier<RuntimeApi, ExecutorDispatch>,
    InvalidStateTransitionProofVerifier<RuntimeApi, ExecutorDispatch>,
>;

/// Subspace networking instantiation variant
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SubspaceNetworking {
    /// Use existing networking instance
    Reuse {
        /// Node instance
        node: Node,
        /// Bootstrap nodes used (that can be also sent to the farmer over RPC)
        bootstrap_nodes: Vec<Multiaddr>,
    },
    /// Networking must be instantiated internally
    Create {
        /// Configuration to use for DSN instantiation
        config: DsnConfig,
    },
}

/// Subspace-specific service configuration.
#[derive(Debug, Deref, DerefMut, Into)]
pub struct SubspaceConfiguration {
    /// Base configuration.
    #[deref]
    #[deref_mut]
    #[into]
    pub base: Configuration,
    /// Whether slot notifications need to be present even if node is not responsible for block
    /// authoring.
    pub force_new_slot_notifications: bool,
    /// Subspace networking (DSN).
    pub subspace_networking: SubspaceNetworking,
    /// Enables DSN-sync on startup.
    pub sync_from_dsn: bool,
    /// Use the block request handler implementation from subspace
    /// instead of the default substrate handler.
    pub enable_subspace_block_relay: bool,
}

struct SubspaceExtensionsFactory<PosTable> {
    kzg: Kzg,
    domain_genesis_receipt_ext: Option<Arc<dyn GenerateGenesisStateRoot>>,
    _pos_table: PhantomData<PosTable>,
}

impl<PosTable, Block> ExtensionsFactory<Block> for SubspaceExtensionsFactory<PosTable>
where
    PosTable: Table,
    Block: BlockT,
{
    fn extensions_for(
        &self,
        _block_hash: Block::Hash,
        _block_number: NumberFor<Block>,
        _capabilities: offchain::Capabilities,
    ) -> Extensions {
        let mut exts = Extensions::new();
        exts.register(KzgExtension::new(self.kzg.clone()));
        exts.register(PosExtension::new::<PosTable>());
        if let Some(ext) = self.domain_genesis_receipt_ext.clone() {
            exts.register(GenesisReceiptExtension::new(ext));
        }
        exts
    }
}

/// PoT configuration used in in [`new_partial()`]
// TODO: Better name
pub struct PotPartialConfig {
    /// Is this node a Timekeeper
    pub is_timekeeper: bool,
    /// Initial PoT key
    pub initial_key: PotKey,
}

/// Other partial components returned by [`new_partial()`]
pub struct OtherPartialComponents<RuntimeApi, ExecutorDispatch>
where
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi, ExecutorDispatch>>
        + Send
        + Sync
        + 'static,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
{
    /// Subspace block import
    pub block_import: Box<
        dyn BlockImport<
                Block,
                Error = ConsensusError,
                Transaction = TransactionFor<FullClient<RuntimeApi, ExecutorDispatch>, Block>,
            > + Send
            + Sync,
    >,
    /// Subspace link
    pub subspace_link: SubspaceLink<Block>,
    /// Segment headers store
    pub segment_headers_store: SegmentHeadersStore<FullClient<RuntimeApi, ExecutorDispatch>>,
    /// Telemetry
    pub telemetry: Option<Telemetry>,
    /// PoT components
    pub pot_components: Option<PotComponents>,
}

type PartialComponents<RuntimeApi, ExecutorDispatch> = sc_service::PartialComponents<
    FullClient<RuntimeApi, ExecutorDispatch>,
    FullBackend,
    FullSelectChain,
    DefaultImportQueue<Block, FullClient<RuntimeApi, ExecutorDispatch>>,
    FullPool<
        Block,
        FullClient<RuntimeApi, ExecutorDispatch>,
        ConsensusChainTxPreValidator<
            Block,
            FullClient<RuntimeApi, ExecutorDispatch>,
            FraudProofVerifier<RuntimeApi, ExecutorDispatch>,
        >,
    >,
    OtherPartialComponents<RuntimeApi, ExecutorDispatch>,
>;

/// Creates `PartialComponents` for Subspace client.
#[allow(clippy::type_complexity)]
pub fn new_partial<PosTable, RuntimeApi, ExecutorDispatch>(
    config: &Configuration,
    construct_domain_genesis_block_builder: Option<
        &dyn Fn(
            Arc<FullBackend>,
            NativeElseWasmExecutor<ExecutorDispatch>,
        ) -> Arc<dyn GenerateGenesisStateRoot>,
    >,
    maybe_pot_config: Option<PotPartialConfig>,
) -> Result<PartialComponents<RuntimeApi, ExecutorDispatch>, ServiceError>
where
    PosTable: Table,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi, ExecutorDispatch>>
        + Send
        + Sync
        + 'static,
    RuntimeApi::RuntimeApi: ApiExt<Block, StateBackend = StateBackendFor<FullBackend, Block>>
        + Metadata<Block>
        + BlockBuilder<Block>
        + OffchainWorkerApi<Block>
        + SessionKeys<Block>
        + TaggedTransactionQueue<Block>
        + SubspaceApi<Block, FarmerPublicKey>
        + DomainsApi<Block, DomainNumber, DomainHash>
        + ObjectsApi<Block>
        + PreValidationObjectApi<Block, DomainNumber, DomainHash>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
{
    let telemetry = config
        .telemetry_endpoints
        .clone()
        .filter(|x| !x.is_empty())
        .map(|endpoints| -> Result<_, sc_telemetry::Error> {
            let worker = TelemetryWorker::new(16)?;
            let telemetry = worker.handle().new_telemetry(endpoints);
            Ok((worker, telemetry))
        })
        .transpose()?;

    let executor = sc_service::new_native_or_wasm_executor(config);

    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, _>(
            config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            executor.clone(),
        )?;

    let kzg = Kzg::new(embedded_kzg_settings());

    let domain_genesis_receipt_ext =
        construct_domain_genesis_block_builder.map(|f| f(backend.clone(), executor.clone()));

    client
        .execution_extensions()
        .set_extensions_factory(SubspaceExtensionsFactory::<PosTable> {
            kzg: kzg.clone(),
            domain_genesis_receipt_ext,
            _pos_table: PhantomData,
        });

    let client = Arc::new(client);

    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let invalid_transaction_proof_verifier = InvalidTransactionProofVerifier::new(
        client.clone(),
        Arc::new(executor.clone()),
        VerifierClient::new(client.clone()),
    );

    let invalid_state_transition_proof_verifier = InvalidStateTransitionProofVerifier::new(
        client.clone(),
        executor,
        VerifierClient::new(client.clone()),
    );

    let proof_verifier = subspace_fraud_proof::ProofVerifier::new(
        Arc::new(invalid_transaction_proof_verifier),
        Arc::new(invalid_state_transition_proof_verifier),
    );

    let tx_pre_validator = ConsensusChainTxPreValidator::new(
        client.clone(),
        Box::new(task_manager.spawn_handle()),
        proof_verifier.clone(),
    );
    let transaction_pool = subspace_transaction_pool::new_full(
        config,
        &task_manager,
        client.clone(),
        tx_pre_validator,
    );

    let segment_headers_store = SegmentHeadersStore::new(client.clone())
        .map_err(|error| ServiceError::Application(error.into()))?;
    let fraud_proof_block_import =
        sc_consensus_fraud_proof::block_import(client.clone(), client.clone(), proof_verifier);

    let pot_components = maybe_pot_config.map(|pot_config| {
        PotComponents::new(
            pot_config.is_timekeeper,
            // TODO: fill proper values. These are set to use less
            // CPU and take less than 1 sec to produce per proof
            // during the initial testing.
            PotConfig {
                initial_seed: PotSeed::from_genesis_block_hash(client.info().genesis_hash.into()),
                initial_key: pot_config.initial_key,
                randomness_update_interval_blocks: 18,
                injection_depth_blocks: 90,
                global_randomness_reveal_lag_slots: 6,
                pot_injection_lag_slots: 6,
                max_future_slots: 10,
                pot_iterations: NonZeroU32::new(4 * 1_000).expect("Not zero; qed"),
            },
        )
    });

    let (block_import, subspace_link) = sc_consensus_subspace::block_import::<
        PosTable,
        _,
        _,
        _,
        _,
        _,
    >(
        sc_consensus_subspace::slot_duration(&*client)?,
        fraud_proof_block_import,
        client.clone(),
        kzg.clone(),
        {
            let client = client.clone();

            move |parent_hash, subspace_link: SubspaceLink<Block>| {
                let client = client.clone();

                async move {
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                    // TODO: Would be nice if the whole header was passed in here
                    let parent_block_number = client
                        .header(parent_hash)?
                        .expect("Parent header must always exist when block is created; qed")
                        .number;

                    let subspace_inherents =
                        sp_consensus_subspace::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                            *timestamp,
                            subspace_link.slot_duration(),
                            subspace_link.segment_headers_for_block(parent_block_number + 1),
                        );

                    Ok((timestamp, subspace_inherents))
                }
            }
        },
        segment_headers_store.clone(),
        pot_components
            .as_ref()
            .map(|component| component.consensus_state()),
    )?;

    let slot_duration = subspace_link.slot_duration();
    let import_queue = sc_consensus_subspace::import_queue::<PosTable, _, _, _, _, _>(
        block_import.clone(),
        None,
        client.clone(),
        kzg,
        select_chain.clone(),
        move || {
            let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

            Slot::from_timestamp(*timestamp, slot_duration)
        },
        &task_manager.spawn_essential_handle(),
        config.prometheus_registry(),
        telemetry.as_ref().map(|x| x.handle()),
        config.role.is_authority(),
    )?;

    let other = OtherPartialComponents {
        block_import: Box::new(block_import),
        subspace_link,
        segment_headers_store,
        telemetry,
        pot_components,
    };

    Ok(PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other,
    })
}

/// Full node along with some other components.
pub struct NewFull<Client, TxPreValidator>
where
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + BlockIdTo<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + 'static,
    Client::Api: TaggedTransactionQueue<Block>
        + DomainsApi<Block, DomainNumber, DomainHash>
        + PreValidationObjectApi<Block, DomainNumber, DomainHash>,
    TxPreValidator: PreValidateTransaction<Block = Block> + Send + Sync + Clone + 'static,
{
    /// Task manager.
    pub task_manager: TaskManager,
    /// Full client.
    pub client: Arc<Client>,
    /// Chain selection rule.
    pub select_chain: FullSelectChain,
    /// Network service.
    pub network_service: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
    /// Sync service.
    pub sync_service: Arc<sc_network_sync::SyncingService<Block>>,
    /// RPC handlers.
    pub rpc_handlers: sc_service::RpcHandlers,
    /// Full client backend.
    pub backend: Arc<FullBackend>,
    /// New slot stream.
    pub new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    /// Block signing stream.
    pub reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    /// Stream of notifications about blocks about to be imported.
    pub block_importing_notification_stream:
        SubspaceNotificationStream<BlockImportingNotification<Block>>,
    /// Archived segment stream.
    pub archived_segment_notification_stream:
        SubspaceNotificationStream<ArchivedSegmentNotification>,
    /// Network starter.
    pub network_starter: NetworkStarter,
    /// Transaction pool.
    pub transaction_pool: Arc<FullPool<Block, Client, TxPreValidator>>,
}

type FullNode<RuntimeApi, ExecutorDispatch> = NewFull<
    FullClient<RuntimeApi, ExecutorDispatch>,
    ConsensusChainTxPreValidator<
        Block,
        FullClient<RuntimeApi, ExecutorDispatch>,
        FraudProofVerifier<RuntimeApi, ExecutorDispatch>,
    >,
>;

/// Builds a new service for a full client.
pub async fn new_full<PosTable, RuntimeApi, ExecutorDispatch>(
    config: SubspaceConfiguration,
    partial_components: PartialComponents<RuntimeApi, ExecutorDispatch>,
    enable_rpc_extensions: bool,
    block_proposal_slot_portion: SlotProportion,
) -> Result<FullNode<RuntimeApi, ExecutorDispatch>, Error>
where
    PosTable: Table,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi, ExecutorDispatch>>
        + Send
        + Sync
        + 'static,
    RuntimeApi::RuntimeApi: ApiExt<Block, StateBackend = StateBackendFor<FullBackend, Block>>
        + Metadata<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + BlockBuilder<Block>
        + OffchainWorkerApi<Block>
        + SessionKeys<Block>
        + TaggedTransactionQueue<Block>
        + TransactionPaymentApi<Block, Balance>
        + SubspaceApi<Block, FarmerPublicKey>
        + DomainsApi<Block, DomainNumber, DomainHash>
        + ObjectsApi<Block>
        + PreValidationObjectApi<Block, DomainNumber, DomainHash>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
{
    let PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other,
    } = partial_components;
    let OtherPartialComponents {
        block_import,
        subspace_link,
        segment_headers_store,
        mut telemetry,
        pot_components,
    } = other;

    let (node, bootstrap_nodes) = match config.subspace_networking.clone() {
        SubspaceNetworking::Reuse {
            node,
            bootstrap_nodes,
        } => (node, bootstrap_nodes),
        SubspaceNetworking::Create { config: dsn_config } => {
            let dsn_protocol_version = hex::encode(client.chain_info().genesis_hash);

            debug!(
                chain_type=?config.chain_spec.chain_type(),
                genesis_hash=%hex::encode(client.chain_info().genesis_hash),
                "Setting DSN protocol version..."
            );

            let (node, mut node_runner) = create_dsn_instance(
                dsn_protocol_version,
                dsn_config.clone(),
                segment_headers_store.clone(),
            )?;

            info!("Subspace networking initialized: Node ID is {}", node.id());

            node.on_new_listener(Arc::new({
                let node = node.clone();

                move |address| {
                    info!(
                        "DSN listening on {}",
                        address.clone().with(Protocol::P2p(node.id()))
                    );
                }
            }))
            .detach();

            task_manager
                .spawn_essential_handle()
                .spawn_essential_blocking(
                    "node-runner",
                    Some("subspace-networking"),
                    Box::pin(
                        async move {
                            node_runner.run().await;
                        }
                        .in_current_span(),
                    ),
                );

            (node, dsn_config.bootstrap_nodes)
        }
    };

    let dsn_bootstrap_nodes = {
        // Fall back to node itself as bootstrap node for DSN so farmer always has someone to
        // connect to
        if bootstrap_nodes.is_empty() {
            let (node_address_sender, node_address_receiver) = oneshot::channel();
            let _handler = node.on_new_listener(Arc::new({
                let node_address_sender = Mutex::new(Some(node_address_sender));

                move |address| {
                    if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                        if let Some(node_address_sender) = node_address_sender.lock().take() {
                            if let Err(err) = node_address_sender.send(address.clone()) {
                                debug!(?err, "Couldn't send a node address to the channel.");
                            }
                        }
                    }
                }
            }));

            let mut node_listeners = node.listeners();

            if node_listeners.is_empty() {
                let Ok(listener) = node_address_receiver.await else {
                    return Err(Error::Other(
                        "Oneshot receiver dropped before DSN node listener was ready"
                            .to_string()
                            .into(),
                    ));
                };

                node_listeners = vec![listener];
            }

            node_listeners.iter_mut().for_each(|multiaddr| {
                multiaddr.push(Protocol::P2p(node.id()));
            });

            node_listeners
        } else {
            bootstrap_nodes.clone()
        }
    };

    let import_queue_service = import_queue.service();
    let network_wrapper = Arc::new(NetworkWrapper::default());
    let block_relay = if config.enable_subspace_block_relay {
        Some(build_consensus_relay(
            network_wrapper.clone(),
            client.clone(),
            transaction_pool.clone(),
            task_manager.spawn_handle(),
        ))
    } else {
        None
    };
    let mut net_config = sc_network::config::FullNetworkConfiguration::new(&config.network);
    net_config.add_notification_protocol(cdm_gossip_peers_set_config());
    net_config.add_notification_protocol(pot_gossip_peers_set_config());
    let sync_mode = Arc::clone(&net_config.network_config.sync_mode);
    let (network_service, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            net_config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            block_announce_validator_builder: None,
            warp_sync_params: None,
            block_relay,
        })?;

    let subspace_sync_oracle =
        SubspaceSyncOracle::new(config.force_authoring, sync_service.clone());

    let subspace_archiver = create_subspace_archiver(
        segment_headers_store.clone(),
        &subspace_link,
        client.clone(),
        subspace_sync_oracle.clone(),
        telemetry.as_ref().map(|telemetry| telemetry.handle()),
    );

    task_manager
        .spawn_essential_handle()
        .spawn_essential_blocking("subspace-archiver", None, Box::pin(subspace_archiver));

    if config.enable_subspace_block_relay {
        network_wrapper.set(network_service.clone());
    }
    if config.sync_from_dsn {
        let (observer, worker) = sync_from_dsn::create_observer_and_worker(
            segment_headers_store.clone(),
            Arc::clone(&network_service),
            node.clone(),
            Arc::clone(&client),
            import_queue_service,
            sync_mode,
            subspace_link.kzg().clone(),
        );
        task_manager
            .spawn_handle()
            .spawn("observer", Some("sync-from-dsn"), observer);
        task_manager
            .spawn_essential_handle()
            .spawn_essential_blocking(
                "worker",
                Some("sync-from-dsn"),
                Box::pin(async move {
                    if let Err(error) = worker.await {
                        error!(%error, "Sync from DSN exited with an error");
                    }
                }),
            );
    }

    if let Some(registry) = config.prometheus_registry().as_ref() {
        match NodeMetrics::new(
            client.clone(),
            client.import_notification_stream(),
            registry,
        ) {
            Ok(node_metrics) => {
                task_manager.spawn_handle().spawn(
                    "node_metrics",
                    None,
                    Box::pin(async move {
                        node_metrics.run().await;
                    }),
                );
            }
            Err(err) => {
                error!("Failed to initialize node metrics: {err:?}");
            }
        }
    }

    if config.offchain_worker.enabled {
        sc_service::build_offchain_workers(
            &config,
            task_manager.spawn_handle(),
            client.clone(),
            network_service.clone(),
        );
    }

    let backoff_authoring_blocks: Option<()> = None;
    let prometheus_registry = config.prometheus_registry().cloned();

    let new_slot_notification_stream = subspace_link.new_slot_notification_stream();
    let reward_signing_notification_stream = subspace_link.reward_signing_notification_stream();
    let block_importing_notification_stream = subspace_link.block_importing_notification_stream();
    let archived_segment_notification_stream = subspace_link.archived_segment_notification_stream();

    if config.role.is_authority() || config.force_new_slot_notifications {
        let pot_consensus = pot_components
            .as_ref()
            .map(|component| component.consensus_state());
        if let Some(components) = pot_components {
            let pot_gossip_worker = PotGossipWorker::<Block>::new(
                &components,
                network_service.clone(),
                sync_service.clone(),
            );
            let gossip_sender = pot_gossip_worker.gossip_sender();
            task_manager.spawn_essential_handle().spawn_blocking(
                "pot-gossip-worker",
                Some("pot"),
                async move {
                    pot_gossip_worker.run().await;
                },
            );

            if components.is_time_keeper() {
                let time_keeper = TimeKeeper::new(
                    &components,
                    client.clone(),
                    subspace_link.slot_duration().as_duration(),
                    gossip_sender,
                );

                task_manager.spawn_essential_handle().spawn_blocking(
                    "subspace-proof-of-time-time-keeper",
                    Some("pot"),
                    async move {
                        time_keeper.run().await;
                    },
                );
            }
        }

        let proposer_factory = ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool.clone(),
            prometheus_registry.as_ref(),
            telemetry.as_ref().map(|x| x.handle()),
        );

        let subspace_config = SubspaceParams {
            client: client.clone(),
            select_chain: select_chain.clone(),
            env: proposer_factory,
            block_import,
            sync_oracle: subspace_sync_oracle.clone(),
            justification_sync_link: sync_service.clone(),
            create_inherent_data_providers: {
                let client = client.clone();
                let subspace_link = subspace_link.clone();

                move |parent_hash, ()| {
                    let client = client.clone();
                    let subspace_link = subspace_link.clone();

                    async move {
                        let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                        // TODO: Would be nice if the whole header was passed in here
                        let parent_block_number = client
                            .header(parent_hash)?
                            .expect("Parent header must always exist when block is created; qed")
                            .number;

                        let subspace_inherents =
                            sp_consensus_subspace::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                                *timestamp,
                                subspace_link.slot_duration(),
                                subspace_link.segment_headers_for_block(parent_block_number + 1),
                            );

                        Ok((subspace_inherents, timestamp))
                    }
                }
            },
            force_authoring: config.force_authoring,
            backoff_authoring_blocks,
            subspace_link: subspace_link.clone(),
            segment_headers_store: segment_headers_store.clone(),
            block_proposal_slot_portion,
            max_block_proposal_slot_portion: None,
            telemetry: None,
            proof_of_time: pot_consensus,
        };

        let subspace =
            sc_consensus_subspace::start_subspace::<PosTable, _, _, _, _, _, _, _, _, _, _, _>(
                subspace_config,
            )?;

        // Subspace authoring task is considered essential, i.e. if it fails we take down the
        // service with it.
        task_manager.spawn_essential_handle().spawn_blocking(
            "subspace-proposer",
            Some("block-authoring"),
            subspace,
        );
    }

    let rpc_handlers = sc_service::spawn_tasks(SpawnTasksParams {
        network: network_service.clone(),
        client: client.clone(),
        keystore: keystore_container.keystore(),
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        rpc_builder: if enable_rpc_extensions {
            let client = client.clone();
            let new_slot_notification_stream = new_slot_notification_stream.clone();
            let reward_signing_notification_stream = reward_signing_notification_stream.clone();
            let archived_segment_notification_stream = archived_segment_notification_stream.clone();
            let transaction_pool = transaction_pool.clone();
            let chain_spec = config.chain_spec.cloned_box();

            Box::new(move |deny_unsafe, subscription_executor| {
                let deps = rpc::FullDeps {
                    client: client.clone(),
                    pool: transaction_pool.clone(),
                    chain_spec: chain_spec.cloned_box(),
                    deny_unsafe,
                    subscription_executor,
                    new_slot_notification_stream: new_slot_notification_stream.clone(),
                    reward_signing_notification_stream: reward_signing_notification_stream.clone(),
                    archived_segment_notification_stream: archived_segment_notification_stream
                        .clone(),
                    dsn_bootstrap_nodes: dsn_bootstrap_nodes.clone(),
                    segment_headers_store: segment_headers_store.clone(),
                    sync_oracle: subspace_sync_oracle.clone(),
                    kzg: subspace_link.kzg().clone(),
                };

                rpc::create_full(deps).map_err(Into::into)
            })
        } else {
            Box::new(|_, _| Ok(RpcModule::new(())))
        },
        backend: backend.clone(),
        system_rpc_tx,
        config: config.into(),
        telemetry: telemetry.as_mut(),
        tx_handler_controller,
        sync_service: sync_service.clone(),
    })?;

    Ok(NewFull {
        task_manager,
        client,
        select_chain,
        network_service,
        sync_service,
        rpc_handlers,
        backend,
        new_slot_notification_stream,
        reward_signing_notification_stream,
        block_importing_notification_stream,
        archived_segment_notification_stream,
        network_starter,
        transaction_pool,
    })
}
