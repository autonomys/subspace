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
#![feature(type_changing_struct_update)]

mod dsn;
pub mod piece_cache;
pub mod rpc;

use crate::dsn::create_dsn_instance;
use crate::piece_cache::PieceCache;
use derive_more::{Deref, DerefMut, Into};
use domain_runtime_primitives::Hash as DomainHash;
use dsn::start_dsn_archiver;
pub use dsn::DsnConfig;
use frame_system_rpc_runtime_api::AccountNonceApi;
use futures::channel::oneshot;
use futures::StreamExt;
use jsonrpsee::RpcModule;
use pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi;
use sc_basic_authorship::ProposerFactory;
use sc_client_api::{BlockBackend, HeaderBackend, StateBackendFor};
use sc_consensus::{BlockImport, DefaultImportQueue};
use sc_consensus_slots::SlotProportion;
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::{
    ArchivedSegmentNotification, ImportedBlockNotification, NewSlotNotification,
    RewardSigningNotification, SubspaceLink, SubspaceParams,
};
use sc_executor::{NativeElseWasmExecutor, NativeExecutionDispatch};
use sc_service::error::Error as ServiceError;
use sc_service::{
    Configuration, NetworkStarter, PartialComponents, SpawnTaskHandle, SpawnTasksParams,
    TaskManager,
};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sp_api::{ApiExt, ConstructRuntimeApi, Metadata, ProvideRuntimeApi, TransactionFor};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderMetadata;
use sp_consensus::Error as ConsensusError;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi};
use sp_core::traits::SpawnEssentialNamed;
use sp_domains::transaction::PreValidationObjectApi;
use sp_domains::ExecutorApi;
use sp_objects::ObjectsApi;
use sp_offchain::OffchainWorkerApi;
use sp_runtime::traits::{Block as BlockT, BlockIdTo};
use sp_session::SessionKeys;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use subspace_core_primitives::PIECES_IN_SEGMENT;
use subspace_fraud_proof::VerifyFraudProof;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::{peer_id, Node};
use subspace_runtime_primitives::opaque::Block;
use subspace_runtime_primitives::{AccountId, Balance, Hash, Index as Nonce};
use subspace_transaction_pool::FullPool;
use tracing::{error, info, Instrument};

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
    SubspaceDsn(#[from] subspace_networking::CreationError),

    /// Other.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

/// Subspace-like full client.
pub type FullClient<RuntimeApi, ExecutorDispatch> =
    sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;

pub type FullBackend = sc_service::TFullBackend<Block>;
pub type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

pub type FraudProofVerifier<RuntimeApi, ExecutorDispatch> = subspace_fraud_proof::ProofVerifier<
    Block,
    FullClient<RuntimeApi, ExecutorDispatch>,
    FullBackend,
    NativeElseWasmExecutor<ExecutorDispatch>,
    SpawnTaskHandle,
    Hash,
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
        /// Piece cache size in bytes
        piece_cache_size: u64,
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
    /// Max number of segments that can be published concurrently.
    pub segment_publish_concurrency: NonZeroUsize,
}

/// Creates `PartialComponents` for Subspace client.
#[allow(clippy::type_complexity)]
pub fn new_partial<RuntimeApi, ExecutorDispatch>(
    config: &Configuration,
) -> Result<
    PartialComponents<
        FullClient<RuntimeApi, ExecutorDispatch>,
        FullBackend,
        FullSelectChain,
        DefaultImportQueue<Block, FullClient<RuntimeApi, ExecutorDispatch>>,
        FullPool<
            Block,
            FullClient<RuntimeApi, ExecutorDispatch>,
            FraudProofVerifier<RuntimeApi, ExecutorDispatch>,
        >,
        (
            impl BlockImport<
                Block,
                Error = ConsensusError,
                Transaction = TransactionFor<FullClient<RuntimeApi, ExecutorDispatch>, Block>,
            >,
            SubspaceLink<Block>,
            Option<Telemetry>,
        ),
    >,
    ServiceError,
>
where
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
        + ExecutorApi<Block, DomainHash>
        + ObjectsApi<Block>
        + PreValidationObjectApi<Block, domain_runtime_primitives::Hash>
        + SubspaceApi<Block, FarmerPublicKey>,
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

    let executor = NativeElseWasmExecutor::<ExecutorDispatch>::new(
        config.wasm_method,
        config.default_heap_pages,
        config.max_runtime_instances,
        config.runtime_cache_size,
    );

    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, _>(
            config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            executor.clone(),
        )?;

    let client = Arc::new(client);

    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let proof_verifier = subspace_fraud_proof::ProofVerifier::new(
        client.clone(),
        backend.clone(),
        executor,
        task_manager.spawn_handle(),
    );
    let transaction_pool = subspace_transaction_pool::new_full(
        config,
        &task_manager,
        client.clone(),
        proof_verifier.clone(),
    );

    let fraud_proof_block_import =
        sc_consensus_fraud_proof::block_import(client.clone(), client.clone(), proof_verifier);

    let (block_import, subspace_link) = sc_consensus_subspace::block_import(
        sc_consensus_subspace::slot_duration(&*client)?,
        fraud_proof_block_import,
        client.clone(),
        {
            let client = client.clone();

            move |parent_hash, subspace_link: SubspaceLink<Block>| {
                let client = client.clone();

                async move {
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                    // TODO: Would be nice if the whole header was passed in here
                    let parent_block_number = client
                        .header(parent_hash)
                        .expect("Parent header must always exist when block is created; qed")
                        .expect("Parent header must always exist when block is created; qed")
                        .number;

                    let subspace_inherents =
                        sp_consensus_subspace::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                            *timestamp,
                            subspace_link.slot_duration(),
                            subspace_link.root_blocks_for_block(parent_block_number + 1),
                        );

                    Ok((timestamp, subspace_inherents))
                }
            }
        },
    )?;

    let slot_duration = subspace_link.slot_duration();
    let import_queue = sc_consensus_subspace::import_queue(
        block_import.clone(),
        None,
        client.clone(),
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

    Ok(PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (block_import, subspace_link, telemetry),
    })
}

/// Full node along with some other components.
pub struct NewFull<Client, Verifier>
where
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + BlockIdTo<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + 'static,
    Client::Api: TaggedTransactionQueue<Block>
        + ExecutorApi<Block, DomainHash>
        + PreValidationObjectApi<Block, domain_runtime_primitives::Hash>,
    Verifier: VerifyFraudProof + Clone + Send + Sync + 'static,
{
    /// Task manager.
    pub task_manager: TaskManager,
    /// Full client.
    pub client: Arc<Client>,
    /// Chain selection rule.
    pub select_chain: FullSelectChain,
    /// Network.
    pub network: Arc<sc_network::NetworkService<Block, <Block as BlockT>::Hash>>,
    /// RPC handlers.
    pub rpc_handlers: sc_service::RpcHandlers,
    /// Full client backend.
    pub backend: Arc<FullBackend>,
    /// New slot stream.
    pub new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    /// Block signing stream.
    pub reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    /// Imported block stream.
    pub imported_block_notification_stream:
        SubspaceNotificationStream<ImportedBlockNotification<Block>>,
    /// Archived segment stream.
    pub archived_segment_notification_stream:
        SubspaceNotificationStream<ArchivedSegmentNotification>,
    /// Network starter.
    pub network_starter: NetworkStarter,
    /// Transaction pool.
    pub transaction_pool: Arc<FullPool<Block, Client, Verifier>>,
}

type FullNode<RuntimeApi, ExecutorDispatch> = NewFull<
    FullClient<RuntimeApi, ExecutorDispatch>,
    FraudProofVerifier<RuntimeApi, ExecutorDispatch>,
>;

/// Builds a new service for a full client.
#[allow(clippy::type_complexity)]
pub async fn new_full<RuntimeApi, ExecutorDispatch, I>(
    config: SubspaceConfiguration,
    partial_components: PartialComponents<
        FullClient<RuntimeApi, ExecutorDispatch>,
        FullBackend,
        FullSelectChain,
        DefaultImportQueue<Block, FullClient<RuntimeApi, ExecutorDispatch>>,
        FullPool<
            Block,
            FullClient<RuntimeApi, ExecutorDispatch>,
            FraudProofVerifier<RuntimeApi, ExecutorDispatch>,
        >,
        (I, SubspaceLink<Block>, Option<Telemetry>),
    >,

    enable_rpc_extensions: bool,
    block_proposal_slot_portion: SlotProportion,
) -> Result<FullNode<RuntimeApi, ExecutorDispatch>, Error>
where
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
        + ExecutorApi<Block, DomainHash>
        + ObjectsApi<Block>
        + PreValidationObjectApi<Block, domain_runtime_primitives::Hash>
        + SubspaceApi<Block, FarmerPublicKey>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
    I: BlockImport<
            Block,
            Error = ConsensusError,
            Transaction = TransactionFor<FullClient<RuntimeApi, ExecutorDispatch>, Block>,
        > + Send
        + Sync
        + 'static,
{
    let PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (block_import, subspace_link, mut telemetry),
    } = partial_components;

    let (node, bootstrap_nodes) = match config.subspace_networking.clone() {
        SubspaceNetworking::Reuse {
            node,
            bootstrap_nodes,
        } => (node, bootstrap_nodes),
        SubspaceNetworking::Create {
            config,
            piece_cache_size,
        } => {
            let piece_cache =
                PieceCache::new(client.clone(), piece_cache_size, peer_id(&config.keypair));

            // Start before archiver below, so we don't have potential race condition and miss pieces
            task_manager
                .spawn_handle()
                .spawn_blocking("subspace-piece-cache", None, {
                    let mut piece_cache = piece_cache.clone();
                    let mut archived_segment_notification_stream = subspace_link
                        .archived_segment_notification_stream()
                        .subscribe();

                    async move {
                        while let Some(archived_segment_notification) =
                            archived_segment_notification_stream.next().await
                        {
                            let segment_index = archived_segment_notification
                                .archived_segment
                                .root_block
                                .segment_index();
                            if let Err(error) = piece_cache.add_pieces(
                                segment_index * u64::from(PIECES_IN_SEGMENT),
                                &archived_segment_notification.archived_segment.pieces,
                            ) {
                                error!(
                                    %segment_index,
                                    %error,
                                    "Failed to store pieces for segment in cache"
                                );
                            }
                        }
                    }
                });

            let (node, mut node_runner) =
                create_dsn_instance::<Block, _>(config.clone(), piece_cache.clone())
                    .instrument(tracing::info_span!(
                        sc_tracing::logging::PREFIX_LOG_SPAN,
                        name = "DSN"
                    ))
                    .await?;

            info!("Subspace networking initialized: Node ID is {}", node.id());

            task_manager.spawn_essential_handle().spawn_essential(
                "node-runner",
                Some("subspace-networking"),
                Box::pin(
                    async move {
                        node_runner.run().await;
                    }
                    .in_current_span(),
                ),
            );

            (node, config.bootstrap_nodes)
        }
    };

    let dsn_archiving_fut = start_dsn_archiver(
        subspace_link
            .archived_segment_notification_stream()
            .subscribe(),
        node.clone(),
        task_manager.spawn_handle(),
        config.segment_publish_concurrency,
    );

    task_manager.spawn_essential_handle().spawn_essential(
        "archiver",
        Some("subspace-networking"),
        Box::pin(dsn_archiving_fut.in_current_span()),
    );

    let dsn_bootstrap_nodes = {
        // Fall back to node itself as bootstrap node for DSN so farmer always has someone to
        // connect to
        if bootstrap_nodes.is_empty() {
            let (node_address_sender, node_address_receiver) = oneshot::channel();
            let _handler = node.on_new_listener(Arc::new({
                let node_address_sender = Mutex::new(Some(node_address_sender));

                move |address| {
                    if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                        if let Some(node_address_sender) = node_address_sender
                            .lock()
                            .expect("Must not be poisoned here")
                            .take()
                        {
                            node_address_sender.send(address.clone()).unwrap();
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
                multiaddr.push(Protocol::P2p(node.id().into()));
            });

            node_listeners
        } else {
            bootstrap_nodes.clone()
        }
    };

    sc_consensus_subspace::start_subspace_archiver(
        &subspace_link,
        client.clone(),
        telemetry.as_ref().map(|telemetry| telemetry.handle()),
        &task_manager.spawn_essential_handle(),
    );

    let (network, system_rpc_tx, tx_handler_controller, network_starter) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            block_announce_validator_builder: None,
            warp_sync: None,
        })?;

    if config.offchain_worker.enabled {
        sc_service::build_offchain_workers(
            &config,
            task_manager.spawn_handle(),
            client.clone(),
            network.clone(),
        );
    }

    let backoff_authoring_blocks: Option<()> = None;
    let prometheus_registry = config.prometheus_registry().cloned();

    let new_slot_notification_stream = subspace_link.new_slot_notification_stream();
    let reward_signing_notification_stream = subspace_link.reward_signing_notification_stream();
    let imported_block_notification_stream = subspace_link.imported_block_notification_stream();
    let archived_segment_notification_stream = subspace_link.archived_segment_notification_stream();

    if config.role.is_authority() || config.force_new_slot_notifications {
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
            sync_oracle: network.clone(),
            justification_sync_link: network.clone(),
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
                                subspace_link.root_blocks_for_block(parent_block_number + 1),
                            );

                        Ok((subspace_inherents, timestamp))
                    }
                }
            },
            force_authoring: config.force_authoring,
            backoff_authoring_blocks,
            subspace_link: subspace_link.clone(),
            block_proposal_slot_portion,
            max_block_proposal_slot_portion: None,
            telemetry: None,
        };

        let subspace = sc_consensus_subspace::start_subspace(subspace_config)?;

        // Subspace authoring task is considered essential, i.e. if it fails we take down the
        // service with it.
        task_manager.spawn_essential_handle().spawn_blocking(
            "subspace-proposer",
            Some("block-authoring"),
            subspace,
        );
    }

    let rpc_handlers = sc_service::spawn_tasks(SpawnTasksParams {
        network: network.clone(),
        client: client.clone(),
        keystore: keystore_container.sync_keystore(),
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
                    subspace_link: subspace_link.clone(),
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
    })?;

    Ok(NewFull {
        task_manager,
        client,
        select_chain,
        network,
        rpc_handlers,
        backend,
        new_slot_notification_stream,
        reward_signing_notification_stream,
        imported_block_notification_stream,
        archived_segment_notification_stream,
        network_starter,
        transaction_pool,
    })
}
