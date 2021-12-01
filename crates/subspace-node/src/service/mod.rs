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

mod overseer;

use sc_client_api::ExecutorProvider;
use sc_consensus_slots::SlotProportion;
use sc_executor::NativeElseWasmExecutor;
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use subspace_runtime::opaque::BlockId;
use subspace_runtime::{self, opaque::Block, RuntimeApi};

use overseer::{OverseerGen, OverseerGenArgs, RealOverseerGen};
use polkadot_overseer::{Handle, Overseer, OverseerConnector, OverseerHandle};

pub use overseer::IsCollator;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    AddrFormatInvalid(#[from] std::net::AddrParseError),

    #[error(transparent)]
    Sub(#[from] sc_service::Error),

    #[error(transparent)]
    Blockchain(#[from] sp_blockchain::Error),

    #[error(transparent)]
    Consensus(#[from] sp_consensus::Error),

    #[error("Failed to create an overseer")]
    Overseer(#[from] polkadot_overseer::SubsystemError),

    #[error(transparent)]
    Prometheus(#[from] substrate_prometheus_endpoint::PrometheusError),
    // #[error(transparent)]
    // Telemetry(#[from] telemetry::Error),

    // #[error(transparent)]
    // Jaeger(#[from] polkadot_subsystem::jaeger::JaegerError),
}

/// Subspace native executor instance.
pub struct ExecutorDispatch;

impl sc_executor::NativeExecutionDispatch for ExecutorDispatch {
    /// Only enable the benchmarking host functions when we actually want to benchmark.
    #[cfg(feature = "runtime-benchmarks")]
    type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
    /// Otherwise we only use the default Substrate host functions.
    #[cfg(not(feature = "runtime-benchmarks"))]
    type ExtendHostFunctions = ();

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        subspace_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        subspace_runtime::native_version()
    }
}

/// Subspace full client.
pub type FullClient =
    sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

/// Creates `PartialComponents` for Subspace client.
#[allow(clippy::type_complexity)]
pub fn new_partial(
    config: &Configuration,
) -> Result<
    sc_service::PartialComponents<
        FullClient,
        FullBackend,
        FullSelectChain,
        sc_consensus::DefaultImportQueue<Block, FullClient>,
        sc_transaction_pool::FullPool<Block, FullClient>,
        (
            sc_consensus_subspace::SubspaceBlockImport<Block, FullClient, Arc<FullClient>>,
            sc_consensus_subspace::SubspaceLink<Block>,
            Option<Telemetry>,
        ),
    >,
    ServiceError,
> {
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
    );

    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, _>(
            config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            executor,
        )?;
    let client = Arc::new(client);

    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        config.prometheus_registry(),
        task_manager.spawn_essential_handle(),
        client.clone(),
    );

    let (block_import, subspace_link) = sc_consensus_subspace::block_import(
        sc_consensus_subspace::Config::get_or_compute(&*client)?,
        client.clone(),
        client.clone(),
    )?;

    sc_consensus_subspace::start_subspace_archiver(
        &subspace_link,
        client.clone(),
        &task_manager.spawn_handle(),
    );

    let slot_duration = subspace_link.config().slot_duration();
    let import_queue = sc_consensus_subspace::import_queue(
        &subspace_link,
        block_import.clone(),
        None,
        client.clone(),
        select_chain.clone(),
        move |_, ()| async move {
            let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

            let subspace_inherents =
                sp_consensus_subspace::inherents::InherentDataProvider::from_timestamp_and_duration(
                    *timestamp,
                    slot_duration,
                    vec![],
                );

            let uncles =
                sp_authorship::InherentDataProvider::<<Block as BlockT>::Header>::check_inherents();

            Ok((timestamp, subspace_inherents, uncles))
        },
        &task_manager.spawn_essential_handle(),
        config.prometheus_registry(),
        sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone()),
        telemetry.as_ref().map(|x| x.handle()),
    )?;

    Ok(sc_service::PartialComponents {
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

use polkadot_overseer::BlockInfo;
use sp_api::ConstructRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::SelectChain;
use sp_runtime::traits::Header as HeaderT;

/// Returns the active leaves the overseer should start with.
async fn active_leaves(
    select_chain: &impl SelectChain<Block>,
    client: &FullClient,
) -> Result<Vec<BlockInfo>, Error>
where
    RuntimeApi: ConstructRuntimeApi<Block, FullClient> + Send + Sync + 'static,
{
    let best_block = select_chain.best_chain().await?;

    let mut leaves = select_chain
        .leaves()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|hash| {
            let number = HeaderBackend::number(client, hash).ok()??;

            // Only consider leaves that are in maximum an uncle of the best block.
            if number < best_block.number().saturating_sub(1) {
                return None;
            } else if hash == best_block.hash() {
                return None;
            };

            let parent_hash = client.header(&BlockId::Hash(hash)).ok()??.parent_hash;

            Some(BlockInfo {
                hash,
                parent_hash,
                number,
            })
        })
        .collect::<Vec<_>>();

    // Sort by block number and get the maximum number of leaves
    leaves.sort_by_key(|b| b.number);

    leaves.push(BlockInfo {
        hash: best_block.hash(),
        parent_hash: *best_block.parent_hash(),
        number: *best_block.number(),
    });

    /// The maximum number of active leaves we forward to the [`Overseer`] on startup.
    const MAX_ACTIVE_LEAVES: usize = 4;

    Ok(leaves.into_iter().rev().take(MAX_ACTIVE_LEAVES).collect())
}

/// Full client along with some other components.
pub struct NewFull<C> {
    /// Task manager.
    pub task_manager: TaskManager,
    /// Full client.
    pub client: C,
    ///
    pub overseer_handle: Option<Handle>,
    /// Network.
    pub network: Arc<sc_network::NetworkService<Block, <Block as BlockT>::Hash>>,
    /// RPC handlers.
    pub rpc_handlers: sc_service::RpcHandlers,
    /// Full client backend.
    pub backend: Arc<FullBackend>,
}

/// Builds a new service for a full client.
pub fn new_full(mut config: Configuration, is_collator: IsCollator) -> Result<NewFull<Arc<FullClient>>, Error> {
    let overseer_gen = overseer::RealOverseerGen;

    use polkadot_node_network_protocol::request_response::IncomingRequest;

    let prometheus_registry = config.prometheus_registry().cloned();

    let overseer_connector = OverseerConnector::default();
    let overseer_handle = Handle::new(overseer_connector.handle());

    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (block_import, subspace_link, mut telemetry),
    } = new_partial(&config)?;

    let local_keystore = keystore_container.local_keystore();

    let (collation_req_receiver, cfg) = IncomingRequest::get_config_receiver();
    config.network.request_response_protocols.push(cfg);

    let (network, system_rpc_tx, network_starter) =
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

    let role = config.role.clone();
    let force_authoring = config.force_authoring;
    let backoff_authoring_blocks: Option<()> = None;
    let prometheus_registry = config.prometheus_registry().cloned();

    let new_slot_notification_stream = subspace_link.new_slot_notification_stream();
    let archived_segment_notification_stream = subspace_link.archived_segment_notification_stream();

    let active_leaves = futures::executor::block_on(active_leaves(&select_chain, &*client))?;

    let overseer_client = client.clone();
    let spawner = task_manager.spawn_handle();

    // let maybe_params = todo!("Handle maybe_params");

    let overseer_handle = if let Some(keystore) = local_keystore {
        let (overseer, overseer_handle) = overseer_gen
            .generate::<sc_service::SpawnTaskHandle, FullClient>(
                overseer_connector,
                OverseerGenArgs {
                    leaves: active_leaves,
                    keystore,
                    runtime_client: client.clone(),
                    network_service: network.clone(),
                    // authority_discovery_service,
                    collation_req_receiver,
                    registry: prometheus_registry.as_ref(),
                    spawner,
                    is_collator,
                },
            )
            .map_err(|e| ServiceError::Other(e.to_string()))?;

        let handle = Handle::new(overseer_handle);

        {
            let handle = handle.clone();
            task_manager.spawn_essential_handle().spawn_blocking(
                "overseer",
                Some("overseer"),
                Box::pin(async move {
                    use futures::{pin_mut, select, FutureExt};

                    let forward = polkadot_overseer::forward_events(overseer_client, handle);

                    let forward = forward.fuse();
                    let overseer_fut = overseer.run().fuse();

                    pin_mut!(overseer_fut);
                    pin_mut!(forward);

                    select! {
                        _ = forward => (),
                        _ = overseer_fut => (),
                        complete => (),
                    }
                }),
            );
        }
        Some(handle)
    } else {
        None
    };

    if role.is_authority() {
        let proposer_factory = sc_basic_authorship::ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool.clone(),
            prometheus_registry.as_ref(),
            telemetry.as_ref().map(|x| x.handle()),
        );

        let can_author_with =
            sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());

        let subspace_config = sc_consensus_subspace::SubspaceParams {
            client: client.clone(),
            select_chain,
            env: proposer_factory,
            block_import,
            sync_oracle: network.clone(),
            justification_sync_link: network.clone(),
            create_inherent_data_providers: {
                let client = client.clone();
                let subspace_link = subspace_link.clone();

                move |parent, ()| {
                    let client = client.clone();
                    let subspace_link = subspace_link.clone();

                    async move {
                        let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                        // TODO: Would be nice if the whole header was passed in here
                        let block_number = client
                            .header(&BlockId::Hash(parent))
                            .expect("Parent header must always exist when block is created; qed")
                            .expect("Parent header must always exist when block is created; qed")
                            .number;

                        let subspace_inherents =
                            sp_consensus_subspace::inherents::InherentDataProvider::from_timestamp_and_duration(
                                *timestamp,
                                subspace_link.config().slot_duration(),
                                subspace_link.root_blocks_for_block(block_number + 1),
                            );

                        let uncles = sc_consensus_uncles::create_uncles_inherent_data_provider(
                            &*client, parent,
                        )?;

                        Ok((timestamp, subspace_inherents, uncles))
                    }
                }
            },
            force_authoring,
            backoff_authoring_blocks,
            subspace_link,
            can_author_with,
            block_proposal_slot_portion: SlotProportion::new(2f32 / 3f32),
            max_block_proposal_slot_portion: None,
            telemetry: None,
        };

        let subspace = sc_consensus_subspace::start_subspace(subspace_config)?;

        // Subspace authoring task is considered essential, i.e. if it fails we take down the
        // service with it.
        task_manager.spawn_essential_handle().spawn_blocking(
            "subspace-proposer-",
            Some("block-authoring"),
            subspace,
        );
    }

    let rpc_extensions_builder = {
        let client = client.clone();
        let pool = transaction_pool.clone();

        Box::new(move |deny_unsafe, subscription_executor| {
            let deps = crate::rpc::FullDeps {
                client: client.clone(),
                pool: pool.clone(),
                deny_unsafe,
                subscription_executor,
                new_slot_notification_stream: new_slot_notification_stream.clone(),
                archived_segment_notification_stream: archived_segment_notification_stream.clone(),
            };

            Ok(crate::rpc::create_full(deps))
        })
    };

    let rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network: network.clone(),
        client: client.clone(),
        keystore: keystore_container.sync_keystore(),
        task_manager: &mut task_manager,
        transaction_pool,
        rpc_extensions_builder,
        backend: backend.clone(),
        system_rpc_tx,
        config,
        telemetry: telemetry.as_mut(),
    })?;

    network_starter.start_network();

    Ok(NewFull {
        task_manager,
        client,
        overseer_handle,
        network,
        rpc_handlers,
        backend,
    })
}
