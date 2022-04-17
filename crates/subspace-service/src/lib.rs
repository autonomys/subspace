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

pub mod rpc;

use futures::channel::mpsc;
use sc_basic_authorship::ProposerFactory;
use sc_client_api::ExecutorProvider;
use sc_consensus::BlockImport;
use sc_consensus_slots::SlotProportion;
use sc_consensus_subspace::{
    notification::SubspaceNotificationStream, BlockSigningNotification, NewSlotNotification,
    SubspaceLink, SubspaceParams,
};
use sc_executor::{NativeElseWasmExecutor, NativeExecutionDispatch};
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sc_service::{NetworkStarter, SpawnTasksParams};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sp_api::{ConstructRuntimeApi, NumberFor, TransactionFor};
use sp_consensus::{CanAuthorWithNativeVersion, Error as ConsensusError};
use sp_consensus_slots::Slot;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use subspace_core_primitives::RootBlock;
use subspace_runtime_primitives::{opaque::Block, AccountId, Balance, Index as Nonce};

// TODO: Check if this is still necessary and remove if not
/// A set of APIs that subspace-like runtimes must implement.
pub trait RuntimeApiCollection:
    sp_api::ApiExt<Block>
    + sp_api::Metadata<Block>
    + sp_block_builder::BlockBuilder<Block>
    + sp_executor::ExecutorApi<Block>
    + sp_offchain::OffchainWorkerApi<Block>
    + sp_session::SessionKeys<Block>
    + sp_consensus_subspace::SubspaceApi<Block>
    + sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block>
    + frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce>
    + pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance>
where
    <Self as sp_api::ApiExt<Block>>::StateBackend: sp_api::StateBackend<BlakeTwo256>,
{
}

impl<Api> RuntimeApiCollection for Api
where
    Api: sp_api::ApiExt<Block>
        + sp_api::Metadata<Block>
        + sp_block_builder::BlockBuilder<Block>
        + sp_executor::ExecutorApi<Block>
        + sp_offchain::OffchainWorkerApi<Block>
        + sp_session::SessionKeys<Block>
        + sp_consensus_subspace::SubspaceApi<Block>
        + sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block>
        + frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce>
        + pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance>,
    <Self as sp_api::ApiExt<Block>>::StateBackend: sp_api::StateBackend<BlakeTwo256>,
{
}

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
}

/// Subspace-like full client.
pub type FullClient<RuntimeApi, ExecutorDispatch> =
    sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;

pub type FullBackend = sc_service::TFullBackend<Block>;
pub type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

/// Subspace-specific service configuration.
#[derive(Debug)]
pub struct SubspaceConfiguration {
    /// Base configuration.
    pub base: Configuration,
    /// Whether slot notifications need to be present even if node is not responsible for block
    /// authoring.
    pub force_new_slot_notifications: bool,
}

impl From<Configuration> for SubspaceConfiguration {
    fn from(base: Configuration) -> Self {
        Self {
            base,
            force_new_slot_notifications: false,
        }
    }
}

impl From<SubspaceConfiguration> for Configuration {
    fn from(configuration: SubspaceConfiguration) -> Self {
        configuration.base
    }
}

impl Deref for SubspaceConfiguration {
    type Target = Configuration;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for SubspaceConfiguration {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

/// Creates `PartialComponents` for Subspace client.
#[allow(clippy::type_complexity)]
pub fn new_partial<RuntimeApi, ExecutorDispatch>(
    config: &Configuration,
) -> Result<
    sc_service::PartialComponents<
        FullClient<RuntimeApi, ExecutorDispatch>,
        FullBackend,
        FullSelectChain,
        sc_consensus::DefaultImportQueue<Block, FullClient<RuntimeApi, ExecutorDispatch>>,
        sc_transaction_pool::FullPool<Block, FullClient<RuntimeApi, ExecutorDispatch>>,
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
    RuntimeApi::RuntimeApi:
        RuntimeApiCollection<StateBackend = sc_client_api::StateBackendFor<FullBackend, Block>>,
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

    let proof_verifier = subspace_fraud_proof::ProofVerifier::new(
        client.clone(),
        backend.clone(),
        executor,
        task_manager.spawn_handle(),
    );
    client
        .execution_extensions()
        .set_extensions_factory(Box::new(proof_verifier));

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
        sc_consensus_subspace::Config::get(&*client)?,
        client.clone(),
        client.clone(),
        CanAuthorWithNativeVersion::new(client.executor().clone()),
        {
            let client = client.clone();

            move |parent_hash, subspace_link: SubspaceLink<Block>| {
                let client = client.clone();

                async move {
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                    // TODO: Would be nice if the whole header was passed in here
                    let parent_block_number = client
                        .header(&BlockId::Hash(parent_hash))
                        .expect("Parent header must always exist when block is created; qed")
                        .expect("Parent header must always exist when block is created; qed")
                        .number;

                    let subspace_inherents =
                        sp_consensus_subspace::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                            *timestamp,
                            subspace_link.config().slot_duration(),
                            subspace_link.root_blocks_for_block(parent_block_number + 1),
                        );

                    let uncles = sc_consensus_uncles::create_uncles_inherent_data_provider(
                        &*client,
                        parent_hash,
                    )?;

                    Ok((timestamp, subspace_inherents, uncles))
                }
            }
        },
    )?;

    sc_consensus_subspace::start_subspace_archiver(
        &subspace_link,
        client.clone(),
        &task_manager.spawn_essential_handle(),
    );

    let slot_duration = subspace_link.config().slot_duration();
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

/// Full node along with some other components.
pub struct NewFull<C> {
    /// Task manager.
    pub task_manager: TaskManager,
    /// Full client.
    pub client: C,
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
    pub block_signing_notification_stream: SubspaceNotificationStream<BlockSigningNotification>,
    /// Imported block stream.
    pub imported_block_notification_stream:
        SubspaceNotificationStream<(NumberFor<Block>, mpsc::Sender<RootBlock>)>,
    /// Network starter.
    pub network_starter: NetworkStarter,
}

/// Builds a new service for a full client.
pub fn new_full<RuntimeApi, ExecutorDispatch>(
    config: SubspaceConfiguration,
    enable_rpc_extensions: bool,
) -> Result<NewFull<Arc<FullClient<RuntimeApi, ExecutorDispatch>>>, Error>
where
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi, ExecutorDispatch>>
        + Send
        + Sync
        + 'static,
    RuntimeApi::RuntimeApi:
        RuntimeApiCollection<StateBackend = sc_client_api::StateBackendFor<FullBackend, Block>>,
    ExecutorDispatch: NativeExecutionDispatch + 'static,
{
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (block_import, subspace_link, mut telemetry),
    } = new_partial::<RuntimeApi, ExecutorDispatch>(&config)?;

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

    let backoff_authoring_blocks: Option<()> = None;
    let prometheus_registry = config.prometheus_registry().cloned();

    let new_slot_notification_stream = subspace_link.new_slot_notification_stream();
    let block_signing_notification_stream = subspace_link.block_signing_notification_stream();
    let archived_segment_notification_stream = subspace_link.archived_segment_notification_stream();
    let imported_block_notification_stream = subspace_link.imported_block_notification_stream();

    let is_authoring_blocks = config.role.is_authority();

    if is_authoring_blocks || config.force_new_slot_notifications {
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
                            .header(&BlockId::Hash(parent_hash))
                            .expect("Parent header must always exist when block is created; qed")
                            .expect("Parent header must always exist when block is created; qed")
                            .number;

                        let subspace_inherents =
                            sp_consensus_subspace::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                                *timestamp,
                                subspace_link.config().slot_duration(),
                                subspace_link.root_blocks_for_block(parent_block_number + 1),
                            );

                        let uncles = sc_consensus_uncles::create_uncles_inherent_data_provider(
                            &*client,
                            parent_hash,
                        )?;

                        Ok((timestamp, subspace_inherents, uncles))
                    }
                }
            },
            force_authoring: config.force_authoring,
            backoff_authoring_blocks,
            subspace_link,
            can_author_with: CanAuthorWithNativeVersion::new(client.executor().clone()),
            block_proposal_slot_portion: SlotProportion::new(2f32 / 3f32),
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
        rpc_extensions_builder: if enable_rpc_extensions {
            let client = client.clone();
            let new_slot_notification_stream = new_slot_notification_stream.clone();
            let block_signing_notification_stream = block_signing_notification_stream.clone();

            Box::new(move |deny_unsafe, subscription_executor| {
                let deps = crate::rpc::FullDeps {
                    client: client.clone(),
                    pool: transaction_pool.clone(),
                    deny_unsafe,
                    subscription_executor,
                    new_slot_notification_stream: new_slot_notification_stream.clone(),
                    block_signing_notification_stream: block_signing_notification_stream.clone(),
                    archived_segment_notification_stream: archived_segment_notification_stream
                        .clone(),
                };

                Ok(crate::rpc::create_full(deps))
            })
        } else {
            Box::new(|_, _| Ok(Default::default()))
        },
        backend: backend.clone(),
        system_rpc_tx,
        config: config.into(),
        telemetry: telemetry.as_mut(),
    })?;

    Ok(NewFull {
        task_manager,
        client,
        select_chain,
        network,
        rpc_handlers,
        backend,
        new_slot_notification_stream,
        block_signing_notification_stream,
        imported_block_notification_stream,
        network_starter,
    })
}
