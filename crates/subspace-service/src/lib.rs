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
    const_option,
    duration_constructors,
    impl_trait_in_assoc_type,
    int_roundings,
    let_chains,
    trait_upcasting,
    type_alias_impl_trait,
    type_changing_struct_update
)]

pub mod config;
pub(crate) mod domains;
pub mod dsn;
mod metrics;
pub(crate) mod mmr;
pub mod rpc;
pub mod sync_from_dsn;
pub mod transaction_pool;

use crate::config::{ChainSyncMode, SubspaceConfiguration, SubspaceNetworking};
use crate::domains::request_handler::LastDomainBlockERRequestHandler;
use crate::dsn::{create_dsn_instance, DsnConfigurationError};
use crate::metrics::NodeMetrics;
use crate::mmr::request_handler::MmrRequestHandler;
use crate::sync_from_dsn::piece_validator::SegmentCommitmentPieceValidator;
use crate::sync_from_dsn::snap_sync::snap_sync;
use crate::transaction_pool::FullPool;
use core::sync::atomic::{AtomicU32, Ordering};
use cross_domain_message_gossip::xdm_gossip_peers_set_config;
use domain_runtime_primitives::opaque::{Block as DomainBlock, Header as DomainHeader};
use frame_system_rpc_runtime_api::AccountNonceApi;
use futures::channel::oneshot;
use futures::FutureExt;
use jsonrpsee::RpcModule;
use pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi;
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use sc_basic_authorship::ProposerFactory;
use sc_client_api::execution_extensions::ExtensionsFactory;
use sc_client_api::{
    AuxStore, Backend, BlockBackend, BlockchainEvents, ExecutorProvider, HeaderBackend,
};
use sc_consensus::{
    BasicQueue, BlockCheckParams, BlockImport, BlockImportParams, DefaultImportQueue, ImportQueue,
    ImportResult, SharedBlockImport,
};
use sc_consensus_slots::SlotProportion;
use sc_consensus_subspace::archiver::{
    create_subspace_archiver, ArchivedSegmentNotification, SegmentHeadersStore,
};
use sc_consensus_subspace::block_import::{BlockImportingNotification, SubspaceBlockImport};
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::slot_worker::{
    NewSlotNotification, RewardSigningNotification, SubspaceSlotWorker, SubspaceSlotWorkerOptions,
    SubspaceSyncOracle,
};
use sc_consensus_subspace::verifier::{SubspaceVerifier, SubspaceVerifierOptions};
use sc_consensus_subspace::SubspaceLink;
use sc_domains::ExtensionsFactory as DomainsExtensionFactory;
use sc_network::service::traits::NetworkService;
use sc_network::{NetworkWorker, NotificationMetrics, NotificationService};
use sc_proof_of_time::source::gossip::pot_gossip_peers_set_config;
use sc_proof_of_time::source::{PotSlotInfo, PotSourceWorker};
use sc_proof_of_time::verifier::PotVerifier;
use sc_service::error::Error as ServiceError;
use sc_service::{Configuration, NetworkStarter, SpawnTasksParams, TaskManager};
use sc_subspace_block_relay::{
    build_consensus_relay, BlockRelayConfigurationError, NetworkWrapper,
};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sp_api::{ApiExt, ConstructRuntimeApi, Metadata, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_blockchain::HeaderMetadata;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::extract_pre_digest;
use sp_consensus_subspace::{
    FarmerPublicKey, KzgExtension, PosExtension, PotExtension, PotNextSlotInput, SubspaceApi,
};
use sp_core::offchain::storage::OffchainDb;
use sp_core::offchain::OffchainDbExt;
use sp_core::traits::SpawnEssentialNamed;
use sp_core::H256;
use sp_domains::{BundleProducerElectionApi, DomainsApi};
use sp_domains_fraud_proof::{FraudProofApi, FraudProofExtension, FraudProofHostFunctionsImpl};
use sp_externalities::Extensions;
use sp_messenger::MessengerApi;
use sp_messenger_host_functions::{MessengerExtension, MessengerHostFunctionsImpl};
use sp_mmr_primitives::MmrApi;
use sp_objects::ObjectsApi;
use sp_offchain::OffchainWorkerApi;
use sp_runtime::traits::{Block as BlockT, BlockIdTo, Header, NumberFor, Zero};
use sp_session::SessionKeys;
use sp_subspace_mmr::host_functions::{SubspaceMmrExtension, SubspaceMmrHostFunctionsImpl};
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use static_assertions::const_assert;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::crypto::kzg::{embedded_kzg_settings, Kzg};
use subspace_core_primitives::{BlockNumber, PotSeed, REWARD_SIGNING_CONTEXT};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::utils::piece_provider::PieceProvider;
use subspace_proof_of_space::Table;
use subspace_runtime_primitives::opaque::Block;
use subspace_runtime_primitives::{AccountId, Balance, Hash, Nonce};
use tokio::sync::broadcast;
use tracing::{debug, error, info, Instrument};

// There are multiple places where it is assumed that node is running on 64-bit system, refuse to
// compile otherwise
const_assert!(std::mem::size_of::<usize>() >= std::mem::size_of::<u64>());

/// This is over 15 minutes of slots assuming there are no forks, should be both sufficient and not
/// too large to handle
const POT_VERIFIER_CACHE_SIZE: u32 = 30_000;
const SYNC_TARGET_UPDATE_INTERVAL: Duration = Duration::from_secs(1);

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

    /// Subspace networking (DSN) error.
    #[error(transparent)]
    SubspaceDsn(#[from] DsnConfigurationError),

    /// Failed to set up block relay.
    #[error(transparent)]
    BlockRelay(#[from] BlockRelayConfigurationError),

    /// Other.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

// Simple wrapper whose ony purpose is to convert error type
struct BlockImportWrapper<BI>(BI);

#[async_trait::async_trait]
impl<Block, BI> BlockImport<Block> for BlockImportWrapper<BI>
where
    Block: BlockT,
    BI: BlockImport<Block, Error = sc_consensus_subspace::block_import::Error<Block::Header>>
        + Send
        + Sync,
{
    type Error = sp_consensus::Error;

    async fn check_block(
        &self,
        block: BlockCheckParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        self.0
            .check_block(block)
            .await
            .map_err(|error| sp_consensus::Error::Other(error.into()))
    }

    async fn import_block(
        &mut self,
        block: BlockImportParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        self.0
            .import_block(block)
            .await
            .map_err(|error| sp_consensus::Error::Other(error.into()))
    }
}

/// Host functions required for Subspace
#[cfg(not(feature = "runtime-benchmarks"))]
pub type HostFunctions = (
    sp_io::SubstrateHostFunctions,
    sp_consensus_subspace::consensus::HostFunctions,
    sp_domains_fraud_proof::HostFunctions,
    sp_subspace_mmr::HostFunctions,
    sp_messenger_host_functions::HostFunctions,
);

/// Host functions required for Subspace
#[cfg(feature = "runtime-benchmarks")]
pub type HostFunctions = (
    sp_io::SubstrateHostFunctions,
    frame_benchmarking::benchmarking::HostFunctions,
    sp_consensus_subspace::consensus::HostFunctions,
    sp_domains_fraud_proof::HostFunctions,
    sp_subspace_mmr::HostFunctions,
    sp_messenger_host_functions::HostFunctions,
);

/// Runtime executor for Subspace
pub type RuntimeExecutor = sc_executor::WasmExecutor<HostFunctions>;

/// Subspace-like full client.
pub type FullClient<RuntimeApi> = sc_service::TFullClient<Block, RuntimeApi, RuntimeExecutor>;

pub type FullBackend = sc_service::TFullBackend<Block>;
pub type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

struct SubspaceExtensionsFactory<PosTable, Client, DomainBlock> {
    kzg: Kzg,
    client: Arc<Client>,
    backend: Arc<FullBackend>,
    pot_verifier: PotVerifier,
    domains_executor: Arc<sc_domains::RuntimeExecutor>,
    confirmation_depth_k: BlockNumber,
    _pos_table: PhantomData<(PosTable, DomainBlock)>,
}

impl<PosTable, Block, Client, DomainBlock> ExtensionsFactory<Block>
    for SubspaceExtensionsFactory<PosTable, Client, DomainBlock>
where
    PosTable: Table,
    Block: BlockT,
    Block::Hash: From<H256> + Into<H256>,
    DomainBlock: BlockT,
    DomainBlock::Hash: Into<H256> + From<H256>,
    Client: BlockBackend<Block>
        + HeaderBackend<Block>
        + ProvideRuntimeApi<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>
        + DomainsApi<Block, DomainBlock::Header>
        + BundleProducerElectionApi<Block, Balance>
        + MmrApi<Block, H256, NumberFor<Block>>
        + MessengerApi<Block, NumberFor<Block>, Block::Hash>,
{
    fn extensions_for(
        &self,
        _block_hash: Block::Hash,
        _block_number: NumberFor<Block>,
    ) -> Extensions {
        let confirmation_depth_k = self.confirmation_depth_k;
        let mut exts = Extensions::new();
        exts.register(KzgExtension::new(self.kzg.clone()));
        exts.register(PosExtension::new::<PosTable>());
        exts.register(PotExtension::new({
            let client = Arc::clone(&self.client);
            let pot_verifier = self.pot_verifier.clone();

            Box::new(
                move |parent_hash, slot, proof_of_time, quick_verification| {
                    let parent_hash = {
                        let mut converted_parent_hash = Block::Hash::default();
                        converted_parent_hash.as_mut().copy_from_slice(&parent_hash);
                        converted_parent_hash
                    };

                    let parent_header = match client.header(parent_hash) {
                        Ok(Some(parent_header)) => parent_header,
                        Ok(None) => {
                            if quick_verification {
                                error!(
                                    %parent_hash,
                                    "Header not found during proof of time verification"
                                );

                                return false;
                            } else {
                                debug!(
                                    %parent_hash,
                                    "Header not found during proof of time verification"
                                );

                                // This can only happen during special sync modes there are no other
                                // cases where parent header may not be available, hence allow it
                                return true;
                            }
                        }
                        Err(error) => {
                            error!(
                                %error,
                                %parent_hash,
                                "Failed to retrieve header during proof of time verification"
                            );

                            return false;
                        }
                    };

                    let parent_pre_digest = match extract_pre_digest(&parent_header) {
                        Ok(parent_pre_digest) => parent_pre_digest,
                        Err(error) => {
                            error!(
                                %error,
                                %parent_hash,
                                parent_number = %parent_header.number(),
                                "Failed to extract pre-digest from parent header during proof of \
                                time verification, this must never happen"
                            );

                            return false;
                        }
                    };

                    let parent_slot = parent_pre_digest.slot();
                    if slot <= *parent_slot {
                        return false;
                    }

                    let pot_parameters = match client.runtime_api().pot_parameters(parent_hash) {
                        Ok(pot_parameters) => pot_parameters,
                        Err(error) => {
                            debug!(
                                %error,
                                %parent_hash,
                                parent_number = %parent_header.number(),
                                "Failed to retrieve proof of time parameters during proof of time \
                                verification"
                            );

                            return false;
                        }
                    };

                    let pot_input = if parent_header.number().is_zero() {
                        PotNextSlotInput {
                            slot: parent_slot + Slot::from(1),
                            slot_iterations: pot_parameters.slot_iterations(),
                            seed: pot_verifier.genesis_seed(),
                        }
                    } else {
                        let pot_info = parent_pre_digest.pot_info();

                        PotNextSlotInput::derive(
                            pot_parameters.slot_iterations(),
                            parent_slot,
                            pot_info.proof_of_time(),
                            &pot_parameters.next_parameters_change(),
                        )
                    };

                    // Ensure proof of time and future proof of time included in upcoming block are
                    // valid

                    if quick_verification {
                        pot_verifier.try_is_output_valid(
                            pot_input,
                            Slot::from(slot) - parent_slot,
                            proof_of_time,
                            pot_parameters.next_parameters_change(),
                        )
                    } else {
                        pot_verifier.is_output_valid(
                            pot_input,
                            Slot::from(slot) - parent_slot,
                            proof_of_time,
                            pot_parameters.next_parameters_change(),
                        )
                    }
                },
            )
        }));

        exts.register(FraudProofExtension::new(Arc::new(
            FraudProofHostFunctionsImpl::<_, _, DomainBlock, _, _>::new(
                self.client.clone(),
                self.domains_executor.clone(),
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
                self.client.clone(),
                confirmation_depth_k,
            ),
        )));

        exts.register(MessengerExtension::new(Arc::new(
            MessengerHostFunctionsImpl::<Block, _, DomainBlock, _>::new(
                self.client.clone(),
                self.domains_executor.clone(),
            ),
        )));

        // if the offchain storage is available, then add offchain extension
        // to generate and verify MMR proofs
        if let Some(offchain_storage) = self.backend.offchain_storage() {
            let offchain_db = OffchainDb::new(offchain_storage);
            exts.register(OffchainDbExt::new(offchain_db));
        }

        exts
    }
}

/// Other partial components returned by [`new_partial()`]
pub struct OtherPartialComponents<RuntimeApi>
where
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi>> + Send + Sync + 'static,
{
    /// Subspace block import
    pub block_import: SharedBlockImport<Block>,
    /// Subspace link
    pub subspace_link: SubspaceLink<Block>,
    /// Segment headers store
    pub segment_headers_store: SegmentHeadersStore<FullClient<RuntimeApi>>,
    /// Proof of time verifier
    pub pot_verifier: PotVerifier,
    /// Approximate target block number for syncing purposes
    pub sync_target_block_number: Arc<AtomicU32>,
    /// Telemetry
    pub telemetry: Option<Telemetry>,
}

type PartialComponents<RuntimeApi> = sc_service::PartialComponents<
    FullClient<RuntimeApi>,
    FullBackend,
    FullSelectChain,
    DefaultImportQueue<Block>,
    FullPool<FullClient<RuntimeApi>, Block, DomainHeader>,
    OtherPartialComponents<RuntimeApi>,
>;

/// Creates `PartialComponents` for Subspace client.
#[allow(clippy::type_complexity)]
pub fn new_partial<PosTable, RuntimeApi>(
    config: &Configuration,
    pot_external_entropy: &[u8],
) -> Result<PartialComponents<RuntimeApi>, ServiceError>
where
    PosTable: Table,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: ApiExt<Block>
        + Metadata<Block>
        + BlockBuilder<Block>
        + OffchainWorkerApi<Block>
        + SessionKeys<Block>
        + TaggedTransactionQueue<Block>
        + SubspaceApi<Block, FarmerPublicKey>
        + DomainsApi<Block, DomainHeader>
        + FraudProofApi<Block, DomainHeader>
        + BundleProducerElectionApi<Block, Balance>
        + ObjectsApi<Block>
        + MmrApi<Block, H256, NumberFor<Block>>
        + MessengerApi<Block, NumberFor<Block>, <Block as BlockT>::Hash>,
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

    let executor = sc_service::new_wasm_executor(config);
    let domains_executor = sc_service::new_wasm_executor(config);

    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, _>(
            config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            executor.clone(),
        )?;

    let kzg = tokio::task::block_in_place(|| Kzg::new(embedded_kzg_settings()));

    let client = Arc::new(client);
    let client_info = client.info();
    let chain_constants = client
        .runtime_api()
        .chain_constants(client_info.best_hash)
        .map_err(|error| ServiceError::Application(error.into()))?;

    let pot_verifier = PotVerifier::new(
        PotSeed::from_genesis(client_info.genesis_hash.as_ref(), pot_external_entropy),
        POT_VERIFIER_CACHE_SIZE,
    );

    client
        .execution_extensions()
        .set_extensions_factory(SubspaceExtensionsFactory::<PosTable, _, DomainBlock> {
            kzg: kzg.clone(),
            client: Arc::clone(&client),
            pot_verifier: pot_verifier.clone(),
            domains_executor: Arc::new(domains_executor),
            backend: backend.clone(),
            confirmation_depth_k: chain_constants.confirmation_depth_k(),
            _pos_table: PhantomData,
        });

    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let segment_headers_store = tokio::task::block_in_place(|| {
        SegmentHeadersStore::new(client.clone(), chain_constants.confirmation_depth_k())
    })
    .map_err(|error| ServiceError::Application(error.into()))?;

    let subspace_link = SubspaceLink::new(chain_constants, kzg.clone());
    let segment_headers_store = segment_headers_store.clone();

    let block_import = SubspaceBlockImport::<PosTable, _, _, _, _, _>::new(
        client.clone(),
        client.clone(),
        subspace_link.clone(),
        {
            let client = client.clone();
            let segment_headers_store = segment_headers_store.clone();

            move |parent_hash, ()| {
                let client = client.clone();
                let segment_headers_store = segment_headers_store.clone();

                async move {
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                    let parent_header = client
                        .header(parent_hash)?
                        .expect("Parent header must always exist when block is created; qed");

                    let parent_block_number = parent_header.number;

                    let subspace_inherents =
                        sp_consensus_subspace::inherents::InherentDataProvider::new(
                            segment_headers_store
                                .segment_headers_for_block(parent_block_number + 1),
                        );

                    Ok((timestamp, subspace_inherents))
                }
            }
        },
        segment_headers_store.clone(),
        pot_verifier.clone(),
    );

    let sync_target_block_number = Arc::new(AtomicU32::new(0));
    let transaction_pool = transaction_pool::new_full(
        config.transaction_pool.clone(),
        config.role.is_authority(),
        config.prometheus_registry(),
        &task_manager,
        client.clone(),
    )?;

    let verifier = SubspaceVerifier::<PosTable, _, _, _>::new(SubspaceVerifierOptions {
        client: client.clone(),
        chain_constants,
        kzg,
        select_chain: select_chain.clone(),
        telemetry: telemetry.as_ref().map(|x| x.handle()),
        offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool.clone()),
        reward_signing_context: schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
        sync_target_block_number: Arc::clone(&sync_target_block_number),
        is_authoring_blocks: config.role.is_authority(),
        pot_verifier: pot_verifier.clone(),
    });

    let block_import = SharedBlockImport::new(BlockImportWrapper(block_import));
    let import_queue = BasicQueue::new(
        verifier,
        block_import.clone(),
        None,
        &task_manager.spawn_essential_handle(),
        config.prometheus_registry(),
    );

    let other = OtherPartialComponents {
        block_import,
        subspace_link,
        segment_headers_store,
        pot_verifier,
        sync_target_block_number,
        telemetry,
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
pub struct NewFull<Client>
where
    Client: ProvideRuntimeApi<Block>
        + AuxStore
        + BlockBackend<Block>
        + BlockIdTo<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + 'static,
    Client::Api: TaggedTransactionQueue<Block>
        + DomainsApi<Block, DomainHeader>
        + FraudProofApi<Block, DomainHeader>
        + SubspaceApi<Block, FarmerPublicKey>
        + MmrApi<Block, H256, NumberFor<Block>>
        + MessengerApi<Block, NumberFor<Block>, <Block as BlockT>::Hash>,
{
    /// Task manager.
    pub task_manager: TaskManager,
    /// Full client.
    pub client: Arc<Client>,
    /// Chain selection rule.
    pub select_chain: FullSelectChain,
    /// Network service.
    pub network_service: Arc<dyn NetworkService + Send + Sync>,
    /// Cross-domain gossip notification service.
    pub xdm_gossip_notification_service: Box<dyn NotificationService>,
    /// Sync service.
    pub sync_service: Arc<sc_network_sync::SyncingService<Block>>,
    /// RPC handlers.
    pub rpc_handlers: sc_service::RpcHandlers,
    /// Full client backend.
    pub backend: Arc<FullBackend>,
    /// Pot slot info stream.
    pub pot_slot_info_stream: broadcast::Receiver<PotSlotInfo>,
    /// New slot stream.
    /// Note: this is currently used to send solutions from the farmer during tests.
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
    pub transaction_pool: Arc<FullPool<Client, Block, DomainHeader>>,
}

type FullNode<RuntimeApi> = NewFull<FullClient<RuntimeApi>>;

/// Builds a new service for a full client.
pub async fn new_full<PosTable, RuntimeApi>(
    mut config: SubspaceConfiguration,
    partial_components: PartialComponents<RuntimeApi>,
    prometheus_registry: Option<&mut Registry>,
    enable_rpc_extensions: bool,
    block_proposal_slot_portion: SlotProportion,
) -> Result<FullNode<RuntimeApi>, Error>
where
    PosTable: Table,
    RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: ApiExt<Block>
        + Metadata<Block>
        + AccountNonceApi<Block, AccountId, Nonce>
        + BlockBuilder<Block>
        + OffchainWorkerApi<Block>
        + SessionKeys<Block>
        + TaggedTransactionQueue<Block>
        + TransactionPaymentApi<Block, Balance>
        + SubspaceApi<Block, FarmerPublicKey>
        + DomainsApi<Block, DomainHeader>
        + FraudProofApi<Block, DomainHeader>
        + ObjectsApi<Block>
        + MmrApi<Block, Hash, BlockNumber>
        + MessengerApi<Block, NumberFor<Block>, <Block as BlockT>::Hash>,
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
        pot_verifier,
        sync_target_block_number,
        mut telemetry,
    } = other;

    let offchain_indexing_enabled = config.offchain_worker.indexing_enabled;
    let fork_id = config.base.chain_spec.fork_id().map(String::from);
    let (node, bootstrap_nodes) = match config.subspace_networking {
        SubspaceNetworking::Reuse {
            node,
            bootstrap_nodes,
        } => (node, bootstrap_nodes),
        SubspaceNetworking::Create { config: dsn_config } => {
            let dsn_protocol_version = hex::encode(client.chain_info().genesis_hash);

            debug!(
                chain_type=?config.base.chain_spec.chain_type(),
                genesis_hash=%hex::encode(client.chain_info().genesis_hash),
                "Setting DSN protocol version..."
            );

            let (node, mut node_runner) = create_dsn_instance(
                dsn_protocol_version,
                dsn_config.clone(),
                prometheus_registry,
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
            bootstrap_nodes
        }
    };

    let import_queue_service1 = import_queue.service();
    let import_queue_service2 = import_queue.service();
    let network_wrapper = Arc::new(NetworkWrapper::default());
    let block_relay = Some(
        build_consensus_relay(
            network_wrapper.clone(),
            client.clone(),
            transaction_pool.clone(),
            config.base.prometheus_registry(),
        )
        .map_err(Error::BlockRelay)?,
    );
    let mut net_config = sc_network::config::FullNetworkConfiguration::new(&config.base.network);
    let (xdm_gossip_notification_config, xdm_gossip_notification_service) =
        xdm_gossip_peers_set_config();
    net_config.add_notification_protocol(xdm_gossip_notification_config);
    let (pot_gossip_notification_config, pot_gossip_notification_service) =
        pot_gossip_peers_set_config();
    net_config.add_notification_protocol(pot_gossip_notification_config);
    let pause_sync = Arc::clone(&net_config.network_config.pause_sync);

    let num_peer_hint = net_config.network_config.default_peers_set_num_full as usize
        + net_config
            .network_config
            .default_peers_set
            .reserved_nodes
            .len();

    if let Some(offchain_storage) = backend.offchain_storage() {
        // Allow both outgoing and incoming requests.
        let (handler, protocol_config) =
            MmrRequestHandler::new::<NetworkWorker<Block, <Block as BlockT>::Hash>, _>(
                &config.base.protocol_id(),
                fork_id.as_deref(),
                client.clone(),
                num_peer_hint,
                offchain_storage,
            );
        task_manager
            .spawn_handle()
            .spawn("mmr-request-handler", Some("networking"), handler.run());

        net_config.add_request_response_protocol(protocol_config);
    }

    // "Last confirmed domain block execution receipt" request handler
    {
        let (handler, protocol_config) =
            LastDomainBlockERRequestHandler::new::<NetworkWorker<Block, <Block as BlockT>::Hash>>(
                &config.base.protocol_id(),
                fork_id.as_deref(),
                client.clone(),
                num_peer_hint,
            );
        task_manager.spawn_handle().spawn(
            "last-domain-execution-receipt-request-handler",
            Some("networking"),
            handler.run(),
        );

        net_config.add_request_response_protocol(protocol_config);
    }

    let (network_service, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config.base,
            net_config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            block_announce_validator_builder: None,
            warp_sync_params: None,
            block_relay,
            metrics: NotificationMetrics::new(
                config
                    .base
                    .prometheus_config
                    .as_ref()
                    .map(|cfg| &cfg.registry),
            ),
        })?;

    task_manager.spawn_handle().spawn(
        "sync-target-follower",
        None,
        Box::pin({
            let sync_service = sync_service.clone();
            let sync_target_block_number = Arc::clone(&sync_target_block_number);

            async move {
                loop {
                    let best_seen_block = sync_service
                        .status()
                        .await
                        .map(|status| status.best_seen_block.unwrap_or_default())
                        .unwrap_or_default();
                    sync_target_block_number.store(best_seen_block, Ordering::Relaxed);

                    tokio::time::sleep(SYNC_TARGET_UPDATE_INTERVAL).await;
                }
            }
        }),
    );

    let sync_oracle = SubspaceSyncOracle::new(
        config.base.force_authoring,
        Arc::clone(&pause_sync),
        sync_service.clone(),
    );

    let subspace_archiver = tokio::task::block_in_place(|| {
        create_subspace_archiver(
            segment_headers_store.clone(),
            subspace_link.clone(),
            client.clone(),
            sync_oracle.clone(),
            telemetry.as_ref().map(|telemetry| telemetry.handle()),
        )
    })
    .map_err(ServiceError::Client)?;

    task_manager
        .spawn_essential_handle()
        .spawn_essential_blocking(
            "subspace-archiver",
            None,
            Box::pin(async move {
                if let Err(error) = subspace_archiver.await {
                    error!(%error, "Archiver exited with error");
                }
            }),
        );

    network_wrapper.set(network_service.clone());

    let dsn_sync_piece_getter = config.dsn_piece_getter.unwrap_or_else(|| {
        Arc::new(PieceProvider::new(
            node.clone(),
            Some(SegmentCommitmentPieceValidator::new(
                node.clone(),
                subspace_link.kzg().clone(),
                segment_headers_store.clone(),
            )),
        ))
    });

    if !config.base.network.force_synced {
        // Start with DSN sync in this case
        pause_sync.store(true, Ordering::Release);
    }

    let snap_sync_task = snap_sync(
        segment_headers_store.clone(),
        node.clone(),
        fork_id.clone(),
        Arc::clone(&client),
        import_queue_service1,
        pause_sync.clone(),
        dsn_sync_piece_getter.clone(),
        Arc::clone(&network_service),
        sync_service.clone(),
    );

    let (observer, worker) = sync_from_dsn::create_observer_and_worker(
        segment_headers_store.clone(),
        Arc::clone(&network_service),
        node.clone(),
        Arc::clone(&client),
        import_queue_service2,
        sync_target_block_number,
        pause_sync,
        dsn_sync_piece_getter,
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
                // Run snap-sync before DSN-sync.
                if config.sync == ChainSyncMode::Snap {
                    snap_sync_task.await;
                }

                if let Err(error) = worker.await {
                    error!(%error, "Sync from DSN exited with an error");
                }
            }),
        );

    if let Some(registry) = config.base.prometheus_registry() {
        match NodeMetrics::new(
            client.clone(),
            client.every_import_notification_stream(),
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

    let offchain_tx_pool_factory = OffchainTransactionPoolFactory::new(transaction_pool.clone());

    if config.base.offchain_worker.enabled {
        task_manager.spawn_handle().spawn(
            "offchain-workers-runner",
            "offchain-worker",
            sc_offchain::OffchainWorkers::new(sc_offchain::OffchainWorkerOptions {
                runtime_api_provider: client.clone(),
                is_validator: config.base.role.is_authority(),
                keystore: Some(keystore_container.keystore()),
                offchain_db: backend.offchain_storage(),
                transaction_pool: Some(offchain_tx_pool_factory.clone()),
                network_provider: Arc::new(network_service.clone()),
                enable_http_requests: true,
                custom_extensions: |_| vec![],
            })
            .run(client.clone(), task_manager.spawn_handle())
            .boxed(),
        );
    }

    // mmr offchain indexer
    if offchain_indexing_enabled {
        task_manager.spawn_essential_handle().spawn_blocking(
            "mmr-gadget",
            None,
            mmr_gadget::MmrGadget::start(
                client.clone(),
                backend.clone(),
                sp_mmr_primitives::INDEXING_PREFIX.to_vec(),
            ),
        );
    }

    let backoff_authoring_blocks: Option<()> = None;

    let new_slot_notification_stream = subspace_link.new_slot_notification_stream();
    let reward_signing_notification_stream = subspace_link.reward_signing_notification_stream();
    let block_importing_notification_stream = subspace_link.block_importing_notification_stream();
    let archived_segment_notification_stream = subspace_link.archived_segment_notification_stream();

    let (pot_source_worker, pot_gossip_worker, pot_slot_info_stream) = PotSourceWorker::new(
        config.is_timekeeper,
        config.timekeeper_cpu_cores,
        client.clone(),
        pot_verifier.clone(),
        Arc::clone(&network_service),
        pot_gossip_notification_service,
        sync_service.clone(),
        sync_oracle.clone(),
    )
    .map_err(|error| Error::Other(error.into()))?;

    let additional_pot_slot_info_stream = pot_source_worker.subscribe_pot_slot_info_stream();

    task_manager
        .spawn_essential_handle()
        .spawn("pot-source", Some("pot"), pot_source_worker.run());
    task_manager
        .spawn_essential_handle()
        .spawn("pot-gossip", Some("pot"), pot_gossip_worker.run());

    if config.base.role.is_authority() || config.force_new_slot_notifications {
        let proposer_factory = ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool.clone(),
            config.base.prometheus_registry(),
            telemetry.as_ref().map(|x| x.handle()),
        );

        let subspace_slot_worker =
            SubspaceSlotWorker::<PosTable, _, _, _, _, _, _, _>::new(SubspaceSlotWorkerOptions {
                client: client.clone(),
                env: proposer_factory,
                block_import,
                sync_oracle: sync_oracle.clone(),
                justification_sync_link: sync_service.clone(),
                force_authoring: config.base.force_authoring,
                backoff_authoring_blocks,
                subspace_link: subspace_link.clone(),
                segment_headers_store: segment_headers_store.clone(),
                block_proposal_slot_portion,
                max_block_proposal_slot_portion: None,
                telemetry: telemetry.as_ref().map(|x| x.handle()),
                offchain_tx_pool_factory,
                pot_verifier,
            });

        let create_inherent_data_providers = {
            let client = client.clone();
            let segment_headers_store = segment_headers_store.clone();

            move |parent_hash, ()| {
                let client = client.clone();
                let segment_headers_store = segment_headers_store.clone();

                async move {
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                    let parent_header = client
                        .header(parent_hash)?
                        .expect("Parent header must always exist when block is created; qed");

                    let parent_block_number = parent_header.number;

                    let subspace_inherents =
                        sp_consensus_subspace::inherents::InherentDataProvider::new(
                            segment_headers_store
                                .segment_headers_for_block(parent_block_number + 1),
                        );

                    Ok((timestamp, subspace_inherents))
                }
            }
        };

        info!(target: "subspace", "🧑‍🌾 Starting Subspace Authorship worker");
        let slot_worker_task = sc_proof_of_time::start_slot_worker(
            subspace_link.chain_constants().slot_duration(),
            client.clone(),
            select_chain.clone(),
            subspace_slot_worker,
            sync_oracle.clone(),
            create_inherent_data_providers,
            pot_slot_info_stream,
        );

        // Subspace authoring task is considered essential, i.e. if it fails we take down the
        // service with it.
        task_manager.spawn_essential_handle().spawn_blocking(
            "subspace-proposer",
            Some("block-authoring"),
            slot_worker_task,
        );
    }

    // We replace the Substrate implementation of metrics server with our own.
    config.base.prometheus_config.take();

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
            let chain_spec = config.base.chain_spec.cloned_box();
            let backend = backend.clone();

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
                    sync_oracle: sync_oracle.clone(),
                    kzg: subspace_link.kzg().clone(),
                    backend: backend.clone(),
                };

                rpc::create_full(deps).map_err(Into::into)
            })
        } else {
            Box::new(|_, _| Ok(RpcModule::new(())))
        },
        backend: backend.clone(),
        system_rpc_tx,
        config: config.base,
        telemetry: telemetry.as_mut(),
        tx_handler_controller,
        sync_service: sync_service.clone(),
    })?;

    Ok(NewFull {
        task_manager,
        client,
        select_chain,
        network_service,
        xdm_gossip_notification_service,
        sync_service,
        rpc_handlers,
        backend,
        pot_slot_info_stream: additional_pot_slot_info_stream,
        new_slot_notification_stream,
        reward_signing_notification_stream,
        block_importing_notification_stream,
        archived_segment_notification_stream,
        network_starter,
        transaction_pool,
    })
}
