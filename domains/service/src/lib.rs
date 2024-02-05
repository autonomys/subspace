//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

pub mod config;
mod domain;
pub mod providers;
pub mod rpc;
mod transaction_pool;

pub use self::domain::{new_full, DomainOperator, DomainParams, FullPool, NewFull};
use futures::channel::oneshot;
use futures::{FutureExt, StreamExt};
use sc_client_api::execution_extensions::ExtensionsFactory;
use sc_client_api::{BlockBackend, BlockchainEvents, HeaderBackend, ProofProvider};
use sc_consensus::ImportQueue;
use sc_network::config::Roles;
use sc_network::peer_store::PeerStore;
use sc_network::NetworkService;
use sc_network_sync::block_request_handler::BlockRequestHandler;
use sc_network_sync::engine::SyncingEngine;
use sc_network_sync::service::network::NetworkServiceProvider;
use sc_network_sync::state_request_handler::StateRequestHandler;
use sc_network_sync::SyncingService;
use sc_service::config::SyncMode;
use sc_service::{
    build_system_rpc_future, BuildNetworkParams, NetworkStarter, TFullClient,
    TransactionPoolAdapter,
};
use sc_transaction_pool_api::MaintainedTransactionPool;
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedSender};
use sp_api::ProvideRuntimeApi;
use sp_api::__private::Extensions;
use sp_blockchain::HeaderMetadata;
use sp_consensus::block_validation::{Chain, DefaultBlockAnnounceValidator};
use sp_core::H256;
use sp_domains::DomainsApi;
use sp_messenger::MessengerApi;
use sp_messenger_host_functions::{MessengerExtension, MessengerHostFunctionsImpl};
use sp_mmr_primitives::MmrApi;
use sp_runtime::traits::{Block as BlockT, BlockIdTo, NumberFor, Zero};
use sp_subspace_mmr::host_functions::{SubspaceMmrExtension, SubspaceMmrHostFunctionsImpl};
use std::marker::PhantomData;
use std::sync::Arc;

/// Host functions required for Subspace domain
#[cfg(not(feature = "runtime-benchmarks"))]
pub type HostFunctions = (
    sp_io::SubstrateHostFunctions,
    sp_messenger_host_functions::HostFunctions,
    sp_subspace_mmr::DomainHostFunctions,
);

/// Host functions required for Subspace domain
#[cfg(feature = "runtime-benchmarks")]
pub type HostFunctions = (
    sp_io::SubstrateHostFunctions,
    sp_messenger_host_functions::HostFunctions,
    sp_subspace_mmr::DomainHostFunctions,
    frame_benchmarking::benchmarking::HostFunctions,
);

/// Runtime executor for Subspace domain
pub type RuntimeExecutor = sc_executor::WasmExecutor<HostFunctions>;

/// Domain full client.
pub type FullClient<Block, RuntimeApi> = TFullClient<Block, RuntimeApi, RuntimeExecutor>;

pub type FullBackend<Block> = sc_service::TFullBackend<Block>;

pub(crate) struct DomainExtensionsFactory<CClient, CBlock, Block> {
    consensus_client: Arc<CClient>,
    executor: Arc<RuntimeExecutor>,
    _marker: PhantomData<(CBlock, Block)>,
}

impl<CClient, CBlock, Block> ExtensionsFactory<Block>
    for DomainExtensionsFactory<CClient, CBlock, Block>
where
    Block: BlockT,
    CBlock: BlockT,
    CBlock::Hash: From<H256>,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + 'static,
    CClient::Api: MmrApi<CBlock, H256, NumberFor<CBlock>>
        + MessengerApi<CBlock, NumberFor<CBlock>>
        + DomainsApi<CBlock, Block::Header>,
{
    fn extensions_for(
        &self,
        _block_hash: Block::Hash,
        _block_number: NumberFor<Block>,
    ) -> Extensions {
        let mut exts = Extensions::new();
        exts.register(SubspaceMmrExtension::new(Arc::new(
            SubspaceMmrHostFunctionsImpl::<CBlock, _>::new(self.consensus_client.clone()),
        )));

        exts.register(MessengerExtension::new(Arc::new(
            MessengerHostFunctionsImpl::<CBlock, _, Block, _>::new(
                self.consensus_client.clone(),
                self.executor.clone(),
            ),
        )));

        exts
    }
}

/// Build the network service, the network status sinks and an RPC sender.
///
/// Port from `sc_service::build_network` mostly the same with block sync disabled.
// TODO: Struct for returned value
#[allow(clippy::type_complexity)]
pub fn build_network<TBl, TExPool, TImpQu, TCl>(
    params: BuildNetworkParams<TBl, TExPool, TImpQu, TCl>,
) -> Result<
    (
        Arc<NetworkService<TBl, <TBl as BlockT>::Hash>>,
        TracingUnboundedSender<sc_rpc::system::Request<TBl>>,
        sc_network_transactions::TransactionsHandlerController<<TBl as BlockT>::Hash>,
        NetworkStarter,
        Arc<SyncingService<TBl>>,
    ),
    sc_service::Error,
>
where
    TBl: BlockT,
    TCl: ProvideRuntimeApi<TBl>
        + HeaderMetadata<TBl, Error = sp_blockchain::Error>
        + Chain<TBl>
        + BlockBackend<TBl>
        + BlockIdTo<TBl, Error = sp_blockchain::Error>
        + ProofProvider<TBl>
        + HeaderBackend<TBl>
        + BlockchainEvents<TBl>
        + 'static,
    TExPool: MaintainedTransactionPool<Block = TBl, Hash = <TBl as BlockT>::Hash> + 'static,
    TImpQu: ImportQueue<TBl> + 'static,
{
    let BuildNetworkParams {
        config,
        mut net_config,
        client,
        transaction_pool,
        spawn_handle,
        import_queue,
        block_announce_validator_builder: _,
        warp_sync_params: _,
        block_relay,
    } = params;

    if client.requires_full_sync() {
        match config.network.sync_mode {
            SyncMode::LightState { .. } => {
                return Err("Fast sync doesn't work for archive nodes".into());
            }
            SyncMode::Warp => return Err("Warp sync doesn't work for archive nodes".into()),
            SyncMode::Full => {}
        }
    }

    let protocol_id = config.protocol_id();

    let (chain_sync_network_provider, chain_sync_network_handle) = NetworkServiceProvider::new();
    let (mut block_server, block_downloader) = match block_relay {
        Some(params) => (params.server, params.downloader),
        None => {
            // Custom protocol was not specified, use the default block handler.
            let params = BlockRequestHandler::new(
                chain_sync_network_handle.clone(),
                &protocol_id,
                config.chain_spec.fork_id(),
                client.clone(),
                config.network.default_peers_set.in_peers as usize
                    + config.network.default_peers_set.out_peers as usize,
            );
            (params.server, params.downloader)
        }
    };
    spawn_handle.spawn("block-request-handler", Some("networking"), async move {
        block_server.run().await;
    });

    // Create `PeerStore` and initialize it with bootnode peer ids.
    let peer_store = PeerStore::new(
        net_config
            .network_config
            .boot_nodes
            .iter()
            .map(|bootnode| bootnode.peer_id)
            .collect(),
    );
    let peer_store_handle = peer_store.handle();
    spawn_handle.spawn("peer-store", Some("networking"), peer_store.run());

    let state_request_protocol_config = {
        // Allow both outgoing and incoming requests.
        let (handler, protocol_config) = StateRequestHandler::new(
            &protocol_id,
            config.chain_spec.fork_id(),
            client.clone(),
            config.network.default_peers_set_num_full as usize,
        );
        spawn_handle.spawn("state-request-handler", Some("networking"), handler.run());
        protocol_config
    };

    let (engine, sync_service, block_announce_config) = SyncingEngine::new(
        Roles::from(&config.role),
        client.clone(),
        // TODO: False-positive in clippy: https://github.com/rust-lang/rust-clippy/issues/12148
        #[allow(clippy::useless_asref)]
        config
            .prometheus_config
            .as_ref()
            .map(|config| config.registry.clone())
            .as_ref(),
        &net_config,
        protocol_id.clone(),
        &config.chain_spec.fork_id().map(ToOwned::to_owned),
        Box::new(DefaultBlockAnnounceValidator),
        None,
        chain_sync_network_handle,
        import_queue.service(),
        block_downloader,
        state_request_protocol_config.name.clone(),
        None,
        peer_store_handle.clone(),
        // set to be force_synced always for domains since they relay on Consensus chain to derive and import domain blocks.
        // If not set, each domain node will wait to be fully synced and as a result will not propagate the transactions over network.
        // It would have been ideal to use `Consensus` chain sync service to respond to `is_major_sync` requests but this
        // would require upstream changes and with some refactoring. This is not worth the effort at the moment since
        // we are planning to enable domain's block request and state sync mechanism in the near future.
        // Until such change has been made, domain's sync service needs to be in force_synced state.
        true,
    )?;
    let sync_service_import_queue = sync_service.clone();
    let sync_service = Arc::new(sync_service);

    let genesis_hash = client
        .hash(Zero::zero())
        .ok()
        .flatten()
        .expect("Genesis block exists; qed");

    // crate transactions protocol and add it to the list of supported protocols of `network_params`
    let (transactions_handler_proto, transactions_config) =
        sc_network_transactions::TransactionsHandlerPrototype::new(
            protocol_id.clone(),
            client
                .block_hash(0u32.into())
                .ok()
                .flatten()
                .expect("Genesis block exists; qed"),
            config.chain_spec.fork_id(),
        );
    net_config.add_notification_protocol(transactions_config);

    let network_params = sc_network::config::Params::<TBl> {
        role: config.role.clone(),
        executor: {
            let spawn_handle = Clone::clone(&spawn_handle);
            Box::new(move |fut| {
                spawn_handle.spawn("libp2p-node", Some("networking"), fut);
            })
        },
        network_config: net_config,
        peer_store: peer_store_handle,
        genesis_hash,
        protocol_id,
        fork_id: config.chain_spec.fork_id().map(ToOwned::to_owned),
        // TODO: False-positive in clippy: https://github.com/rust-lang/rust-clippy/issues/12148
        #[allow(clippy::useless_asref)]
        metrics_registry: config
            .prometheus_config
            .as_ref()
            .map(|config| config.registry.clone()),
        block_announce_config,
    };

    let has_bootnodes = !network_params
        .network_config
        .network_config
        .boot_nodes
        .is_empty();
    let network_mut = sc_network::NetworkWorker::new(network_params)?;
    let network = network_mut.service().clone();

    let (tx_handler, tx_handler_controller) = transactions_handler_proto.build(
        network.clone(),
        sync_service.clone(),
        Arc::new(TransactionPoolAdapter::new(
            transaction_pool,
            client.clone(),
        )),
        // TODO: False-positive in clippy: https://github.com/rust-lang/rust-clippy/issues/12148
        #[allow(clippy::useless_asref)]
        config
            .prometheus_config
            .as_ref()
            .map(|config| &config.registry),
    )?;

    spawn_handle.spawn(
        "network-transactions-handler",
        Some("networking"),
        tx_handler.run(),
    );
    spawn_handle.spawn_blocking(
        "chain-sync-network-service-provider",
        Some("networking"),
        chain_sync_network_provider.run(network.clone()),
    );
    spawn_handle.spawn(
        "import-queue",
        None,
        import_queue.run(Box::new(sync_service_import_queue)),
    );
    spawn_handle.spawn_blocking("syncing", None, engine.run());

    let (system_rpc_tx, system_rpc_rx) = tracing_unbounded("mpsc_system_rpc", 10_000);
    spawn_handle.spawn(
        "system-rpc-handler",
        Some("networking"),
        build_system_rpc_future(
            config.role.clone(),
            network_mut.service().clone(),
            sync_service.clone(),
            client.clone(),
            system_rpc_rx,
            has_bootnodes,
        ),
    );

    let future = build_network_future(network_mut, client, sync_service.clone());

    // TODO: Normally, one is supposed to pass a list of notifications protocols supported by the
    // node through the `NetworkConfiguration` struct. But because this function doesn't know in
    // advance which components, such as GrandPa or Polkadot, will be plugged on top of the
    // service, it is unfortunately not possible to do so without some deep refactoring. To bypass
    // this problem, the `NetworkService` provides a `register_notifications_protocol` method that
    // can be called even after the network has been initialized. However, we want to avoid the
    // situation where `register_notifications_protocol` is called *after* the network actually
    // connects to other peers. For this reason, we delay the process of the network future until
    // the user calls `NetworkStarter::start_network`.
    //
    // This entire hack should eventually be removed in favour of passing the list of protocols
    // through the configuration.
    //
    // See also https://github.com/paritytech/substrate/issues/6827
    let (network_start_tx, network_start_rx) = oneshot::channel();

    // The network worker is responsible for gathering all network messages and processing
    // them. This is quite a heavy task, and at the time of the writing of this comment it
    // frequently happens that this future takes several seconds or in some situations
    // even more than a minute until it has processed its entire queue. This is clearly an
    // issue, and ideally we would like to fix the network future to take as little time as
    // possible, but we also take the extra harm-prevention measure to execute the networking
    // future using `spawn_blocking`.
    spawn_handle.spawn_blocking("network-worker", Some("networking"), async move {
        if network_start_rx.await.is_err() {
            log::warn!(
                "The NetworkStart returned as part of `build_network` has been silently dropped"
            );
            // This `return` might seem unnecessary, but we don't want to make it look like
            // everything is working as normal even though the user is clearly misusing the API.
            return;
        }

        future.await
    });

    Ok((
        network,
        system_rpc_tx,
        tx_handler_controller,
        NetworkStarter::new(network_start_tx),
        sync_service,
    ))
}

/// Builds a future that continuously polls the network.
async fn build_network_future<
    B: BlockT,
    C: BlockchainEvents<B>
        + HeaderBackend<B>
        + BlockBackend<B>
        + HeaderMetadata<B, Error = sp_blockchain::Error>
        + ProofProvider<B>
        + Send
        + Sync
        + 'static,
    H: sc_network_common::ExHashT,
>(
    network: sc_network::NetworkWorker<B, H>,
    client: Arc<C>,
    sync_service: Arc<SyncingService<B>>,
) {
    // Stream of finalized blocks reported by the client.
    let mut finality_notification_stream = client.finality_notification_stream().fuse();

    let network_run = network.run().fuse();
    futures::pin_mut!(network_run);

    loop {
        futures::select! {
            // List of blocks that the client has finalized.
            notification = finality_notification_stream.select_next_some() => {
                sync_service.on_block_finalized(notification.hash, notification.header);
            }

            // Drive the network. Shut down the network future if `NetworkWorker` has terminated.
            _ = network_run => {
                tracing::debug!("`NetworkWorker` has terminated, shutting down the network future.");
                return
            }
        }
    }
}
