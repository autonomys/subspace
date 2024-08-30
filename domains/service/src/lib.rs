//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

pub mod config;
mod domain;
pub mod providers;
pub mod rpc;

pub use self::domain::{new_full, DomainOperator, DomainParams, FullPool, NewFull};
use futures::channel::oneshot;
use futures::{FutureExt, StreamExt};
use sc_client_api::{BlockBackend, BlockchainEvents, HeaderBackend, ProofProvider};
use sc_consensus::ImportQueue;
use sc_domains::RuntimeExecutor;
use sc_network::config::Roles;
use sc_network::{NetworkService, NetworkWorker};
use sc_network_sync::block_relay_protocol::BlockDownloader;
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
use sp_blockchain::HeaderMetadata;
use sp_consensus::block_validation::{Chain, DefaultBlockAnnounceValidator};
use sp_runtime::traits::{Block as BlockT, BlockIdTo, Zero};
use std::sync::Arc;

/// Domain full client.
pub type FullClient<Block, RuntimeApi> = TFullClient<Block, RuntimeApi, RuntimeExecutor>;

pub type FullBackend<Block> = sc_service::TFullBackend<Block>;

/// Build the network service, the network status sinks and an RPC sender.
///
/// Port from `sc_service::build_network` mostly the same with block sync disabled.
// TODO: Struct for returned value
#[allow(clippy::type_complexity)]
pub fn build_network<TBl, TExPool, TImpQu, TCl>(
    params: BuildNetworkParams<
        TBl,
        NetworkWorker<TBl, <TBl as BlockT>::Hash>,
        TExPool,
        TImpQu,
        TCl,
    >,
) -> Result<
    (
        Arc<NetworkService<TBl, <TBl as BlockT>::Hash>>,
        TracingUnboundedSender<sc_rpc::system::Request<TBl>>,
        sc_network_transactions::TransactionsHandlerController<<TBl as BlockT>::Hash>,
        NetworkStarter,
        Arc<SyncingService<TBl>>,
        Arc<dyn BlockDownloader<TBl>>,
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
        metrics,
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
    let genesis_hash = client
        .hash(Zero::zero())
        .ok()
        .flatten()
        .expect("Genesis block exists; qed");

    let (chain_sync_network_provider, chain_sync_network_handle) = NetworkServiceProvider::new();
    let (mut block_server, block_downloader, block_request_protocol_config) = match block_relay {
        Some(params) => (
            params.server,
            params.downloader,
            params.request_response_config,
        ),
        None => {
            // Custom protocol was not specified, use the default block handler.
            let params = BlockRequestHandler::new::<NetworkWorker<TBl, <TBl as BlockT>::Hash>>(
                chain_sync_network_handle.clone(),
                &protocol_id,
                config.chain_spec.fork_id(),
                client.clone(),
                config.network.default_peers_set.in_peers as usize
                    + config.network.default_peers_set.out_peers as usize,
            );
            (
                params.server,
                params.downloader,
                params.request_response_config,
            )
        }
    };
    spawn_handle.spawn("block-request-handler", Some("networking"), async move {
        block_server.run().await;
    });

    // crate transactions protocol and add it to the list of supported protocols of `network_params`
    let peer_store_handle = net_config.peer_store_handle();
    let (transactions_handler_proto, transactions_config) =
        sc_network_transactions::TransactionsHandlerPrototype::new::<
            _,
            _,
            NetworkWorker<TBl, <TBl as BlockT>::Hash>,
        >(
            protocol_id.clone(),
            genesis_hash,
            config.chain_spec.fork_id(),
            metrics.clone(),
            Arc::clone(&peer_store_handle),
        );
    net_config.add_notification_protocol(transactions_config);

    // Start task for `PeerStore`
    let peer_store = net_config.take_peer_store();
    spawn_handle.spawn("peer-store", Some("networking"), peer_store.run());

    let state_request_protocol_config = {
        // Allow both outgoing and incoming requests.
        let (handler, protocol_config) =
            StateRequestHandler::new::<NetworkWorker<TBl, <TBl as BlockT>::Hash>>(
                &protocol_id,
                config.chain_spec.fork_id(),
                client.clone(),
                config.network.default_peers_set_num_full as usize,
            );
        spawn_handle.spawn("state-request-handler", Some("networking"), handler.run());
        protocol_config
    };

    net_config.add_request_response_protocol(block_request_protocol_config);
    net_config.add_request_response_protocol(state_request_protocol_config.clone());

    let (engine, sync_service, block_announce_config) = SyncingEngine::new(
        Roles::from(&config.role),
        client.clone(),
        config
            .prometheus_config
            .as_ref()
            .map(|config| config.registry.clone())
            .as_ref(),
        metrics.clone(),
        &net_config,
        protocol_id.clone(),
        &config.chain_spec.fork_id().map(ToOwned::to_owned),
        Box::new(DefaultBlockAnnounceValidator),
        None,
        chain_sync_network_handle,
        import_queue.service(),
        block_downloader.clone(),
        state_request_protocol_config.name.clone(),
        None,
        peer_store_handle,
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

    let network_params = sc_network::config::Params::<TBl, _, _> {
        role: config.role.clone(),
        executor: {
            let spawn_handle = Clone::clone(&spawn_handle);
            Box::new(move |fut| {
                spawn_handle.spawn("libp2p-node", Some("networking"), fut);
            })
        },
        network_config: net_config,
        genesis_hash,
        protocol_id,
        fork_id: config.chain_spec.fork_id().map(ToOwned::to_owned),
        metrics_registry: config
            .prometheus_config
            .as_ref()
            .map(|config| config.registry.clone()),
        block_announce_config,
        bitswap_config: None,
        notification_metrics: metrics,
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
        build_system_rpc_future::<_, _, <TBl as BlockT>::Hash>(
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
        block_downloader,
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
    network: NetworkWorker<B, H>,
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
