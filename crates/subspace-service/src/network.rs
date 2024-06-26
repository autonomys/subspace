use futures::channel::oneshot;
use futures::{pin_mut, FutureExt, StreamExt};
use sc_client_api::{BlockBackend, BlockchainEvents, ProofProvider};
use sc_consensus::ImportQueue;
use sc_network::config::{ExHashT, PeerStore};
use sc_network::service::traits::RequestResponseConfig;
use sc_network::{NetworkBackend, NetworkBlock, Roles};
use sc_network_light::light_client_requests::handler::LightClientRequestHandler;
use sc_network_sync::block_request_handler::BlockRequestHandler;
use sc_network_sync::engine::SyncingEngine;
use sc_network_sync::service::network::NetworkServiceProvider;
use sc_network_sync::state_request_handler::StateRequestHandler;
use sc_network_sync::warp_request_handler::RequestHandler as WarpSyncRequestHandler;
use sc_network_sync::{SyncingService, WarpSyncParams};
use sc_service::config::SyncMode;
use sc_service::{
    build_system_rpc_future, BuildNetworkParams, NetworkStarter, TransactionPoolAdapter,
};
use sc_transaction_pool_api::TransactionPool;
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedSender};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::block_validation::{Chain, DefaultBlockAnnounceValidator};
use sp_runtime::traits::{Block as BlockT, BlockIdTo, Header, Zero};
use std::sync::Arc;
use tracing::{debug, warn};

/// Build the network service, the network status sinks and an RPC sender.
pub fn build_network<TBl, TNet, TExPool, TImpQu, TCl>(
    params: BuildNetworkParams<TBl, TNet, TExPool, TImpQu, TCl>,
) -> Result<
    (
        Arc<dyn sc_network::service::traits::NetworkService>,
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
    TExPool: TransactionPool<Block = TBl, Hash = <TBl as BlockT>::Hash> + 'static,
    TImpQu: ImportQueue<TBl> + 'static,
    TNet: NetworkBackend<TBl, <TBl as BlockT>::Hash>,
{
    let BuildNetworkParams {
        config,
        mut net_config,
        client,
        transaction_pool,
        spawn_handle,
        import_queue,
        block_announce_validator_builder,
        warp_sync_params,
        block_relay,
        metrics,
    } = params;

    if warp_sync_params.is_none() && config.network.sync_mode.is_warp() {
        return Err("Warp sync enabled, but no warp sync provider configured.".into());
    }

    if client.requires_full_sync() {
        match config.network.sync_mode {
            SyncMode::LightState { .. } => {
                return Err("Fast sync doesn't work for archive nodes".into())
            }
            SyncMode::Warp => return Err("Warp sync doesn't work for archive nodes".into()),
            SyncMode::Full => {}
        }
    }

    let protocol_id = config.protocol_id();
    let genesis_hash = client
        .block_hash(0u32.into())
        .ok()
        .flatten()
        .expect("Genesis block exists; qed");

    let block_announce_validator = if let Some(f) = block_announce_validator_builder {
        f(client.clone())
    } else {
        Box::new(DefaultBlockAnnounceValidator)
    };

    let (chain_sync_network_provider, chain_sync_network_handle) = NetworkServiceProvider::new();
    let (mut block_server, block_downloader, block_request_protocol_config) = match block_relay {
        Some(params) => (
            params.server,
            params.downloader,
            params.request_response_config,
        ),
        None => {
            // Custom protocol was not specified, use the default block handler.
            // Allow both outgoing and incoming requests.
            let params = BlockRequestHandler::new::<TNet>(
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

    let (state_request_protocol_config, state_request_protocol_name) = {
        let num_peer_hint = net_config.network_config.default_peers_set_num_full as usize
            + net_config
                .network_config
                .default_peers_set
                .reserved_nodes
                .len();
        // Allow both outgoing and incoming requests.
        let (handler, protocol_config) = StateRequestHandler::new::<TNet>(
            &protocol_id,
            config.chain_spec.fork_id(),
            client.clone(),
            num_peer_hint,
        );
        let config_name = protocol_config.protocol_name().clone();

        spawn_handle.spawn("state-request-handler", Some("networking"), handler.run());
        (protocol_config, config_name)
    };

    let (warp_sync_protocol_config, warp_request_protocol_name) = match warp_sync_params.as_ref() {
        Some(WarpSyncParams::WithProvider(warp_with_provider)) => {
            // Allow both outgoing and incoming requests.
            let (handler, protocol_config) = WarpSyncRequestHandler::new::<_, TNet>(
                protocol_id.clone(),
                genesis_hash,
                config.chain_spec.fork_id(),
                warp_with_provider.clone(),
            );
            let config_name = protocol_config.protocol_name().clone();

            spawn_handle.spawn(
                "warp-sync-request-handler",
                Some("networking"),
                handler.run(),
            );
            (Some(protocol_config), Some(config_name))
        }
        _ => (None, None),
    };

    let light_client_request_protocol_config = {
        // Allow both outgoing and incoming requests.
        let (handler, protocol_config) = LightClientRequestHandler::new::<TNet>(
            &protocol_id,
            config.chain_spec.fork_id(),
            client.clone(),
        );
        spawn_handle.spawn(
            "light-client-request-handler",
            Some("networking"),
            handler.run(),
        );
        protocol_config
    };

    // install request handlers to `FullNetworkConfiguration`
    net_config.add_request_response_protocol(block_request_protocol_config);
    net_config.add_request_response_protocol(state_request_protocol_config);
    net_config.add_request_response_protocol(light_client_request_protocol_config);

    if let Some(config) = warp_sync_protocol_config {
        net_config.add_request_response_protocol(config);
    }

    let bitswap_config = config.network.ipfs_server.then(|| {
        let (handler, config) = TNet::bitswap_server(client.clone());
        spawn_handle.spawn("bitswap-request-handler", Some("networking"), handler);

        config
    });

    // create transactions protocol and add it to the list of supported protocols of
    let peer_store_handle = net_config.peer_store_handle();
    let (transactions_handler_proto, transactions_config) =
        sc_network_transactions::TransactionsHandlerPrototype::new::<_, TBl, TNet>(
            protocol_id.clone(),
            genesis_hash,
            config.chain_spec.fork_id(),
            metrics.clone(),
            Arc::clone(&peer_store_handle),
        );
    net_config.add_notification_protocol(transactions_config);

    // Start task for `PeerStore`
    let peer_store = net_config.take_peer_store();
    let peer_store_handle = peer_store.handle();
    spawn_handle.spawn("peer-store", Some("networking"), peer_store.run());

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
        block_announce_validator,
        warp_sync_params,
        chain_sync_network_handle,
        import_queue.service(),
        block_downloader,
        state_request_protocol_name,
        warp_request_protocol_name,
        Arc::clone(&peer_store_handle),
        config.network.force_synced,
    )?;
    let sync_service_import_queue = sync_service.clone();
    let sync_service = Arc::new(sync_service);

    let genesis_hash = client
        .hash(Zero::zero())
        .ok()
        .flatten()
        .expect("Genesis block exists; qed");
    let network_params = sc_network::config::Params::<TBl, <TBl as BlockT>::Hash, TNet> {
        role: config.role.clone(),
        executor: {
            let spawn_handle = Clone::clone(&spawn_handle);
            Box::new(move |fut| {
                spawn_handle.spawn("libp2p-node", Some("networking"), fut);
            })
        },
        network_config: net_config,
        genesis_hash,
        protocol_id: protocol_id.clone(),
        fork_id: config.chain_spec.fork_id().map(ToOwned::to_owned),
        metrics_registry: config
            .prometheus_config
            .as_ref()
            .map(|config| config.registry.clone()),
        block_announce_config,
        bitswap_config,
        notification_metrics: metrics,
    };

    let has_bootnodes = !network_params
        .network_config
        .network_config
        .boot_nodes
        .is_empty();
    let network_mut = TNet::new(network_params)?;
    let network = network_mut.network_service().clone();

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
    spawn_handle.spawn_blocking(
        "network-transactions-handler",
        Some("networking"),
        tx_handler.run(),
    );

    spawn_handle.spawn_blocking(
        "chain-sync-network-service-provider",
        Some("networking"),
        chain_sync_network_provider.run(Arc::new(network.clone())),
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
            network_mut.network_service(),
            sync_service.clone(),
            client.clone(),
            system_rpc_rx,
            has_bootnodes,
        ),
    );

    let future = build_network_future::<_, _, <TBl as BlockT>::Hash, _>(
        network_mut,
        client,
        sync_service.clone(),
        config.announce_block,
    );

    // TODO: Normally, one is supposed to pass a list of notifications protocols supported by the
    // node through the `NetworkConfiguration` struct. But because this function doesn't know in
    // advance which components, such as GrandPa or Polkadot, will be plugged on top of the
    // service, it is unfortunately not possible to do so without some deep refactoring. To
    // bypass this problem, the `NetworkService` provides a `register_notifications_protocol`
    // method that can be called even after the network has been initialized. However, we want to
    // avoid the situation where `register_notifications_protocol` is called *after* the network
    // actually connects to other peers. For this reason, we delay the process of the network
    // future until the user calls `NetworkStarter::start_network`.
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
            warn!("The NetworkStart returned as part of `build_network` has been silently dropped");
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
        sync_service.clone(),
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
    H: ExHashT,
    N: NetworkBackend<B, <B as BlockT>::Hash>,
>(
    network: N,
    client: Arc<C>,
    sync_service: Arc<SyncingService<B>>,
    announce_imported_blocks: bool,
) {
    let mut imported_blocks_stream = client.import_notification_stream().fuse();

    // Stream of finalized blocks reported by the client.
    let mut finality_notification_stream = client.finality_notification_stream().fuse();

    let network_run = network.run().fuse();
    pin_mut!(network_run);

    loop {
        futures::select! {
            // List of blocks that the client has imported.
            notification = imported_blocks_stream.next() => {
                let notification = match notification {
                    Some(n) => n,
                    // If this stream is shut down, that means the client has shut down, and the
                    // most appropriate thing to do for the network future is to shut down too.
                    None => {
                        debug!("Block import stream has terminated, shutting down the network future.");
                        return
                    },
                };

                if announce_imported_blocks {
                    sync_service.announce_block(notification.hash, None);
                }

                if notification.is_new_best {
                    sync_service.new_best_block_imported(
                        notification.hash,
                        *notification.header.number(),
                    );
                }
            }

            // List of blocks that the client has finalized.
            notification = finality_notification_stream.select_next_some() => {
                sync_service.on_block_finalized(notification.hash, notification.header);
            }

            // Drive the network. Shut down the network future if `NetworkWorker` has terminated.
            _ = network_run => {
                debug!("`NetworkWorker` has terminated, shutting down the network future.");
                return
            }
        }
    }
}
