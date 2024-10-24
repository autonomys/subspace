use crate::network::execution_receipt_protocol::LastDomainBlockERRequestHandler;
use sc_client_api::{AuxStore, BlockBackend, BlockchainEvents, ProofProvider};
use sc_consensus::ImportQueue;
use sc_network::NetworkBackend;
use sc_network_common::role::Roles;
use sc_network_sync::block_relay_protocol::{BlockDownloader, BlockRelayParams};
use sc_network_sync::engine::SyncingEngine;
use sc_network_sync::service::network::{NetworkServiceHandle, NetworkServiceProvider};
use sc_network_sync::SyncingService;
use sc_service::{
    build_default_block_downloader, build_network_advanced, build_polkadot_syncing_strategy,
    BuildNetworkAdvancedParams, BuildNetworkParams, Error, NetworkStarter,
};
use sc_transaction_pool_api::TransactionPool;
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::ProvideRuntimeApi;
use sp_api::__private::BlockT;
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::block_validation::{Chain, DefaultBlockAnnounceValidator};
use sp_domains::DomainsApi;
use sp_runtime::traits::{BlockIdTo, Header};
use std::sync::Arc;

pub mod execution_receipt_protocol;
pub mod receipt_receiver;

/// Build the network service, the network status sinks and an RPC sender.
#[allow(clippy::type_complexity)]
pub fn build_network<Block, Net, TxPool, IQ, Client, CBlock, CClient, DomainHeader>(
    params: BuildNetworkParams<Block, Net, TxPool, IQ, Client>,
    consensus_client: Arc<CClient>,
) -> Result<
    (
        Arc<dyn sc_network::service::traits::NetworkService>,
        TracingUnboundedSender<sc_rpc::system::Request<Block>>,
        sc_network_transactions::TransactionsHandlerController<<Block as BlockT>::Hash>,
        NetworkStarter,
        Arc<SyncingService<Block>>,
        NetworkServiceHandle,
        Arc<dyn BlockDownloader<Block>>,
    ),
    Error,
>
where
    Block: BlockT<Header = DomainHeader>,
    CBlock: BlockT,
    Client: ProvideRuntimeApi<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + Chain<Block>
        + BlockBackend<Block>
        + BlockIdTo<Block, Error = sp_blockchain::Error>
        + ProofProvider<Block>
        + HeaderBackend<Block>
        + BlockchainEvents<Block>
        + AuxStore
        + 'static,
    TxPool: TransactionPool<Block = Block, Hash = <Block as BlockT>::Hash> + 'static,
    IQ: ImportQueue<Block> + 'static,
    Net: NetworkBackend<Block, <Block as BlockT>::Hash>,
    CClient: ProvideRuntimeApi<CBlock>
        + BlockBackend<CBlock>
        + ProofProvider<CBlock>
        + HeaderBackend<CBlock>
        + Send
        + Sync
        + 'static,
    CClient::Api: DomainsApi<CBlock, DomainHeader>,
    DomainHeader: Header,
{
    let BuildNetworkParams {
        config,
        mut net_config,
        client,
        transaction_pool,
        spawn_handle,
        import_queue,
        block_announce_validator_builder,
        warp_sync_config,
        block_relay,
        metrics,
    } = params;
    let fork_id = config.chain_spec.fork_id();

    let block_announce_validator = if let Some(f) = block_announce_validator_builder {
        f(client.clone())
    } else {
        Box::new(DefaultBlockAnnounceValidator)
    };

    // "Last confirmed domain block execution receipt" request handler
    {
        let num_peer_hint = net_config.network_config.default_peers_set_num_full as usize
            + net_config
                .network_config
                .default_peers_set
                .reserved_nodes
                .len();

        let (handler, protocol_config) = LastDomainBlockERRequestHandler::new::<Net>(
            fork_id,
            consensus_client,
            client.clone(),
            num_peer_hint,
        );
        spawn_handle.spawn(
            "last-domain-execution-receipt-request-handler",
            Some("networking"),
            handler.run(),
        );

        net_config.add_request_response_protocol(protocol_config);
    }

    let network_service_provider = NetworkServiceProvider::new();
    let protocol_id = config.protocol_id();
    let metrics_registry = config
        .prometheus_config
        .as_ref()
        .map(|config| &config.registry);

    let block_downloader = match block_relay {
        Some(params) => {
            let BlockRelayParams {
                mut server,
                downloader,
                request_response_config,
            } = params;

            net_config.add_request_response_protocol(request_response_config);

            spawn_handle.spawn("block-request-handler", Some("networking"), async move {
                server.run().await;
            });

            downloader
        }
        None => build_default_block_downloader(
            &protocol_id,
            fork_id,
            &mut net_config,
            network_service_provider.handle(),
            Arc::clone(&client),
            config.network.default_peers_set.in_peers as usize
                + config.network.default_peers_set.out_peers as usize,
            &spawn_handle,
        ),
    };

    let syncing_strategy = build_polkadot_syncing_strategy(
        protocol_id.clone(),
        fork_id,
        &mut net_config,
        warp_sync_config,
        block_downloader.clone(),
        client.clone(),
        &spawn_handle,
        metrics_registry,
    )?;

    let (syncing_engine, sync_service, block_announce_config) = SyncingEngine::new(
        Roles::from(&config.role),
        Arc::clone(&client),
        metrics_registry,
        metrics.clone(),
        &net_config,
        protocol_id.clone(),
        fork_id,
        block_announce_validator,
        syncing_strategy,
        network_service_provider.handle(),
        import_queue.service(),
        net_config.peer_store_handle(),
        config.network.force_synced,
    )?;

    spawn_handle.spawn_blocking("syncing", None, syncing_engine.run());

    let network_service_handle = network_service_provider.handle();
    build_network_advanced(BuildNetworkAdvancedParams {
        role: config.role,
        protocol_id,
        fork_id,
        ipfs_server: config.network.ipfs_server,
        announce_block: config.announce_block,
        net_config,
        client,
        transaction_pool,
        spawn_handle,
        import_queue,
        sync_service,
        block_announce_config,
        network_service_provider,
        metrics_registry,
        metrics,
    })
    .map(
        |(network_service, system_rpc_tx, tx_handler_controller, network_starter, sync_service)| {
            (
                network_service,
                system_rpc_tx,
                tx_handler_controller,
                network_starter,
                sync_service,
                network_service_handle,
                block_downloader,
            )
        },
    )
}
