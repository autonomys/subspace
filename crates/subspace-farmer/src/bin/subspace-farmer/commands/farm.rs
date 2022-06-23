use anyhow::{anyhow, Result};
use jsonrpsee::ws_server::WsServerBuilder;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::PIECE_SIZE;
use subspace_farmer::multi_farming::{MultiFarming, Options as MultiFarmingOptions};
use subspace_farmer::ws_rpc_server::{RpcServer, RpcServerImpl};
use subspace_farmer::{NodeRpcClient, ObjectMappings, Plot, RpcClient};
use subspace_rpc_primitives::FarmerMetadata;
use tracing::{info, warn};

use crate::{utils, FarmingArgs};

/// Start farming by using multiple replica plot in specified path and connecting to WebSocket
/// server at specified address.
pub(crate) async fn farm(
    base_directory: PathBuf,
    FarmingArgs {
        bootstrap_nodes,
        listen_on,
        node_rpc_url,
        mut ws_server_listen_addr,
        reward_address,
        plot_size,
        max_plot_size,
        enable_dsn_archiving,
    }: FarmingArgs,
) -> Result<(), anyhow::Error> {
    utils::raise_fd_limit();

    if plot_size < 1024 * 1024 {
        return Err(anyhow::anyhow!(
            "Plot size is too low ({plot_size} bytes). Did you mean {plot_size}G or {plot_size}T?"
        ));
    }

    info!("Connecting to node at {}", node_rpc_url);
    let archiving_client = NodeRpcClient::new(&node_rpc_url).await?;
    let farming_client = NodeRpcClient::new(&node_rpc_url).await?;

    let metadata = farming_client
        .farmer_metadata()
        .await
        .map_err(|error| anyhow!(error))?;

    let max_plot_size = match max_plot_size.map(|max_plot_size| max_plot_size / PIECE_SIZE as u64) {
        Some(max_plot_size) if max_plot_size > metadata.max_plot_size => {
            warn!("Passed `max_plot_size` is too big. Fallback to the one from consensus.");
            metadata.max_plot_size
        }
        Some(max_plot_size) => max_plot_size,
        None => metadata.max_plot_size,
    };

    let FarmerMetadata {
        record_size,
        recorded_history_segment_size,
        ..
    } = metadata;

    info!("Opening object mapping");
    let object_mappings = tokio::task::spawn_blocking({
        let base_directory = base_directory.clone();

        move || ObjectMappings::open_or_create(&base_directory)
    })
    .await??;

    let multi_farming = MultiFarming::new(
        MultiFarmingOptions {
            base_directory: base_directory.clone(),
            archiving_client,
            farming_client,
            object_mappings: object_mappings.clone(),
            reward_address,
            bootstrap_nodes,
            listen_on,
            enable_dsn_archiving,
        },
        plot_size,
        max_plot_size,
        move |plot_index, public_key, max_piece_count| {
            Plot::open_or_create(
                base_directory.join(format!("plot{plot_index}")),
                public_key,
                max_piece_count,
            )
        },
        true,
    )
    .await?;

    // Start RPC server
    let ws_server = match WsServerBuilder::default()
        .build(ws_server_listen_addr)
        .await
    {
        Ok(ws_server) => ws_server,
        Err(jsonrpsee::core::Error::Transport(error)) => {
            warn!(
                address = %ws_server_listen_addr,
                %error,
                "Failed to start WebSocket RPC server on, trying random port"
            );
            ws_server_listen_addr.set_port(0);
            WsServerBuilder::default()
                .build(ws_server_listen_addr)
                .await?
        }
        Err(error) => {
            return Err(error.into());
        }
    };
    let ws_server_addr = ws_server.local_addr()?;
    let rpc_server = RpcServerImpl::new(
        record_size,
        recorded_history_segment_size,
        Arc::clone(&multi_farming.plots),
        object_mappings.clone(),
    );
    let _stop_handle = ws_server.start(rpc_server.into_rpc())?;

    info!("WS RPC server listening on {ws_server_addr}");

    multi_farming.wait().await
}
