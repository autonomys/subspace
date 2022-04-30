use anyhow::{anyhow, Result};
use jsonrpsee::ws_server::WsServerBuilder;
use log::{info, warn};
use std::mem;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::PIECE_SIZE;
use subspace_farmer::multi_farming::MultiFarming;
use subspace_farmer::ws_rpc_server::{RpcServer, RpcServerImpl};
use subspace_farmer::{retrieve_piece_from_plots, NodeRpcClient, ObjectMappings, Plot, RpcClient};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::multihash::Multihash;
use subspace_networking::multimess::MultihashCode;
use subspace_networking::Config;
use subspace_rpc_primitives::FarmerMetadata;

use crate::FarmingArgs;

/// Start farming by using multiple replica plot in specified path and connecting to WebSocket
/// server at specified address.
pub(crate) async fn farm(
    FarmingArgs {
        bootstrap_nodes,
        custom_path,
        listen_on,
        node_rpc_url,
        mut ws_server_listen_addr,
        reward_address,
        plot_size,
        max_plot_size,
    }: FarmingArgs,
    best_block_number_check_interval: Duration,
) -> Result<(), anyhow::Error> {
    let base_directory = crate::utils::get_path(custom_path);

    info!("Connecting to node at {}", node_rpc_url);
    let client = NodeRpcClient::new(&node_rpc_url).await?;

    let metadata = client
        .farmer_metadata()
        .await
        .map_err(|error| anyhow!(error))?;
    let max_plot_size = max_plot_size
        .map(|max_plot_size| max_plot_size / PIECE_SIZE as u64)
        .unwrap_or(metadata.max_plot_size);

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

    // TODO: we need to remember plot size in order to prune unused plots in future if plot size is
    // less than it was specified before.
    // TODO: Piece count should account for database overhead of various additional databases
    // For now assume 80% will go for plot itself
    let plot_size = plot_size * 4 / 5 / PIECE_SIZE as u64;

    let plot_sizes = std::iter::repeat(max_plot_size).take((plot_size / max_plot_size) as usize);
    let plot_sizes = if plot_size % max_plot_size > 0 {
        plot_sizes
            .chain(std::iter::once(plot_size % max_plot_size))
            .collect::<Vec<_>>()
    } else {
        plot_sizes.collect()
    };

    let multi_farming = MultiFarming::new(
        base_directory,
        client,
        object_mappings.clone(),
        plot_sizes,
        reward_address,
        best_block_number_check_interval,
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
                "Failed to start WebSocket RPC server on {ws_server_listen_addr} ({error}),\
                trying random port"
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

    info!("WS RPC server listening on {}", ws_server_addr);

    let (node, mut node_runner) = subspace_networking::create(Config {
        bootstrap_nodes,
        listen_on,
        value_getter: Arc::new({
            let plots = Arc::clone(&multi_farming.plots);

            move |key| networking_getter(&plots, key)
        }),
        allow_non_globals_in_dht: true,
        // TODO: Persistent identity
        ..Config::with_generated_keypair()
    })
    .await?;

    node.on_new_listener(Arc::new({
        let node_id = node.id();

        move |multiaddr| {
            info!(
                "Listening on {}",
                multiaddr.clone().with(Protocol::P2p(node_id.into()))
            );
        }
    }))
    .detach();

    tokio::spawn(async move {
        info!("Starting subspace network node instance");

        node_runner.run().await;
    });

    multi_farming.wait().await
}

fn networking_getter(plots: &[Plot], key: &Multihash) -> Option<Vec<u8>> {
    let code = key.code();

    if code != u64::from(MultihashCode::Piece) && code != u64::from(MultihashCode::PieceIndex) {
        return None;
    }

    let piece_index = u64::from_le_bytes(key.digest()[..mem::size_of::<u64>()].try_into().ok()?);

    retrieve_piece_from_plots(plots, piece_index)
        .expect("Decoding of local pieces must never fail")
        .map(|piece| piece.to_vec())
}
