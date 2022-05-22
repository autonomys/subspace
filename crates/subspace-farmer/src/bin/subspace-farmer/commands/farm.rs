use anyhow::{anyhow, Result};
use jsonrpsee::ws_server::WsServerBuilder;
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::PIECE_SIZE;
use subspace_farmer::multi_farming::{MultiFarming, Options as MultiFarmingOptions};
use subspace_farmer::ws_rpc_server::{RpcServer, RpcServerImpl};
use subspace_farmer::{retrieve_piece_from_plots, NodeRpcClient, ObjectMappings, Plot, RpcClient};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::multihash::Multihash;
use subspace_networking::multimess::MultihashCode;
use subspace_networking::Config;
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
    }: FarmingArgs,
) -> Result<(), anyhow::Error> {
    utils::raise_fd_limit();

    info!("Connecting to node at {}", node_rpc_url);
    let client = NodeRpcClient::new(&node_rpc_url).await?;

    let metadata = client
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
            client,
            object_mappings: object_mappings.clone(),
            reward_address,
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
