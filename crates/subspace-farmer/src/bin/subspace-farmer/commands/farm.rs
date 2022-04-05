use anyhow::{anyhow, Result};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use jsonrpsee::ws_server::WsServerBuilder;
use log::info;
use std::mem;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::PIECE_SIZE;
use subspace_farmer::multi_farming::create_multi_farming;
use subspace_farmer::ws_rpc_server::{RpcServer, RpcServerImpl};
use subspace_farmer::{
    retrieve_piece_from_plots, Identity, ObjectMappings, Plot, RpcClient, WsRpc,
};
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
        ws_server_listen_addr,
        reward_address,
        plot_size,
    }: FarmingArgs,
    best_block_number_check_interval: Duration,
) -> Result<(), anyhow::Error> {
    let base_directory = crate::utils::get_path(custom_path);

    let reward_address = if let Some(reward_address) = reward_address {
        reward_address
    } else {
        let identity = Identity::open_or_create(&base_directory)?;
        identity.public_key().to_bytes().into()
    };

    info!("Connecting to node at {}", node_rpc_url);
    let client = WsRpc::new(&node_rpc_url).await?;

    let FarmerMetadata {
        record_size,
        recorded_history_segment_size,
        max_plot_size,
        ..
    } = client
        .farmer_metadata()
        .await
        .map_err(|error| anyhow!(error))?;

    info!("Opening object mapping");
    let object_mappings = tokio::task::spawn_blocking({
        let base_directory = base_directory.clone();

        move || ObjectMappings::open_or_create(&base_directory)
    })
    .await??;

    // TODO: Piece count should account for database overhead of various additional databases
    // For now assume 80% will go for plot itself
    let plot_size = plot_size * 4 / 5 / PIECE_SIZE as u64;

    let (plots, farming_plotting) = create_multi_farming(
        base_directory,
        client,
        object_mappings.clone(),
        plot_size,
        max_plot_size,
        reward_address,
        best_block_number_check_interval,
    )
    .await?;
    let plots = Arc::new(plots);

    // Start RPC server
    let ws_server = WsServerBuilder::default()
        .build(ws_server_listen_addr)
        .await?;
    let ws_server_addr = ws_server.local_addr()?;
    let rpc_server = RpcServerImpl::new(
        record_size,
        recorded_history_segment_size,
        Arc::clone(&plots),
        object_mappings.clone(),
    );
    let _stop_handle = ws_server.start(rpc_server.into_rpc())?;

    info!("WS RPC server listening on {}", ws_server_addr);

    let (node, mut node_runner) = subspace_networking::create(Config {
        bootstrap_nodes,
        listen_on,
        value_getter: Arc::new({
            let plots = Arc::clone(&plots);

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

    // Wait for any incoming error from farming or plotting
    let mut farming_plotting = farming_plotting
        .into_iter()
        .map(|(farming, plotting)| async move {
            tokio::select! {
                res = plotting.wait() => if let Err(error) = res {
                    return Err(anyhow!(error))
                },
                res = farming.wait() => if let Err(error) = res {
                    return Err(anyhow!(error))
                },
            }
            Ok(())
        })
        .collect::<FuturesUnordered<_>>();

    while let Some(res) = farming_plotting.next().await {
        res?;
    }

    Ok(())
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
