use anyhow::{anyhow, Result};
use jsonrpsee::ws_server::WsServerBuilder;
use log::info;
use std::mem;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::PIECE_SIZE;
use subspace_farmer::ws_rpc_server::{RpcServer, RpcServerImpl};
use subspace_farmer::{
    Commitments, FarmerData, Farming, Identity, ObjectMappings, Plot, Plotting, RpcClient, WsRpc,
};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::multimess::MultihashCode;
use subspace_networking::Config;
use subspace_solving::SubspaceCodec;

use crate::FarmingArgs;

/// Start farming by using plot in specified path and connecting to WebSocket server at specified
/// address.
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

    let identity = Identity::open_or_create(&base_directory)?;
    let address = identity.public_key().to_bytes().into();

    let reward_address = reward_address.unwrap_or(address);

    // TODO: This doesn't account for the fact that node can
    // have a completely different history to what farmer expects
    info!("Opening plot");
    let plot_fut = tokio::task::spawn_blocking({
        let base_directory = base_directory.clone();

        // TODO: Piece count should account for database overhead of various additional databases
        move || {
            Plot::open_or_create(
                &base_directory,
                address,
                plot_size.map(|plot_size| plot_size / PIECE_SIZE as u64),
            )
        }
    });
    let plot = plot_fut.await.unwrap()?;

    info!("Opening commitments");
    let commitments_fut = tokio::task::spawn_blocking({
        let path = base_directory.join("commitments");

        move || Commitments::new(path)
    });
    let commitments = commitments_fut.await.unwrap()?;

    info!("Opening object mapping");
    let object_mappings = tokio::task::spawn_blocking({
        let base_directory = base_directory.clone();

        move || ObjectMappings::open_or_create(&base_directory)
    })
    .await??;

    info!("Connecting to node at {}", node_rpc_url);
    let client = WsRpc::new(&node_rpc_url).await?;

    let farmer_metadata = client
        .farmer_metadata()
        .await
        .map_err(|error| anyhow::Error::msg(error.to_string()))?;

    let subspace_codec = SubspaceCodec::new(identity.public_key());

    // Start RPC server
    let ws_server = WsServerBuilder::default()
        .build(ws_server_listen_addr)
        .await?;
    let ws_server_addr = ws_server.local_addr()?;
    let rpc_server = RpcServerImpl::new(
        farmer_metadata.record_size,
        farmer_metadata.recorded_history_segment_size,
        plot.clone(),
        object_mappings.clone(),
        subspace_codec,
    );
    let _stop_handle = ws_server.start(rpc_server.into_rpc())?;

    info!("WS RPC server listening on {}", ws_server_addr);

    let (node, mut node_runner) = subspace_networking::create(Config {
        bootstrap_nodes,
        listen_on,
        value_getter: Arc::new({
            let plot = plot.clone();

            move |key| {
                let code = key.code();

                if code == u64::from(MultihashCode::Piece)
                    || code == u64::from(MultihashCode::PieceIndex)
                {
                    let piece_index =
                        u64::from_le_bytes(key.digest()[..mem::size_of::<u64>()].try_into().ok()?);
                    let mut piece = plot.read_piece(piece_index).ok()?;

                    subspace_codec
                        .decode(&mut piece, piece_index)
                        .expect("Decoding of local pieces must never fail");
                    Some(piece)
                } else {
                    None
                }
            }
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

    // start the farming task
    let farming_instance = Farming::start(
        plot.clone(),
        commitments.clone(),
        client.clone(),
        identity,
        reward_address,
    );

    let farmer_data = FarmerData::new(plot, commitments, object_mappings, farmer_metadata);

    // start the background plotting
    let plotting_instance = Plotting::start(
        farmer_data,
        client,
        subspace_codec,
        best_block_number_check_interval,
    );

    tokio::select! {
        res = plotting_instance.wait() => if let Err(error) = res {
            return Err(anyhow!(error))
        },
        res = farming_instance.wait() => if let Err(error) = res {
            return Err(anyhow!(error))
        },
    }

    Ok(())
}
