use anyhow::{anyhow, Context, Result};
use jsonrpsee::ws_server::WsServerBuilder;
use log::info;
use std::mem;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::PIECE_SIZE;
use subspace_farmer::ws_rpc_server::{RpcServer, RpcServerImpl};
use subspace_farmer::{
    Commitments, FarmerData, Farming, Identity, MultiPlot, ObjectMappings, Plotting, RpcClient,
    WsRpc,
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

    info!("Connecting to node at {}", node_rpc_url);
    let client = WsRpc::new(&node_rpc_url).await?;

    let farmer_metadata = client
        .farmer_metadata()
        .await
        .map_err(|error| anyhow::Error::msg(error.to_string()))?;

    // TODO: This doesn't account for the fact that node can
    // have a completely different history to what farmer expects
    info!("Opening plot");
    let plot_fut = tokio::task::spawn_blocking({
        let base_directory = base_directory.clone();
        let plot_size = plot_size / PIECE_SIZE as u64;

        let single_plot_sizes = std::iter::repeat(farmer_metadata.max_plot_size)
            .take((plot_size / farmer_metadata.max_plot_size) as usize);
        let single_plot_sizes = if plot_size % farmer_metadata.max_plot_size > 0 {
            single_plot_sizes
                .chain(std::iter::once(plot_size % farmer_metadata.max_plot_size))
                .collect()
        } else {
            single_plot_sizes.collect()
        };

        // TODO: Piece count should account for database overhead of various additional databases
        move || MultiPlot::open_or_create(&base_directory, single_plot_sizes)
    });
    let (multiplot, identities) = plot_fut.await.unwrap()?;

    info!("Opening commitments");
    let commitments_fut = tokio::task::spawn_blocking({
        let multiplot = multiplot.clone();

        move || Commitments::from_multiplot(&multiplot)
    });
    let commitments = commitments_fut.await.unwrap()?;

    info!("Opening object mapping");
    let object_mappings = tokio::task::spawn_blocking({
        let base_directory = base_directory.clone();

        move || ObjectMappings::open_or_create(&base_directory)
    })
    .await??;

    // Start RPC server
    let ws_server = WsServerBuilder::default()
        .build(ws_server_listen_addr)
        .await?;
    let ws_server_addr = ws_server.local_addr()?;
    let rpc_server = RpcServerImpl::new(
        farmer_metadata.record_size,
        farmer_metadata.recorded_history_segment_size,
        multiplot.clone(),
        object_mappings.clone(),
    );
    let _stop_handle = ws_server.start(rpc_server.into_rpc())?;

    info!("WS RPC server listening on {}", ws_server_addr);

    let (node, mut node_runner) = subspace_networking::create(Config {
        bootstrap_nodes,
        listen_on,
        value_getter: Arc::new({
            let multiplot = multiplot.clone();

            move |key| {
                let code = key.code();

                if code == u64::from(MultihashCode::Piece)
                    || code == u64::from(MultihashCode::PieceIndex)
                {
                    let piece_index =
                        u64::from_le_bytes(key.digest()[..mem::size_of::<u64>()].try_into().ok()?);
                    let (address, mut piece) = multiplot.read(piece_index)?;

                    SubspaceCodec::new(&address)
                        .decode(&mut piece, piece_index)
                        .expect("Decoding of local pieces must never fail");
                    Some(piece.to_vec())
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
        multiplot.clone(),
        commitments.clone(),
        client.clone(),
        identities,
        reward_address,
    );

    let farmer_data = FarmerData::new(
        multiplot,
        commitments,
        farmer_metadata,
        best_block_number_check_interval,
    );

    // start the background plotting
    let plotting_instance = Plotting::start(farmer_data, object_mappings, client)
        .await
        .context("Failed to start plotting")?;

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
