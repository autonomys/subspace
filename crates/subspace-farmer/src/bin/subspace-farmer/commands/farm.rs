use anyhow::{anyhow, Result};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use jsonrpsee::ws_server::WsServerBuilder;
use log::info;
use std::mem;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{PublicKey, PIECE_SIZE};
use subspace_farmer::ws_rpc_server::{RpcServer, RpcServerImpl};
use subspace_farmer::{
    Commitments, FarmerData, Farming, Identity, ObjectMappings, Plot, Plotting, RpcClient, WsRpc,
};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::multihash::Multihash;
use subspace_networking::multimess::MultihashCode;
use subspace_networking::Config;
use subspace_rpc_primitives::FarmerMetadata;
use subspace_solving::SubspaceCodec;

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

    let (plots, mut farming_plotting): (Arc<Vec<_>>, FuturesUnordered<_>) = {
        let plot_size = plot_size / PIECE_SIZE as u64;
        let single_plot_sizes =
            std::iter::repeat(max_plot_size).take((plot_size / max_plot_size) as usize);
        let single_plot_sizes = if plot_size % max_plot_size > 0 {
            single_plot_sizes
                .chain(std::iter::once(plot_size % max_plot_size))
                .collect::<Vec<_>>()
        } else {
            single_plot_sizes.collect()
        };

        let (mut plots, farming_plotting) = <(Vec<_>, FuturesUnordered<_>)>::default();

        for (base_directory, max_plot_pieces) in (0..)
            .map(|i| base_directory.join(format!("plot{i}")))
            .zip(single_plot_sizes)
        {
            let (plot, plotting, farming) = farm_single_plot(
                base_directory,
                reward_address,
                client.clone(),
                object_mappings.clone(),
                max_plot_pieces,
                best_block_number_check_interval,
            )
            .await?;
            plots.push(plot);
            farming_plotting.push(Box::pin(async move {
                tokio::select! {
                    res = plotting.wait() => if let Err(error) = res {
                        return Err(anyhow!(error))
                    },
                    res = farming.wait() => if let Err(error) = res {
                        return Err(anyhow!(error))
                    },
                }
                Ok(())
            }));
        }

        (Arc::new(plots), farming_plotting)
    };

    // Start RPC server
    let ws_server = WsServerBuilder::default()
        .build(ws_server_listen_addr)
        .await?;
    let ws_server_addr = ws_server.local_addr()?;
    let rpc_server = RpcServerImpl::new(
        record_size,
        recorded_history_segment_size,
        Vec::clone(&*plots),
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
    while let Some(res) = farming_plotting.next().await {
        match res {
            Ok(()) => (),
            Err(_) => return res,
        }
    }

    Ok(())
}

/// Starts farming for a single plot in specified base directory.
pub(crate) async fn farm_single_plot(
    base_directory: impl AsRef<Path>,
    reward_address: PublicKey,
    client: WsRpc,
    object_mappings: ObjectMappings,
    max_plot_pieces: u64,
    best_block_number_check_interval: Duration,
) -> Result<(Plot, Plotting, Farming), anyhow::Error> {
    let identity = Identity::open_or_create(&base_directory)?;
    let address = identity.public_key().to_bytes().into();

    // TODO: This doesn't account for the fact that node can
    // have a completely different history to what farmer expects
    info!("Opening plot");
    let plot = tokio::task::spawn_blocking({
        let base_directory = base_directory.as_ref().to_owned();

        // TODO: Piece count should account for database overhead of various additional databases
        move || Plot::open_or_create(&base_directory, address, max_plot_pieces)
    })
    .await
    .unwrap()?;

    info!("Opening commitments");
    let commitments_fut = tokio::task::spawn_blocking({
        let path = base_directory.as_ref().join("commitments");

        move || Commitments::new(path)
    });
    let commitments = commitments_fut.await.unwrap()?;

    let subspace_codec = SubspaceCodec::new(identity.public_key());

    // start the farming task
    let farming_instance = Farming::start(
        plot.clone(),
        commitments.clone(),
        client.clone(),
        identity,
        reward_address,
    );

    let farmer_data = FarmerData::new(
        plot.clone(),
        commitments,
        object_mappings,
        client
            .farmer_metadata()
            .await
            .map_err(|error| anyhow!(error))?,
    );

    // start the background plotting
    let plotting_instance = Plotting::start(
        farmer_data,
        client,
        subspace_codec,
        best_block_number_check_interval,
    );

    Ok((plot, plotting_instance, farming_instance))
}

fn networking_getter(plots: &[Plot], key: &Multihash) -> Option<Vec<u8>> {
    let code = key.code();

    if code != u64::from(MultihashCode::Piece) && code != u64::from(MultihashCode::PieceIndex) {
        return None;
    }

    let piece_index = u64::from_le_bytes(key.digest()[..mem::size_of::<u64>()].try_into().ok()?);

    let (mut piece, address) = plots.iter().find_map(|plot| {
        plot.read_piece(piece_index)
            .ok()
            .map(|piece| (piece, plot.address()))
    })?;

    SubspaceCodec::new(&address)
        .decode(&mut piece, piece_index)
        .expect("Decoding of local pieces must never fail");
    Some(piece)
}
