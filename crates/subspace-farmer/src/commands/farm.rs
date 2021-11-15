use crate::commitments::Commitments;
use crate::farming::Farming;
use crate::identity::Identity;
use crate::object_mappings::ObjectMappings;
use crate::plot::Plot;
use crate::plotting::Plotting;
use crate::ws_rpc::WsRpc;
use crate::ws_rpc_server::{RpcServer, RpcServerImpl};
use anyhow::{anyhow, Result};
use jsonrpsee::ws_server::WsServerBuilder;
use log::info;
use std::net::SocketAddr;
use std::path::PathBuf;
use subspace_solving::SubspaceCodec;

/// Start farming by using plot in specified path and connecting to WebSocket server at specified
/// address.
pub(crate) async fn farm(
    base_directory: PathBuf,
    node_rpc_url: &str,
    ws_server_listen_addr: SocketAddr,
) -> Result<(), anyhow::Error> {
    // TODO: This doesn't account for the fact that node can
    // have a completely different history to what farmer expects
    info!("Opening plot");
    let plot = Plot::open_or_create(&base_directory).await?;

    info!("Opening commitments");
    let commitments = Commitments::new(base_directory.join("commitments").into()).await?;

    info!("Opening object mapping");
    let object_mappings = tokio::task::spawn_blocking({
        let path = base_directory.join("object-mappings");
        move || ObjectMappings::new(&path)
    })
    .await??;

    info!("Connecting to node at {}", node_rpc_url);
    let client = WsRpc::new(node_rpc_url).await?;

    let identity = Identity::open_or_create(&base_directory)?;

    let subspace_codec = SubspaceCodec::new(&identity.public_key());

    // Start RPC server
    let ws_server = WsServerBuilder::default()
        .build(ws_server_listen_addr)
        .await?;
    let ws_server_addr = ws_server.local_addr()?;
    let rpc_server = RpcServerImpl::new(plot.clone(), subspace_codec);
    let _stop_handle = ws_server.start(rpc_server.into_rpc())?;

    info!("WS RPC server listening on {}", ws_server_addr);

    // start the farming task
    let farming_instance =
        Farming::start(plot.clone(), commitments.clone(), client.clone(), identity);

    // start the background plotting
    let plotting_instance =
        Plotting::start(plot, commitments, object_mappings, client, subspace_codec);

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
