use crate::commitments::Commitments;
use crate::farming::Farming;
use crate::identity::Identity;
use crate::object_mappings::ObjectMappings;
use crate::plot::Plot;
use crate::plotting::Plotting;
use crate::rpc::RpcClient;
use anyhow::{anyhow, Result};
use log::info;
use std::path::PathBuf;

/// Start farming by using plot in specified path and connecting to WebSocket server at specified
/// address.
pub(crate) async fn farm(base_directory: PathBuf, ws_server: &str) -> Result<(), anyhow::Error> {
    // TODO: This doesn't account for the fact that node can
    // have a completely different history to what farmer expects
    info!("Opening plot");
    let plot = Plot::open_or_create(&base_directory.clone().into()).await?;

    info!("Opening commitments");
    let commitments = Commitments::new(base_directory.join("commitments").into()).await?;

    info!("Opening object mapping");
    let object_mappings = tokio::task::spawn_blocking({
        let path = base_directory.join("object-mappings");
        move || ObjectMappings::new(&path)
    })
    .await??;

    info!("Connecting to RPC server: {}", ws_server);
    let client = RpcClient::new(ws_server).await?;

    let identity = Identity::open_or_create(&base_directory)?;

    // start the farming task
    let farming_instance = Farming::start(
        plot.clone(),
        commitments.clone(),
        client.clone(),
        identity.clone(),
    );

    // start the background plotting
    let plotting_instance = Plotting::start(plot, commitments, object_mappings, client, identity);

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
