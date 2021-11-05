use crate::commitments::Commitments;
use crate::farming::Farming;
use crate::identity::Identity;
use crate::object_mappings::ObjectMappings;
use crate::plot::Plot;
use crate::rpc::RpcClient;
use anyhow::{anyhow, Result};
use log::info;
use std::path::PathBuf;

/// Start farming by using plot in specified path and connecting to WebSocket server at specified
/// address.
pub async fn farm(base_directory: PathBuf, ws_server: &str) -> Result<()> {
    // TODO: revert this to pub(crate) again (temporarily modified)
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
    // right now the instance is unused, however, if we want to call stop the process
    // we can just drop the instance, and it will be stopped magically :)
    let _farming_instance = Farming::start(
        plot.clone(),
        commitments.clone(),
        client.clone(),
        identity.clone(),
    );

    // start the background plotting
    // NOTE: THIS WILL CHANGE IN THE UPCOMING PR
    let public_key = identity.public_key();
    let plotting_result = crate::plotting::background_plotting(
        client,
        plot,
        commitments,
        object_mappings,
        &public_key,
    )
    .await;

    match plotting_result {
        Ok(()) => {
            info!("Background plotting shutdown gracefully");

            Ok(())
        }
        Err(error) => Err(anyhow!("Background plotting error: {}", error)),
    }
}
