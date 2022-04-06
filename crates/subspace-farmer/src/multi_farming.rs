use std::{path::Path, sync::Arc, time::Duration};

use anyhow::anyhow;
use futures::stream::{FuturesUnordered, StreamExt};
use log::info;
use subspace_core_primitives::PublicKey;
use subspace_solving::SubspaceCodec;

use crate::{
    Commitments, FarmerData, Farming, Identity, ObjectMappings, Plot, Plotting, RpcClient, WsRpc,
};

#[doc = include_str!("../docs/multi_farming.md")]
pub struct MultiFarming {
    pub plots: Arc<Vec<Plot>>,
    farmings: Vec<Farming>,
    plottings: Vec<Plotting>,
}

impl MultiFarming {
    /// Starts multiple farmers with any plot sizes which user gives
    pub async fn new(
        base_directory: impl AsRef<Path>,
        client: WsRpc,
        object_mappings: ObjectMappings,
        plot_sizes: Vec<u64>,
        reward_address: PublicKey,
        best_block_number_check_interval: Duration,
    ) -> anyhow::Result<Self> {
        let mut plots = Vec::with_capacity(plot_sizes.len());
        let mut farmings = Vec::with_capacity(plot_sizes.len());
        let mut plottings = Vec::with_capacity(plot_sizes.len());

        for (plot_index, max_plot_pieces) in plot_sizes.into_iter().enumerate() {
            let base_directory = base_directory.as_ref().join(format!("plot{plot_index}"));
            std::fs::create_dir_all(&base_directory)?;
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
            farmings.push(farming);
            plottings.push(plotting);
        }

        Ok(Self {
            plots: Arc::new(plots),
            farmings,
            plottings,
        })
    }

    /// Waits for farming and plotting completion (or errors)
    pub async fn wait(self) -> anyhow::Result<()> {
        let mut farming_plotting = self
            .farmings
            .into_iter()
            .zip(self.plottings)
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

        if let Some(res) = farming_plotting.next().await {
            res?;
        }
        Ok(())
    }
}

/// Starts farming for a single plot in specified base directory.
pub(crate) async fn farm_single_plot(
    base_directory: impl AsRef<Path>,
    reward_address: PublicKey,
    client: WsRpc,
    object_mappings: ObjectMappings,
    max_plot_pieces: u64,
    best_block_number_check_interval: Duration,
) -> anyhow::Result<(Plot, Plotting, Farming)> {
    let identity = Identity::open_or_create(&base_directory)?;
    let public_key = identity.public_key().to_bytes().into();

    // TODO: This doesn't account for the fact that node can
    // have a completely different history to what farmer expects
    info!("Opening plot");
    let plot = tokio::task::spawn_blocking({
        let base_directory = base_directory.as_ref().to_owned();

        move || Plot::open_or_create(&base_directory, public_key, max_plot_pieces)
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
