use std::{path::Path, sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use futures::stream::{FuturesUnordered, StreamExt};
use log::info;
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::PublicKey;
use subspace_rpc_primitives::{EncodedBlockWithObjectMapping, FarmerMetadata};
use subspace_solving::SubspaceCodec;
use tokio::task::JoinHandle;

use crate::{
    Archiving, Commitments, FarmerData, Farming, Identity, ObjectMappings, Plot, Plotting,
    RpcClient, WsRpc,
};

/// Abstraction around having multiple plots, farmings and plottings
pub struct MultiFarming {
    pub plots: Arc<Vec<Plot>>,
    farmings: Vec<Farming>,
    plottings: Vec<Plotting>,
    archiving: JoinHandle<()>,
}

async fn create_archiver(
    client: WsRpc,
    base_directory: impl AsRef<Path>,
) -> anyhow::Result<Archiver> {
    let first_plot = base_directory.as_ref().join("plot0");
    let (plot_is_empty, maybe_last_root_block) = if first_plot.is_dir() {
        let identity = Identity::open_or_create(&base_directory)?;
        let public_key = identity.public_key().to_bytes().into();
        let plot = Plot::open_or_create(first_plot, public_key, u64::MAX)?;

        (plot.is_empty(), plot.get_last_root_block()?)
    } else {
        (true, None)
    };
    let FarmerMetadata {
        record_size,
        recorded_history_segment_size,
        ..
    } = client
        .farmer_metadata()
        .await
        .map_err(|error| anyhow!(error))?;

    if let Some(last_root_block) = maybe_last_root_block {
        // Continuing from existing initial state
        if plot_is_empty {
            return Err(anyhow!("Plot is empty on restart, can't continue"));
        }

        let last_archived_block_number = last_root_block.last_archived_block().number;
        info!("Last archived block {}", last_archived_block_number);

        let maybe_last_archived_block = client
            .block_by_number(last_archived_block_number)
            .await
            .map_err(|err| anyhow!("jsonrpsee error: {err}"))?;

        match maybe_last_archived_block {
                Some(EncodedBlockWithObjectMapping {
                    block,
                    object_mapping,
                }) => Archiver::with_initial_state(
                    record_size as usize,
                    recorded_history_segment_size as usize,
                    last_root_block,
                    &block,
                    object_mapping,
                )
                .context("Archiver instantiation error"),
                None => return Err(anyhow!("Failed to get block {last_archived_block_number} from the chain, probably need to erase existing plot")),
            }
    } else {
        // Starting from genesis
        if !plot_is_empty {
            // Restart before first block was archived, erase the plot
            // TODO: Erase plot
        }

        Archiver::new(record_size as usize, recorded_history_segment_size as usize)
            .context("Archiver instantiation error")
    }
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
        let archiver = create_archiver(client.clone(), base_directory.as_ref()).await?;
        let (archiving, new_block_to_archive_sender, archived_segments_subscriber) =
            Archiving::new(archiver, client.clone());
        let mut plots = Vec::with_capacity(plot_sizes.len());
        let mut farmings = Vec::with_capacity(plot_sizes.len());
        let mut plottings = Vec::with_capacity(plot_sizes.len());

        for (plot_index, max_plot_pieces) in plot_sizes.into_iter().enumerate() {
            let base_directory = base_directory.as_ref().join(format!("plot{plot_index}"));
            std::fs::create_dir_all(&base_directory)?;

            let identity = Identity::open_or_create(&base_directory)?;
            let public_key = identity.public_key().to_bytes().into();

            // TODO: This doesn't account for the fact that node can
            // have a completely different history to what farmer expects
            info!("Opening plot");
            let plot = tokio::task::spawn_blocking({
                let base_directory = base_directory.to_owned();

                move || Plot::open_or_create(&base_directory, public_key, max_plot_pieces)
            })
            .await
            .unwrap()?;

            info!("Opening commitments");
            let commitments_fut = tokio::task::spawn_blocking({
                let path = base_directory.join("commitments");

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
                object_mappings.clone(),
                client
                    .farmer_metadata()
                    .await
                    .map_err(|error| anyhow!(error))?,
            );

            // start the background plotting
            let plotting_instance = Plotting::start(
                farmer_data,
                client.clone(),
                subspace_codec,
                best_block_number_check_interval,
                new_block_to_archive_sender.clone(),
                archived_segments_subscriber.subscribe(),
            );

            plots.push(plot);
            farmings.push(farming_instance);
            plottings.push(plotting_instance);
        }

        let archiving = tokio::task::spawn_blocking(move || archiving.archive());

        Ok(Self {
            plots: Arc::new(plots),
            farmings,
            plottings,
            archiving,
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
        self.archiving.await?;
        Ok(())
    }
}
