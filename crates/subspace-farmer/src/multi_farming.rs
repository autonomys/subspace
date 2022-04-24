use crate::{
    plotting, Archiving, Commitments, Farming, Identity, NodeRpcClient, ObjectMappings, Plot,
    RpcClient,
};
use anyhow::anyhow;
use futures::stream::{FuturesUnordered, StreamExt};
use log::info;
use rayon::prelude::*;
use std::{path::Path, sync::Arc, time::Duration};
use subspace_core_primitives::PublicKey;
use subspace_solving::SubspaceCodec;

/// Abstraction around having multiple `Plot`s, `Farming`s and `Plotting`s.
///
/// It is needed because of the limit of a single plot size from the consensus
/// (`pallet_subspace::MaxPlotSize`) in order to support any amount of disk space from user.
pub struct MultiFarming {
    pub plots: Arc<Vec<Plot>>,
    farmings: Vec<Farming>,
    archiving: Archiving,
}

impl MultiFarming {
    /// Starts multiple farmers with any plot sizes which user gives
    pub async fn new(
        base_directory: impl AsRef<Path>,
        client: NodeRpcClient,
        object_mappings: ObjectMappings,
        plot_sizes: Vec<u64>,
        reward_address: PublicKey,
        best_block_number_check_interval: Duration,
    ) -> anyhow::Result<Self> {
        let mut plots = Vec::with_capacity(plot_sizes.len());
        let mut subspace_codecs = Vec::with_capacity(plot_sizes.len());
        let mut commitments = Vec::with_capacity(plot_sizes.len());
        let mut farmings = Vec::with_capacity(plot_sizes.len());

        let mut results = plot_sizes
            .into_iter()
            .enumerate()
            .map(|(plot_index, max_plot_pieces)| {
                let base_directory = base_directory.as_ref().join(format!("plot{plot_index}"));
                let client = client.clone();
                async move {
                    std::fs::create_dir_all(&base_directory)?;

                    let identity = Identity::open_or_create(&base_directory)?;
                    let public_key = identity.public_key().to_bytes().into();

                    let plot_future = tokio::task::spawn_blocking({
                        let base_directory = base_directory.clone();

                        move || {
                            // TODO: This doesn't account for the fact that node can
                            // have a completely different history to what farmer expects
                            info!("Opening plot");
                            Plot::open_or_create(&base_directory, public_key, max_plot_pieces)
                        }
                    });

                    let plot_commitments_future = tokio::task::spawn_blocking({
                        let path = base_directory.join("commitments");

                        move || {
                            info!("Opening commitments");
                            Commitments::new(path)
                        }
                    });

                    let (plot_result, plot_commitments_result) =
                        tokio::join!(plot_future, plot_commitments_future);
                    let (plot, plot_commitments) =
                        (plot_result.unwrap()?, plot_commitments_result.unwrap()?);

                    let subspace_codec = SubspaceCodec::new(identity.public_key());

                    // Start the farming task
                    let farming = Farming::start(
                        plot.clone(),
                        plot_commitments.clone(),
                        client.clone(),
                        identity,
                        reward_address,
                    );

                    Ok::<_, anyhow::Error>((plot, subspace_codec, plot_commitments, farming))
                }
            })
            .map(tokio::spawn)
            .collect::<FuturesUnordered<_>>();

        while let Some(result) = results.next().await {
            let (plot, subspace_codec, plot_commitments, farming) = result??;

            plots.push(plot);
            subspace_codecs.push(subspace_codec);
            commitments.push(plot_commitments);
            farmings.push(farming);
        }

        let farmer_metadata = client
            .farmer_metadata()
            .await
            .map_err(|error| anyhow!(error))?;

        // Start archiving task
        let archiving = Archiving::start(
            farmer_metadata,
            object_mappings,
            client.clone(),
            best_block_number_check_interval,
            {
                let mut on_pieces_to_plots = plots
                    .iter()
                    .zip(subspace_codecs)
                    .zip(&commitments)
                    .map(|((plot, subspace_codec), commitments)| {
                        plotting::plot_pieces(subspace_codec, plot, commitments.clone())
                    })
                    .collect::<Vec<_>>();

                move |pieces_to_plot| {
                    on_pieces_to_plots
                        .par_iter_mut()
                        .map(|on_pieces_to_plot| {
                            // TODO: It might be desirable to not clone it and instead pick just
                            //  unnecessary pieces and copy pieces once since different plots will
                            //  care about different pieces
                            on_pieces_to_plot(pieces_to_plot.clone())
                        })
                        .reduce(|| true, |result, should_continue| result && should_continue)
                }
            },
        )
        .await?;

        Ok(Self {
            plots: Arc::new(plots),
            farmings,
            archiving,
        })
    }

    /// Waits for farming and plotting completion (or errors)
    pub async fn wait(self) -> anyhow::Result<()> {
        let mut farming = self
            .farmings
            .into_iter()
            .map(|farming| farming.wait())
            .collect::<FuturesUnordered<_>>();

        tokio::select! {
            res = farming.select_next_some() => {
                res?;
            },
            res = self.archiving.wait() => {
                res?;
            },
        }

        Ok(())
    }
}
