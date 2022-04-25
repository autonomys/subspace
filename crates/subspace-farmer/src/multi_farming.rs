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

        let results = plot_sizes
            .into_iter()
            .enumerate()
            .map(|(plot_index, max_plot_pieces)| {
                let base_directory = base_directory.as_ref().to_owned();
                let client = client.clone();

                tokio::task::spawn_blocking(move || {
                    let base_directory = base_directory.join(format!("plot{plot_index}"));
                    std::fs::create_dir_all(&base_directory)?;

                    let identity = Identity::open_or_create(&base_directory)?;
                    let public_key = identity.public_key().to_bytes().into();

                    // TODO: This doesn't account for the fact that node can
                    // have a completely different history to what farmer expects
                    info!("Opening plot");
                    let plot = Plot::open_or_create(&base_directory, public_key, max_plot_pieces)?;

                    info!("Opening commitments");
                    let plot_commitments = Commitments::new(base_directory.join("commitments"))?;

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
                })
            })
            .collect::<Vec<_>>();

        for result_future in results {
            let (plot, subspace_codec, plot_commitments, farming) = result_future.await.unwrap()?;
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
