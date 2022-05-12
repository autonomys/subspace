use crate::{
    plotting, Archiving, Commitments, Farming, Identity, ObjectMappings, Plot, PlotError, RpcClient,
};
use anyhow::anyhow;
use futures::stream::{FuturesUnordered, StreamExt};
use log::info;
use rayon::prelude::*;
use std::{path::PathBuf, sync::Arc, time::Duration};
use subspace_core_primitives::{PublicKey, PIECE_SIZE};
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

fn get_plot_sizes(total_plot_size: u64, max_plot_size: u64) -> Vec<u64> {
    // TODO: we need to remember plot size in order to prune unused plots in future if plot size is
    // less than it was specified before.
    // TODO: Piece count should account for database overhead of various additional databases
    // For now assume 80% will go for plot itself
    let total_plot_size = total_plot_size * 4 / 5 / PIECE_SIZE as u64;

    let plot_sizes =
        std::iter::repeat(max_plot_size).take((total_plot_size / max_plot_size) as usize);
    if total_plot_size % max_plot_size > 0 {
        plot_sizes
            .chain(std::iter::once(total_plot_size % max_plot_size))
            .collect::<Vec<_>>()
    } else {
        plot_sizes.collect()
    }
}

/// Options for `MultiFarming` creation
pub struct Options<C: RpcClient> {
    pub base_directory: PathBuf,
    pub client: C,
    pub object_mappings: ObjectMappings,
    pub reward_address: PublicKey,
    pub best_block_number_check_interval: Duration,
}

impl MultiFarming {
    /// Starts multiple farmers with any plot sizes which user gives
    pub async fn new(
        options: Options<impl RpcClient>,
        total_plot_size: u64,
        max_plot_size: u64,
    ) -> anyhow::Result<Self> {
        let plot_sizes = get_plot_sizes(total_plot_size, max_plot_size);
        let base_directory = options.base_directory.clone();
        Self::new_inner(
            options,
            plot_sizes,
            move |plot_index, address, max_piece_count| {
                Plot::open_or_create(
                    base_directory.join(format!("plot{plot_index}")),
                    address,
                    max_piece_count,
                )
            },
            true,
        )
        .await
    }

    /// Starts multiple farmers for benchmarking (basically disables farming, just plots pieces
    /// from the archiver)
    pub async fn benchmarking(
        options: Options<impl RpcClient>,
        total_plot_size: u64,
        max_plot_size: u64,
    ) -> anyhow::Result<Self> {
        let plot_sizes = get_plot_sizes(total_plot_size, max_plot_size);
        let base_directory = options.base_directory.clone();

        Self::new_inner(
            options,
            plot_sizes,
            move |plot_index, address, max_piece_count| {
                Plot::open_or_create(
                    base_directory.join(format!("plot{plot_index}")),
                    address,
                    max_piece_count,
                )
            },
            false,
        )
        .await
    }

    async fn new_inner(
        Options {
            base_directory,
            client,
            object_mappings,
            reward_address,
            best_block_number_check_interval,
        }: Options<impl RpcClient>,
        plot_sizes: Vec<u64>,
        new_plot: impl Fn(usize, PublicKey, u64) -> Result<Plot, PlotError> + Clone + Send + 'static,
        start_farmings: bool,
    ) -> anyhow::Result<Self> {
        let mut plots = Vec::with_capacity(plot_sizes.len());
        let mut subspace_codecs = Vec::with_capacity(plot_sizes.len());
        let mut commitments = Vec::with_capacity(plot_sizes.len());
        let mut farmings = Vec::with_capacity(plot_sizes.len());

        let results = plot_sizes
            .into_iter()
            .enumerate()
            .map(|(plot_index, max_plot_pieces)| {
                let base_directory = base_directory.to_owned();
                let client = client.clone();
                let new_plot = new_plot.clone();

                tokio::task::spawn_blocking(move || {
                    let base_directory = base_directory.join(format!("plot{plot_index}"));
                    std::fs::create_dir_all(&base_directory)?;

                    let identity = Identity::open_or_create(&base_directory)?;
                    let public_key = identity.public_key().to_bytes().into();

                    // TODO: This doesn't account for the fact that node can
                    // have a completely different history to what farmer expects
                    info!("Opening plot");
                    let plot = new_plot(plot_index, public_key, max_plot_pieces)?;

                    info!("Opening commitments");
                    let plot_commitments = Commitments::new(base_directory.join("commitments"))?;

                    let subspace_codec = SubspaceCodec::new(identity.public_key());

                    // Start the farming task
                    let farming = start_farmings.then(|| {
                        Farming::start(
                            plot.clone(),
                            plot_commitments.clone(),
                            client.clone(),
                            identity,
                            reward_address,
                        )
                    });

                    Ok::<_, anyhow::Error>((plot, subspace_codec, plot_commitments, farming))
                })
            })
            .collect::<Vec<_>>();

        for result_future in results {
            let (plot, subspace_codec, plot_commitments, farming) = result_future.await.unwrap()?;
            plots.push(plot);
            subspace_codecs.push(subspace_codec);
            commitments.push(plot_commitments);
            if let Some(farming) = farming {
                farmings.push(farming);
            }
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
        if self.farmings.is_empty() {
            return self.archiving.wait().await.map_err(Into::into);
        }

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
