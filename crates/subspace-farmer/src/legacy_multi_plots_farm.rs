use crate::archiving::Archiving;
use crate::object_mappings::ObjectMappings;
use crate::plot::{Plot, PlotError};
use crate::rpc_client::RpcClient;
use crate::single_disk_farm::SingleDiskFarmPieceGetter;
use crate::single_plot_farm::{SinglePlotFarm, SinglePlotFarmOptions};
use anyhow::anyhow;
use futures::stream::{FuturesUnordered, StreamExt};
use parking_lot::Mutex;
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::PublicKey;
use subspace_networking::libp2p::Multiaddr;
use tracing::error;

fn get_plot_sizes(allocated_space: u64, max_plot_size: u64) -> Vec<u64> {
    // TODO: we need to remember plot size in order to prune unused plots in future if plot size is
    //  less than it was specified before.
    // TODO: Piece count should account for database overhead of various additional databases.
    //  For now assume 92% will go for plot itself
    let usable_space_for_plots = allocated_space * 92 / 100;

    let plot_sizes =
        std::iter::repeat(max_plot_size).take((usable_space_for_plots / max_plot_size) as usize);
    if usable_space_for_plots / max_plot_size == 0
        || usable_space_for_plots % max_plot_size > max_plot_size / 2
    {
        plot_sizes
            .chain(std::iter::once(usable_space_for_plots % max_plot_size))
            .collect::<Vec<_>>()
    } else {
        plot_sizes.collect()
    }
}

/// Options for `MultiFarming` creation
pub struct Options<C> {
    pub base_directory: PathBuf,
    /// Client used for archiving subscriptions
    pub archiving_client: C,
    /// Independent client used for farming, such that it is not blocked by archiving
    pub farming_client: C,
    pub object_mappings: ObjectMappings,
    pub reward_address: PublicKey,
    pub bootstrap_nodes: Vec<Multiaddr>,
    pub listen_on: Vec<Multiaddr>,
    /// Enable DSN subscription for archiving segments.
    pub enable_dsn_archiving: bool,
    pub enable_dsn_sync: bool,
    pub enable_farming: bool,
}

/// Abstraction around having multiple `Plot`s, `Farming`s and `Plotting`s.
///
/// It is needed because of the limit of a single plot size from the consensus
/// (`pallet_subspace::MaxPlotSize`) in order to support any amount of disk space from user.
pub struct LegacyMultiPlotsFarm {
    pub single_plot_farms: Vec<SinglePlotFarm>,
    archiving: Archiving,
}

impl LegacyMultiPlotsFarm {
    /// Starts multiple farmers with any plot sizes which user gives
    pub async fn new<C: RpcClient>(
        Options {
            base_directory,
            archiving_client,
            farming_client,
            object_mappings,
            reward_address,
            bootstrap_nodes,
            listen_on,
            enable_dsn_archiving,
            enable_dsn_sync,
            enable_farming,
        }: Options<C>,
        allocated_space: u64,
        max_plot_size: u64,
        new_plot: impl Fn(usize, PublicKey, u64) -> Result<Plot, PlotError>
            + Clone
            + Send
            + Sync
            + 'static,
    ) -> anyhow::Result<Self> {
        let plot_sizes = get_plot_sizes(allocated_space, max_plot_size);

        let first_listen_on: Arc<Mutex<Option<Vec<Multiaddr>>>> = Arc::default();

        let farmer_metadata = farming_client
            .farmer_metadata()
            .await
            .map_err(|error| anyhow!(error))?;
        let max_plot_size = farmer_metadata.max_plot_size;
        let total_pieces = farmer_metadata.total_pieces;

        let single_plot_farms = tokio::task::spawn_blocking(move || {
            plot_sizes
                .par_iter()
                .enumerate()
                .map(|(plot_index, &max_plot_pieces)| {
                    let base_directory = base_directory.join(format!("plot{plot_index}"));
                    let farming_client = farming_client.clone();
                    let new_plot = new_plot.clone();
                    let listen_on = listen_on.clone();
                    let bootstrap_nodes = bootstrap_nodes.clone();
                    let first_listen_on = Arc::clone(&first_listen_on);

                    SinglePlotFarm::new(SinglePlotFarmOptions {
                        base_directory,
                        plot_index,
                        max_plot_pieces,
                        max_plot_size,
                        total_pieces,
                        farming_client,
                        new_plot,
                        listen_on,
                        bootstrap_nodes,
                        first_listen_on,
                        enable_farming,
                        reward_address,
                        enable_dsn_sync,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .await
        .expect("Not supposed to panic, crash if it does")?;

        // Start archiving task
        let archiving = Archiving::start(
            farmer_metadata,
            object_mappings,
            archiving_client,
            enable_dsn_archiving.then(|| {
                single_plot_farms
                    .get(0)
                    .expect("There is always at least one farm; qed")
                    .node()
                    .clone()
            }),
            {
                let plotters = single_plot_farms
                    .iter()
                    .map(|single_plot_farm| single_plot_farm.plotter())
                    .collect::<Vec<_>>();

                move |pieces_to_plot| {
                    if let Some(Err(error)) = plotters
                        .par_iter()
                        .map(|plotter| plotter.plot_pieces(&pieces_to_plot))
                        .find_first(|result| result.is_err())
                    {
                        error!(%error, "Failed to plot pieces");
                        false
                    } else {
                        true
                    }
                }
            },
        )
        .await?;

        Ok(Self {
            single_plot_farms,
            archiving,
        })
    }

    pub fn piece_getter(&self) -> SingleDiskFarmPieceGetter {
        SingleDiskFarmPieceGetter::new(
            self.single_plot_farms
                .iter()
                .map(|single_plot_farm| single_plot_farm.piece_getter())
                .collect(),
        )
    }

    /// Waits for farming and plotting completion (or errors)
    pub async fn wait(self) -> anyhow::Result<()> {
        let mut single_plot_farms = self
            .single_plot_farms
            .into_iter()
            .map(|mut single_plot_farm| async move { single_plot_farm.run().await })
            .collect::<FuturesUnordered<_>>();

        tokio::select! {
            res = single_plot_farms.select_next_some() => {
                res?;
            },
            res = self.archiving.wait() => {
                res?;
            },
        }

        Ok(())
    }
}
