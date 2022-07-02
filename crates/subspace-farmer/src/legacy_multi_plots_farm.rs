use crate::archiving::Archiving;
use crate::object_mappings::ObjectMappings;
use crate::plot::{Plot, PlotError};
use crate::rpc_client::RpcClient;
use crate::single_plot_farm::{SinglePlotFarm, SinglePlotFarmOptions};
use anyhow::anyhow;
use futures::stream::{FuturesUnordered, StreamExt};
use parking_lot::Mutex;
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::{PublicKey, PIECE_SIZE};
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::NodeRunner;
use tracing::error;

fn get_plot_sizes(total_plot_size: u64, max_plot_size: u64) -> Vec<u64> {
    // TODO: we need to remember plot size in order to prune unused plots in future if plot size is
    // less than it was specified before.
    // TODO: Piece count should account for database overhead of various additional databases
    // For now assume 92% will go for plot itself
    let total_plot_size = total_plot_size * 92 / 100 / PIECE_SIZE as u64;

    let plot_sizes =
        std::iter::repeat(max_plot_size).take((total_plot_size / max_plot_size) as usize);
    if total_plot_size / max_plot_size == 0 || total_plot_size % max_plot_size > max_plot_size / 2 {
        plot_sizes
            .chain(std::iter::once(total_plot_size % max_plot_size))
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
    pub(crate) networking_node_runners: Vec<NodeRunner>,
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
        total_plot_size: u64,
        max_plot_size: u64,
        new_plot: impl Fn(usize, PublicKey, u64) -> Result<Plot, PlotError>
            + Clone
            + Send
            + Sync
            + 'static,
    ) -> anyhow::Result<Self> {
        let plot_sizes = get_plot_sizes(total_plot_size, max_plot_size);

        let first_listen_on: Arc<Mutex<Option<Vec<Multiaddr>>>> = Arc::default();

        let farmer_metadata = farming_client
            .farmer_metadata()
            .await
            .map_err(|error| anyhow!(error))?;
        let max_plot_size = farmer_metadata.max_plot_size;
        let total_pieces = farmer_metadata.total_pieces;

        let (single_plot_farms, networking_node_runners, node) =
            tokio::task::spawn_blocking(move || {
                let mut single_plot_farms = Vec::with_capacity(plot_sizes.len());
                let mut networking_node_runners = Vec::with_capacity(plot_sizes.len());
                let mut node = None;

                let single_plot_farm_instantiations = plot_sizes
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
                    .collect::<anyhow::Result<Vec<_>>>()?;

                for (farm, node_runner) in single_plot_farm_instantiations {
                    if node.is_none() {
                        node = Some(farm.node.clone());
                    }
                    networking_node_runners.push(node_runner);
                    single_plot_farms.push(farm);
                }

                Ok::<_, anyhow::Error>((single_plot_farms, networking_node_runners, node))
            })
            .await
            .expect("Not supposed to panic, crash if it does")?;

        // Start archiving task
        let archiving = Archiving::start(
            farmer_metadata,
            object_mappings,
            archiving_client,
            enable_dsn_archiving
                .then(|| node.expect("Always set, as we have at least one networking instance")),
            {
                let plotters = single_plot_farms
                    .iter()
                    .map(|single_plot_farm| single_plot_farm.get_plotter())
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
            networking_node_runners,
        })
    }

    /// Waits for farming and plotting completion (or errors)
    pub async fn wait(mut self) -> anyhow::Result<()> {
        if !self
            .single_plot_farms
            .iter()
            .any(|single_plot_farm| single_plot_farm.farming.is_some())
        {
            return self.archiving.wait().await.map_err(Into::into);
        }

        // `.iter_mut()` so that we don't drop `SinglePlotFarm` and continue background tasks if
        // there are any
        let mut farming = self
            .single_plot_farms
            .iter_mut()
            .filter_map(|single_plot_farm| {
                let mut farming = single_plot_farm.farming.take()?;
                Some(async move { farming.wait().await })
            })
            .collect::<FuturesUnordered<_>>();
        let mut node_runners = self
            .networking_node_runners
            .iter_mut()
            .map(NodeRunner::run)
            .collect::<FuturesUnordered<_>>();

        tokio::select! {
            res = farming.select_next_some() => {
                res?;
            },
            () = node_runners.select_next_some() => {},
            res = self.archiving.wait() => {
                res?;
            },
        }

        Ok(())
    }
}
