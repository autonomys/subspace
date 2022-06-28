use crate::archiving::Archiving;
use crate::object_mappings::ObjectMappings;
use crate::plot::{Plot, PlotError};
use crate::plotting;
use crate::rpc_client::RpcClient;
use crate::single_plot_farm::{SinglePlotFarm, SinglePlotFarmOptions};
use anyhow::anyhow;
use futures::stream::{FuturesOrdered, FuturesUnordered, StreamExt};
use parking_lot::Mutex;
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::{PublicKey, PIECE_SIZE};
use subspace_networking::libp2p::Multiaddr;
use tracing::{error, info, trace};

// TODO: tie `plots`, `commitments`, `farmings`, ``networking_node_runners` together as they always
// will have the same length.
/// Abstraction around having multiple `Plot`s, `Farming`s and `Plotting`s.
///
/// It is needed because of the limit of a single plot size from the consensus
/// (`pallet_subspace::MaxPlotSize`) in order to support any amount of disk space from user.
pub struct MultiFarming {
    pub single_plot_farms: Vec<SinglePlotFarm>,
    archiving: Archiving,
    networking_node_runners: Vec<subspace_networking::NodeRunner>,
}

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
    pub dsn_sync: bool,
}

impl MultiFarming {
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
            dsn_sync,
        }: Options<C>,
        total_plot_size: u64,
        max_plot_size: u64,
        new_plot: impl Fn(usize, PublicKey, u64) -> Result<Plot, PlotError> + Clone + Send + 'static,
        start_farmings: bool,
    ) -> anyhow::Result<Self> {
        let plot_sizes = get_plot_sizes(total_plot_size, max_plot_size);

        let first_listen_on: Arc<Mutex<Option<Vec<Multiaddr>>>> = Arc::default();

        let mut single_plot_farm_instantiations = plot_sizes
            .iter()
            .enumerate()
            .map(|(plot_index, &max_plot_pieces)| {
                let base_directory = base_directory.join(format!("plot{plot_index}"));
                let farming_client = farming_client.clone();
                let new_plot = new_plot.clone();
                let listen_on = listen_on.clone();
                let bootstrap_nodes = bootstrap_nodes.clone();
                let first_listen_on = Arc::clone(&first_listen_on);

                tokio::task::spawn_blocking(move || {
                    SinglePlotFarm::new(SinglePlotFarmOptions {
                        base_directory,
                        plot_index,
                        max_plot_pieces,
                        farming_client,
                        new_plot,
                        listen_on,
                        bootstrap_nodes,
                        first_listen_on,
                        start_farmings,
                        reward_address,
                    })
                })
            })
            .collect::<FuturesOrdered<_>>()
            .map(|single_plot_farm| {
                single_plot_farm.expect("Blocking task above never supposed to panic")
            });

        let mut single_plot_farms = Vec::with_capacity(plot_sizes.len());
        let mut networking_node_runners = Vec::with_capacity(plot_sizes.len());

        let mut node = None;

        while let Some(single_plot_farm) = single_plot_farm_instantiations.next().await {
            let mut single_plot_farm = single_plot_farm?;

            // Enable DSN subscription for segments archiving.
            if enable_dsn_archiving {
                // TODO: Make sure this task can be cancelled
                tokio::spawn({
                    let node = single_plot_farm.node.clone();
                    async move {
                        trace!("Subscribing to pubsub archiving...");
                        match node
                            .subscribe(subspace_networking::PUB_SUB_ARCHIVING_TOPIC.clone())
                            .await
                        {
                            Ok(mut subscription) => {
                                info!("Subscribed to pubsub archiving.");

                                //TODO: Integrate with archiving process.
                                #[allow(clippy::redundant_pattern_matching)]
                                while let Some(_) = subscription.next().await {
                                    info!("Archiving segment received from pubsub subscription.");
                                }
                            }
                            Err(err) => {
                                error!(error = ?err, "Pubsub archiving subscription failed.");
                            }
                        }
                    }
                });
            }

            if node.is_none() {
                node = Some(single_plot_farm.node.clone());
            }
            networking_node_runners.push(
                single_plot_farm
                    .node_runner
                    .take()
                    .expect("Node runner was never taken out before this; qed"),
            );
            single_plot_farms.push(single_plot_farm);
        }

        let farmer_metadata = farming_client
            .farmer_metadata()
            .await
            .map_err(|error| anyhow!(error))?;
        let max_plot_size = farmer_metadata.max_plot_size;
        let total_pieces = farmer_metadata.total_pieces;

        // Start syncing
        if dsn_sync {
            tokio::spawn({
                let mut futures = single_plot_farms
                    .iter()
                    .map(|single_plot_farm| single_plot_farm.dsn_sync(max_plot_size, total_pieces))
                    .collect::<FuturesUnordered<_>>();

                async move {
                    while let Some(result) = futures.next().await {
                        result?;
                    }

                    info!("Sync done");

                    Ok::<_, anyhow::Error>(())
                }
            });
        }

        // Start archiving task
        let archiving = Archiving::start(
            farmer_metadata,
            object_mappings,
            archiving_client,
            enable_dsn_archiving
                .then(|| node.expect("Always set, as we have at least one networking instance")),
            {
                let mut on_pieces_to_plots = single_plot_farms
                    .iter()
                    .map(|single_plot_farm| {
                        plotting::plot_pieces(
                            single_plot_farm.codec.clone(),
                            &single_plot_farm.plot,
                            single_plot_farm.commitments.clone(),
                        )
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
            single_plot_farms,
            archiving,
            networking_node_runners,
        })
    }

    /// Waits for farming and plotting completion (or errors)
    pub async fn wait(self) -> anyhow::Result<()> {
        if !self
            .single_plot_farms
            .iter()
            .any(|single_plot_farm| single_plot_farm.farming.is_some())
        {
            return self.archiving.wait().await.map_err(Into::into);
        }

        let mut farming = self
            .single_plot_farms
            .into_iter()
            .filter_map(|single_plot_farm| {
                let farming = single_plot_farm.farming?;
                Some(farming.wait())
            })
            .collect::<FuturesUnordered<_>>();
        let mut node_runners = self
            .networking_node_runners
            .into_iter()
            .map(|node_runner| async move { node_runner.run().await })
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
