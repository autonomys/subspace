use crate::archiving::Archiving;
use crate::object_mappings::LegacyObjectMappings;
use crate::rpc_client::RpcClient;
use crate::single_disk_farm::SingleDiskSemaphore;
use crate::single_plot_farm::{PlotFactory, SinglePlotFarm, SinglePlotFarmOptions};
use crate::utils::{get_plot_sizes, get_usable_plot_space};
use crate::ws_rpc_server::PieceGetter;
use futures::stream::{FuturesUnordered, StreamExt};
use rayon::prelude::*;
use std::num::NonZeroU16;
use std::path::PathBuf;
use subspace_core_primitives::PublicKey;
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::Node;
use subspace_rpc_primitives::FarmerProtocolInfo;
use tokio::runtime::Handle;
use tracing::{error, info_span};

/// Options for `MultiFarming` creation
pub struct Options<C> {
    pub base_directory: PathBuf,
    pub farmer_protocol_info: FarmerProtocolInfo,
    /// Client used for archiving subscriptions
    pub archiving_client: C,
    /// Independent client used for farming, such that it is not blocked by archiving
    pub farming_client: C,
    pub object_mappings: LegacyObjectMappings,
    pub reward_address: PublicKey,
    pub bootstrap_nodes: Vec<Multiaddr>,
    /// Enable DSN subscription for archiving segments.
    pub enable_dsn_archiving: bool,
    pub enable_dsn_sync: bool,
    pub enable_farming: bool,
    pub relay_server_node: Node,
}

/// Abstraction around having multiple `Plot`s, `Farming`s and `Plotting`s.
///
/// It is needed because of the limit of a single plot size from the consensus
/// (`pallet_subspace::MaxPlotSize`) in order to support any amount of disk space from user.
pub struct LegacyMultiPlotsFarm {
    single_plot_farms: Vec<SinglePlotFarm>,
    archiving: Option<Archiving>,
}

impl LegacyMultiPlotsFarm {
    /// Creates multiple single plot farms with user-provided total plot size
    pub async fn new<RC, PF>(
        options: Options<RC>,
        allocated_space: u64,
        plot_factory: PF,
    ) -> anyhow::Result<Self>
    where
        RC: RpcClient,
        PF: PlotFactory,
    {
        let Options {
            base_directory,
            farmer_protocol_info,
            archiving_client,
            farming_client,
            object_mappings,
            reward_address,
            bootstrap_nodes,
            enable_dsn_archiving,
            enable_dsn_sync,
            enable_farming,
            relay_server_node,
        } = options;
        let usable_space = get_usable_plot_space(allocated_space);
        let plot_sizes = get_plot_sizes(usable_space, farmer_protocol_info.max_plot_size);

        // Somewhat arbitrary number (we don't know if this is RAID or anything), but at least not
        // unbounded.
        let single_disk_semaphore =
            SingleDiskSemaphore::new(NonZeroU16::try_from(16).expect("Non zero; qed"));

        let single_plot_farms = tokio::task::spawn_blocking(move || {
            let handle = Handle::current();
            plot_sizes
                .into_par_iter()
                .enumerate()
                .map(move |(plot_index, allocated_plotting_space)| {
                    let _guard = handle.enter();

                    let plot_directory = base_directory.join(format!("plot{plot_index}"));
                    let metadata_directory = base_directory.join(format!("plot{plot_index}"));
                    let farming_client = farming_client.clone();
                    let bootstrap_nodes = bootstrap_nodes.clone();
                    let single_disk_semaphore = single_disk_semaphore.clone();

                    let span = info_span!("single_plot_farm", %plot_index);
                    let _enter = span.enter();

                    SinglePlotFarm::new(SinglePlotFarmOptions {
                        id: plot_index.into(),
                        plot_directory,
                        metadata_directory,
                        allocated_plotting_space,
                        farmer_protocol_info,
                        farming_client,
                        plot_factory: &plot_factory,
                        bootstrap_nodes,
                        single_disk_semaphore,
                        enable_farming,
                        reward_address,
                        enable_dsn_archiving,
                        enable_dsn_sync,
                        relay_server_node: relay_server_node.clone(),
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .await
        .expect("Not supposed to panic, crash if it does")?;

        // Start archiving task
        let archiving = if !enable_dsn_archiving {
            let archiving_start_fut = Archiving::start(
                farmer_protocol_info,
                single_plot_farms
                    .iter()
                    .map(|single_plot_farm| single_plot_farm.object_mappings().clone())
                    .collect(),
                vec![object_mappings],
                archiving_client,
                {
                    let plotters = single_plot_farms
                        .iter()
                        .map(|single_plot_farm| single_plot_farm.plotter())
                        .collect::<Vec<_>>();

                    move |pieces_to_plot| {
                        if let Some(Err(error)) = plotters
                            .par_iter()
                            .map(|plotter| plotter.plot_pieces(pieces_to_plot.clone()))
                            .find_first(|result| result.is_err())
                        {
                            error!(%error, "Failed to plot pieces");
                            false
                        } else {
                            true
                        }
                    }
                },
            );

            Some(archiving_start_fut.await?)
        } else {
            None
        };

        Ok(Self {
            single_plot_farms,
            archiving,
        })
    }

    pub fn single_plot_farms(&self) -> &[SinglePlotFarm] {
        &self.single_plot_farms
    }

    pub fn piece_getter(&self) -> impl PieceGetter {
        self.single_plot_farms
            .iter()
            .map(|single_plot_farm| single_plot_farm.piece_getter())
            .collect::<Vec<_>>()
    }

    /// Waits for farming and plotting completion (or errors)
    pub async fn wait(self) -> anyhow::Result<()> {
        let mut single_plot_farms = self
            .single_plot_farms
            .into_iter()
            .map(|mut single_plot_farm| async move { single_plot_farm.run().await })
            .collect::<FuturesUnordered<_>>();

        if let Some(archiving) = self.archiving {
            tokio::select! {
                res = single_plot_farms.select_next_some() => {
                    res?;
                },
                res = archiving.wait() => {
                    res?;
                },
            }
        } else {
            while let Some(result) = single_plot_farms.next().await {
                result?;
            }
        }

        Ok(())
    }
}
