use crate::archiving::Archiving;
use crate::rpc_client::RpcClient;
use crate::single_plot_farm::{
    PlotFactory, SinglePlotFarm, SinglePlotFarmId, SinglePlotFarmOptions, SinglePlotFarmSummary,
};
use crate::utils::get_plot_sizes;
use crate::ws_rpc_server::PieceGetter;
use anyhow::anyhow;
use derive_more::{Display, From};
use futures::future::{select, Either};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fmt, fs, io};
use std_semaphore::{Semaphore, SemaphoreGuard};
use subspace_core_primitives::PublicKey;
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::Node;
use subspace_rpc_primitives::FarmerProtocolInfo;
use tokio::runtime::Handle;
use tracing::{error, info, info_span};
use ulid::Ulid;

/// Semaphore that limits disk access concurrency in strategic places to the number specified during
/// initialization
#[derive(Clone)]
pub struct SingleDiskSemaphore {
    inner: Arc<Semaphore>,
}

impl fmt::Debug for SingleDiskSemaphore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleDiskSemaphore").finish()
    }
}

impl SingleDiskSemaphore {
    /// Create new semaphore for limiting concurrency of the major processes working with the same
    /// disk
    pub fn new(concurrency: NonZeroU16) -> Self {
        Self {
            inner: Arc::new(Semaphore::new(concurrency.get() as isize)),
        }
    }

    /// Acquire access, will block current thread until previously acquired guards are dropped and
    /// access is released
    pub fn acquire(&self) -> SemaphoreGuard<'_> {
        self.inner.access()
    }
}

/// An identifier for single plot farm, can be used for in logs, thread names, etc.
#[derive(
    Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Display, From,
)]
pub struct SingleDiskFarmId(Ulid);

#[allow(clippy::new_without_default)]
impl SingleDiskFarmId {
    /// Creates new ID
    pub fn new() -> Self {
        Self(Ulid::new())
    }
}

/// Important information about the contents of the `SingleDiskFarm`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SingleDiskFarmInfo {
    /// V0 of the info
    #[serde(rename_all = "camelCase")]
    V0 {
        /// ID of the farm
        id: SingleDiskFarmId,
        /// Genesis hash of the chain used for farm creation
        #[serde(with = "hex::serde")]
        genesis_hash: [u8; 32],
        /// How much space in bytes can farm use for plots (metadata space is not included)
        allocated_plotting_space: u64,
        /// IDs of single plot farms contained within
        single_plot_farms: Vec<SinglePlotFarmId>,
    },
}

impl SingleDiskFarmInfo {
    const FILE_NAME: &'static str = "single_disk_farm.json";

    pub fn new(
        genesis_hash: [u8; 32],
        allocated_plotting_space: u64,
        single_plot_farms: Vec<SinglePlotFarmId>,
    ) -> Self {
        Self::V0 {
            id: SingleDiskFarmId::new(),
            genesis_hash,
            allocated_plotting_space,
            single_plot_farms,
        }
    }

    /// Load `SingleDiskFarm` from path, `None` means no info file was found, happens during first
    /// start.
    pub fn load_from(path: &Path) -> io::Result<Option<Self>> {
        let bytes = match fs::read(path.join(Self::FILE_NAME)) {
            Ok(bytes) => bytes,
            Err(error) => {
                return if error.kind() == io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(error)
                };
            }
        };

        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// Store `SingleDiskFarm` info to path so it can be loaded again upon restart.
    pub fn store_to(&self, path: &Path) -> io::Result<()> {
        fs::write(
            path.join(Self::FILE_NAME),
            serde_json::to_vec(self).expect("Info serialization never fails; qed"),
        )
    }

    // ID of the farm
    pub fn id(&self) -> &SingleDiskFarmId {
        let Self::V0 { id, .. } = self;
        id
    }

    // Genesis hash of the chain used for farm creation
    pub fn genesis_hash(&self) -> &[u8; 32] {
        let Self::V0 { genesis_hash, .. } = self;
        genesis_hash
    }

    // How much space in bytes can farm use for plots (metadata space is not included)
    pub fn allocated_plotting_space(&self) -> u64 {
        let Self::V0 {
            allocated_plotting_space,
            ..
        } = self;
        *allocated_plotting_space
    }

    // IDs of single plot farms contained within
    pub fn single_plot_farms(&self) -> &[SinglePlotFarmId] {
        let Self::V0 {
            single_plot_farms, ..
        } = self;
        single_plot_farms
    }
}

/// Summary of single disk farm for presentational purposes
pub enum SingleDiskFarmSummary {
    /// Farm was found and read successfully
    Found {
        // ID of the farm
        id: SingleDiskFarmId,
        // Genesis hash of the chain used for farm creation
        genesis_hash: [u8; 32],
        // How much space in bytes can farm use for plots (metadata space is not included)
        allocated_plotting_space: u64,
        /// Path to directory where plots are stored, typically HDD.
        plot_directory: PathBuf,
        /// Path to directory for storing metadata, typically SSD.
        metadata_directory: PathBuf,
        // Summaries of single plot farms contained within
        single_plot_farm_summaries: Vec<SinglePlotFarmSummary>,
    },
    /// Farm was not found
    NotFound {
        /// Path to directory where plots are stored, typically HDD.
        plot_directory: PathBuf,
        /// Path to directory for storing metadata, typically SSD.
        metadata_directory: PathBuf,
    },
    /// Failed to open farm
    Error {
        /// Path to directory where plots are stored, typically HDD.
        plot_directory: PathBuf,
        /// Path to directory for storing metadata, typically SSD.
        metadata_directory: PathBuf,
        /// Error itself
        error: io::Error,
    },
}

/// Options for `SingleDiskFarm` creation
pub struct SingleDiskFarmOptions<RC, PF> {
    /// Path to directory where plots are stored, typically HDD.
    pub plot_directory: PathBuf,
    /// Path to directory for storing metadata, typically SSD.
    pub metadata_directory: PathBuf,
    /// How much space in bytes can farm use for plots (metadata space is not included)
    pub allocated_plotting_space: u64,
    /// Information about protocol necessary for farmer
    pub farmer_protocol_info: FarmerProtocolInfo,
    /// Number of major concurrent operations to allow for disk
    pub disk_concurrency: NonZeroU16,
    /// Client used for archiving subscriptions
    pub archiving_client: RC,
    /// Independent client used for farming, such that it is not blocked by archiving
    pub farming_client: RC,
    /// Factory that'll create/open plot using given options
    pub plot_factory: PF,
    pub reward_address: PublicKey,
    pub bootstrap_nodes: Vec<Multiaddr>,
    /// Enable DSN subscription for archiving segments.
    pub enable_dsn_archiving: bool,
    pub enable_dsn_sync: bool,
    pub enable_farming: bool,
    pub relay_server_node: Arc<Node>,
}

/// Abstraction on top of `SinglePlotFarm` instances contained within the same physical disk (or
/// what appears to be one disk).
///
/// It primarily constraints some of the disk access concurrency to achieve higher performance by
/// avoiding unnecessary random disk access and preferring sequential reads/writes whenever possible
/// instead of doing a large amount of random I/O that is bad for HDDs (intended storage medium for
/// plots).
pub struct SingleDiskFarm {
    single_plot_farms: Vec<SinglePlotFarm>,
    archiving: Option<Archiving>,
}

impl SingleDiskFarm {
    /// Creates single disk farm with user-provided total plot size
    pub async fn new<RC, PF>(options: SingleDiskFarmOptions<RC, PF>) -> anyhow::Result<Self>
    where
        RC: RpcClient,
        PF: PlotFactory,
    {
        let SingleDiskFarmOptions {
            plot_directory,
            metadata_directory,
            allocated_plotting_space,
            farmer_protocol_info,
            disk_concurrency,
            plot_factory,
            archiving_client,
            farming_client,
            reward_address,
            bootstrap_nodes,
            enable_dsn_archiving,
            enable_dsn_sync,
            enable_farming,
            relay_server_node,
        } = options;

        let plot_sizes =
            get_plot_sizes(allocated_plotting_space, farmer_protocol_info.max_plot_size);

        // Store in plot directory so that metadata directory (typically SSD) can be shared by
        // multiple single disk farms
        let single_disk_farm_info = match SingleDiskFarmInfo::load_from(&plot_directory)? {
            Some(single_disk_farm_info) => {
                if allocated_plotting_space != single_disk_farm_info.allocated_plotting_space() {
                    error!(
                        id = %single_disk_farm_info.id(),
                        plot_directory = %plot_directory.display(),
                        metadata_directory = %metadata_directory.display(),
                        "Usable plotting space {} is different from {} when farm was created, \
                        resizing isn't supported yet",
                        allocated_plotting_space,
                        single_disk_farm_info.allocated_plotting_space(),
                    );

                    return Err(anyhow!("Can't resize farm after creation"));
                }

                if &farmer_protocol_info.genesis_hash != single_disk_farm_info.genesis_hash() {
                    error!(
                        id = %single_disk_farm_info.id(),
                        "Genesis hash {} is different from {} when farm was created, is is not \
                        possible to use farm on a different chain",
                        hex::encode(farmer_protocol_info.genesis_hash),
                        hex::encode(single_disk_farm_info.genesis_hash()),
                    );

                    return Err(anyhow!("Wrong chain (genesis hash)"));
                }
                single_disk_farm_info
            }
            None => {
                let single_disk_farm_info = SingleDiskFarmInfo::new(
                    farmer_protocol_info.genesis_hash,
                    allocated_plotting_space,
                    plot_sizes
                        .iter()
                        .map(|_plot_size| SinglePlotFarmId::new())
                        .collect(),
                );

                single_disk_farm_info.store_to(&plot_directory)?;

                single_disk_farm_info
            }
        };

        let single_disk_semaphore = SingleDiskSemaphore::new(disk_concurrency);

        let single_plot_farms = tokio::task::spawn_blocking(move || {
            let handle = Handle::current();
            single_disk_farm_info
                .single_plot_farms()
                .into_par_iter()
                .zip(plot_sizes)
                .map(move |(single_plot_farm_id, allocated_plotting_space)| {
                    let _guard = handle.enter();

                    let plot_directory = plot_directory.join(single_plot_farm_id.to_string());
                    let metadata_directory =
                        metadata_directory.join(single_plot_farm_id.to_string());
                    let farming_client = farming_client.clone();
                    let bootstrap_nodes = bootstrap_nodes.clone();
                    let single_disk_semaphore = single_disk_semaphore.clone();

                    let span = info_span!("single_plot_farm", %single_plot_farm_id);
                    let _enter = span.enter();

                    SinglePlotFarm::new(SinglePlotFarmOptions {
                        id: *single_plot_farm_id,
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

    pub fn single_plot_farms(&self) -> &'_ [SinglePlotFarm] {
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
            let fut = select(
                Box::pin(archiving.wait()),
                Box::pin(async move {
                    while let Some(result) = single_plot_farms.next().await {
                        result?;
                    }

                    anyhow::Ok(())
                }),
            );

            match fut.await {
                Either::Left((result, _)) => result?,
                Either::Right((result, _)) => result?,
            }
        } else {
            while let Some(result) = single_plot_farms.next().await {
                result?;
            }
        }

        Ok(())
    }

    /// Collect summary of single disk farm for presentational purposes
    pub fn collect_summary(
        plot_directory: PathBuf,
        metadata_directory: PathBuf,
    ) -> SingleDiskFarmSummary {
        let single_disk_farm_info = match SingleDiskFarmInfo::load_from(&plot_directory) {
            Ok(Some(single_disk_farm_info)) => single_disk_farm_info,
            Ok(None) => {
                return SingleDiskFarmSummary::NotFound {
                    plot_directory,
                    metadata_directory,
                };
            }
            Err(error) => {
                return SingleDiskFarmSummary::Error {
                    plot_directory,
                    metadata_directory,
                    error,
                };
            }
        };

        let single_plot_farm_summaries = single_disk_farm_info
            .single_plot_farms()
            .iter()
            .map(|single_plot_farm_id| {
                SinglePlotFarm::collect_summary(
                    plot_directory.join(single_plot_farm_id.to_string()),
                    metadata_directory.join(single_plot_farm_id.to_string()),
                )
            })
            .collect();

        return SingleDiskFarmSummary::Found {
            id: *single_disk_farm_info.id(),
            genesis_hash: *single_disk_farm_info.genesis_hash(),
            allocated_plotting_space: single_disk_farm_info.allocated_plotting_space(),
            plot_directory,
            metadata_directory,
            single_plot_farm_summaries,
        };
    }

    /// Wipe everything that belongs to this single disk farm
    pub fn wipe(plot_directory: &Path, metadata_directory: &Path) -> io::Result<()> {
        let single_disk_farm_info_path = plot_directory.join(SingleDiskFarmInfo::FILE_NAME);
        let single_disk_farm_info =
            SingleDiskFarmInfo::load_from(plot_directory)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "Single disk plot info not found at {}",
                        single_disk_farm_info_path.display()
                    ),
                )
            })?;

        info!("Found single disk farm {}", single_disk_farm_info.id());

        for single_farm_plot_id in single_disk_farm_info.single_plot_farms() {
            info!("Deleting single plot farm {}", single_farm_plot_id);
            let plot_directory = plot_directory.join(single_farm_plot_id.to_string());
            let metadata_directory = metadata_directory.join(single_farm_plot_id.to_string());

            if plot_directory.exists() {
                info!(
                    "Found plot directory {}, deleting",
                    plot_directory.display()
                );
                fs::remove_dir_all(plot_directory)?;
            }

            if metadata_directory.exists() {
                info!(
                    "Found metadata directory {}, deleting",
                    metadata_directory.display()
                );
                fs::remove_dir_all(metadata_directory)?;
            }
        }

        info!(
            "Deleting single disk farm info at {}",
            single_disk_farm_info_path.display()
        );
        fs::remove_file(single_disk_farm_info_path)
    }
}
