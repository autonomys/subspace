use crate::archiving::Archiving;
use crate::rpc_client::RpcClient;
use crate::single_plot_farm::{
    PlotFactory, SinglePlotFarm, SinglePlotFarmId, SinglePlotFarmOptions, SinglePlotPieceGetter,
};
use crate::utils::get_plot_sizes;
use crate::ws_rpc_server::PieceGetter;
use anyhow::anyhow;
use derive_more::From;
use futures::future::{select, Either};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use parking_lot::Mutex;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fmt, fs, io};
use std_semaphore::{Semaphore, SemaphoreGuard};
use subspace_core_primitives::{Piece, PieceIndex, PieceIndexHash, PublicKey};
use subspace_networking::libp2p::Multiaddr;
use subspace_rpc_primitives::FarmerProtocolInfo;
use tokio::runtime::Handle;
use tracing::{error, info_span};
use ulid::Ulid;

/// Abstraction that can get pieces out of internal plots
#[derive(Debug, Clone)]
pub struct SingleDiskFarmPieceGetter {
    single_plot_piece_getters: Vec<SinglePlotPieceGetter>,
}

impl SingleDiskFarmPieceGetter {
    /// Create new piece getter for many single plot farms
    pub fn new(single_plot_piece_getters: Vec<SinglePlotPieceGetter>) -> Self {
        Self {
            single_plot_piece_getters,
        }
    }
}

impl PieceGetter for SingleDiskFarmPieceGetter {
    fn get_piece(
        &self,
        piece_index: PieceIndex,
        piece_index_hash: PieceIndexHash,
    ) -> Option<Piece> {
        self.single_plot_piece_getters
            .iter()
            .find_map(|single_plot_piece_getter| {
                single_plot_piece_getter.get_piece(piece_index, piece_index_hash)
            })
    }
}

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
    pub fn new(concurrency: u16) -> Self {
        Self {
            inner: Arc::new(Semaphore::new(concurrency as isize)),
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
    Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, From,
)]
pub struct SingleDiskFarmId(Ulid);

impl fmt::Display for SingleDiskFarmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[allow(clippy::new_without_default)]
impl SingleDiskFarmId {
    /// Creates new ID
    pub fn new() -> Self {
        Self(Ulid::new())
    }
}

/// Metadata for `SingleDiskFarm`, stores important information about the contents of the farm
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SingleDiskFarmMetadata {
    /// V0 of the metadata
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

impl SingleDiskFarmMetadata {
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

    /// Load `SingleDiskFarm` metadata from path where metadata is supposed to be stored, `None`
    /// means no metadata was found, happens during first start.
    pub fn load_from(metadata_directory: &Path) -> io::Result<Option<Self>> {
        let bytes = match fs::read(metadata_directory.join(Self::FILE_NAME)) {
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

    /// Store `SingleDiskFarm` metadata to path where metadata is supposed to be stored so it can be
    /// loaded again upon restart.
    pub fn store_to(&self, metadata_directory: &Path) -> io::Result<()> {
        fs::write(
            metadata_directory.join(Self::FILE_NAME),
            serde_json::to_vec(self).expect("Metadata serialization never fails; qed"),
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

/// Options for `SingleDiskFarm` creation
pub struct SingleDiskFarmOptions<RC, PF> {
    /// Path to directory where plots are stored, typically HDD.
    pub plot_directory: PathBuf,
    /// Path to directory for storing metadata, typically SSD.
    pub metadata_directory: PathBuf,
    /// How much space in bytes can farm use for plots (metadata space is not included)
    pub allocated_plotting_space: u64,
    pub farmer_protocol_info: FarmerProtocolInfo,
    /// Client used for archiving subscriptions
    pub archiving_client: RC,
    /// Independent client used for farming, such that it is not blocked by archiving
    pub farming_client: RC,
    /// Factory that'll create/open plot using given options
    pub plot_factory: PF,
    pub reward_address: PublicKey,
    pub bootstrap_nodes: Vec<Multiaddr>,
    pub listen_on: Vec<Multiaddr>,
    /// Enable DSN subscription for archiving segments.
    pub enable_dsn_archiving: bool,
    pub enable_dsn_sync: bool,
    pub enable_farming: bool,
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
            plot_factory,
            archiving_client,
            farming_client,
            reward_address,
            bootstrap_nodes,
            listen_on,
            enable_dsn_archiving,
            enable_dsn_sync,
            enable_farming,
        } = options;

        let plot_sizes =
            get_plot_sizes(allocated_plotting_space, farmer_protocol_info.max_plot_size);

        let single_disk_farm_metadata =
            match SingleDiskFarmMetadata::load_from(&metadata_directory)? {
                Some(single_disk_farm_metadata) => {
                    if allocated_plotting_space
                        != single_disk_farm_metadata.allocated_plotting_space()
                    {
                        error!(
                            id = %single_disk_farm_metadata.id(),
                            plot_directory = %plot_directory.display(),
                            metadata_directory = %metadata_directory.display(),
                            "Usable plotting space {} is different from {} when farm was created, \
                            resizing isn't supported yet",
                            allocated_plotting_space,
                            single_disk_farm_metadata.allocated_plotting_space(),
                        );

                        return Err(anyhow!("Can't resize farm after creation"));
                    }

                    if &farmer_protocol_info.genesis_hash
                        != single_disk_farm_metadata.genesis_hash()
                    {
                        error!(
                            id = %single_disk_farm_metadata.id(),
                            "Genesis hash {} is different from {} when farm was created, is is not \
                            possible to use farm on a different chain",
                            hex::encode(farmer_protocol_info.genesis_hash),
                            hex::encode(single_disk_farm_metadata.genesis_hash()),
                        );

                        return Err(anyhow!("Wrong chain (genesis hash)"));
                    }
                    single_disk_farm_metadata
                }
                None => {
                    let single_disk_farm_metadata = SingleDiskFarmMetadata::new(
                        farmer_protocol_info.genesis_hash,
                        allocated_plotting_space,
                        plot_sizes
                            .iter()
                            .map(|_plot_size| SinglePlotFarmId::new())
                            .collect(),
                    );

                    single_disk_farm_metadata.store_to(&metadata_directory)?;

                    single_disk_farm_metadata
                }
            };

        let first_listen_on: Arc<Mutex<Option<Vec<Multiaddr>>>> = Arc::default();

        // Somewhat arbitrary number (we don't know if this is RAID or anything), but at least not
        // unbounded.
        let single_disk_semaphore = SingleDiskSemaphore::new(16);

        let single_plot_farms = tokio::task::spawn_blocking(move || {
            let handle = Handle::current();
            single_disk_farm_metadata
                .single_plot_farms()
                .into_par_iter()
                .zip(plot_sizes)
                .enumerate()
                .map(
                    move |(plot_index, (single_farm_plot_id, allocated_plotting_space))| {
                        let _guard = handle.enter();

                        let plot_directory = plot_directory.join(single_farm_plot_id.to_string());
                        let metadata_directory =
                            metadata_directory.join(single_farm_plot_id.to_string());
                        let farming_client = farming_client.clone();
                        let listen_on = listen_on.clone();
                        let bootstrap_nodes = bootstrap_nodes.clone();
                        let first_listen_on = Arc::clone(&first_listen_on);
                        let single_disk_semaphore = single_disk_semaphore.clone();

                        let span = info_span!("single_plot_farm", %single_farm_plot_id);
                        let _enter = span.enter();

                        SinglePlotFarm::new(SinglePlotFarmOptions {
                            id: *single_farm_plot_id,
                            plot_directory,
                            metadata_directory,
                            plot_index,
                            allocated_plotting_space,
                            farmer_protocol_info,
                            farming_client,
                            plot_factory: &plot_factory,
                            listen_on,
                            bootstrap_nodes,
                            first_listen_on,
                            single_disk_semaphore,
                            enable_farming,
                            reward_address,
                            enable_dsn_archiving,
                            enable_dsn_sync,
                        })
                    },
                )
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
}
