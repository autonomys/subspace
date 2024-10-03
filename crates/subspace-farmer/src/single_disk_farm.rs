//! Primary [`Farm`] implementation that deals with hardware directly
//!
//! Single disk farm is an abstraction that contains an identity, associated plot with metadata and
//! a small piece cache. It fully manages farming and plotting process, including listening to node
//! notifications, producing solutions and singing rewards.

pub mod direct_io_file;
pub mod farming;
pub mod identity;
mod metrics;
pub mod piece_cache;
pub mod piece_reader;
pub mod plot_cache;
mod plotted_sectors;
mod plotting;
mod reward_signing;

use crate::disk_piece_cache::{DiskPieceCache, DiskPieceCacheError};
use crate::farm::{
    Farm, FarmId, FarmingError, FarmingNotification, HandlerFn, PieceCacheId, PieceReader,
    PlottedSectors, SectorUpdate,
};
use crate::node_client::NodeClient;
use crate::plotter::Plotter;
use crate::single_disk_farm::direct_io_file::{DirectIoFile, DISK_SECTOR_SIZE};
use crate::single_disk_farm::farming::rayon_files::RayonFiles;
use crate::single_disk_farm::farming::{
    farming, slot_notification_forwarder, FarmingOptions, PlotAudit,
};
use crate::single_disk_farm::identity::{Identity, IdentityError};
use crate::single_disk_farm::metrics::SingleDiskFarmMetrics;
use crate::single_disk_farm::piece_cache::SingleDiskPieceCache;
use crate::single_disk_farm::piece_reader::DiskPieceReader;
use crate::single_disk_farm::plot_cache::DiskPlotCache;
use crate::single_disk_farm::plotted_sectors::SingleDiskPlottedSectors;
pub use crate::single_disk_farm::plotting::PlottingError;
use crate::single_disk_farm::plotting::{
    plotting, plotting_scheduler, PlottingOptions, PlottingSchedulerOptions, SectorPlottingOptions,
};
use crate::single_disk_farm::reward_signing::reward_signing;
use crate::utils::{tokio_rayon_spawn_handler, AsyncJoinOnDrop};
use crate::{farm, KNOWN_PEERS_CACHE_SIZE};
use async_lock::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use async_trait::async_trait;
use event_listener_primitives::{Bag, HandlerId};
use futures::channel::{mpsc, oneshot};
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use rand::prelude::*;
use rayon::prelude::*;
use rayon::{ThreadPoolBuildError, ThreadPoolBuilder};
use serde::{Deserialize, Serialize};
use static_assertions::const_assert;
use std::collections::HashSet;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fmt, fs, io, mem};
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::crypto::{blake3_hash, Scalar};
use subspace_core_primitives::pieces::Record;
use subspace_core_primitives::sectors::SectorIndex;
use subspace_core_primitives::segments::{HistorySize, SegmentIndex};
use subspace_core_primitives::{Blake3Hash, PublicKey};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::file_ext::FileExt;
use subspace_farmer_components::reading::ReadSectorRecordChunksMode;
use subspace_farmer_components::sector::{sector_size, SectorMetadata, SectorMetadataChecksummed};
use subspace_farmer_components::{FarmerProtocolInfo, ReadAtSync};
use subspace_networking::KnownPeersManager;
use subspace_proof_of_space::Table;
use subspace_rpc_primitives::{FarmerAppInfo, SolutionResponse};
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::sync::{broadcast, Barrier, Semaphore};
use tokio::task;
use tracing::{debug, error, info, trace, warn, Instrument, Span};

// Refuse to compile on non-64-bit platforms, offsets may fail on those when converting from u64 to
// usize depending on chain parameters
const_assert!(mem::size_of::<usize>() >= mem::size_of::<u64>());

/// Reserve 1M of space for plot metadata (for potential future expansion)
const RESERVED_PLOT_METADATA: u64 = 1024 * 1024;
/// Reserve 1M of space for farm info (for potential future expansion)
const RESERVED_FARM_INFO: u64 = 1024 * 1024;
const NEW_SEGMENT_PROCESSING_DELAY: Duration = Duration::from_secs(30);
/// Limit for reads in internal benchmark.
///
/// 4 seconds is proving time, hence 3 seconds for reads.
const INTERNAL_BENCHMARK_READ_TIMEOUT: Duration = Duration::from_millis(3500);

/// Exclusive lock for single disk farm info file, ensuring no concurrent edits by cooperating processes is done
#[derive(Debug)]
#[must_use = "Lock file must be kept around or as long as farm is used"]
pub struct SingleDiskFarmInfoLock {
    _file: File,
}

/// Important information about the contents of the `SingleDiskFarm`
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SingleDiskFarmInfo {
    /// V0 of the info
    #[serde(rename_all = "camelCase")]
    V0 {
        /// ID of the farm
        id: FarmId,
        /// Genesis hash of the chain used for farm creation
        #[serde(with = "hex")]
        genesis_hash: [u8; 32],
        /// Public key of identity used for farm creation
        public_key: PublicKey,
        /// How many pieces does one sector contain.
        pieces_in_sector: u16,
        /// How much space in bytes is allocated for this farm
        allocated_space: u64,
    },
}

impl SingleDiskFarmInfo {
    const FILE_NAME: &'static str = "single_disk_farm.json";

    /// Create new instance
    pub fn new(
        id: FarmId,
        genesis_hash: [u8; 32],
        public_key: PublicKey,
        pieces_in_sector: u16,
        allocated_space: u64,
    ) -> Self {
        Self::V0 {
            id,
            genesis_hash,
            public_key,
            pieces_in_sector,
            allocated_space,
        }
    }

    /// Load `SingleDiskFarm` from path is supposed to be stored, `None` means no info file was
    /// found, happens during first start.
    pub fn load_from(directory: &Path) -> io::Result<Option<Self>> {
        let bytes = match fs::read(directory.join(Self::FILE_NAME)) {
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

    /// Store `SingleDiskFarm` info to path, so it can be loaded again upon restart.
    pub fn store_to(&self, directory: &Path) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(directory.join(Self::FILE_NAME))?;
        fs4::fs_std::FileExt::try_lock_exclusive(&file)?;
        file.write_all(&serde_json::to_vec(self).expect("Info serialization never fails; qed"))
    }

    /// Try to acquire exclusive lock on the single disk farm info file, ensuring no concurrent edits by cooperating
    /// processes is done
    pub fn try_lock(directory: &Path) -> io::Result<SingleDiskFarmInfoLock> {
        let file = File::open(directory.join(Self::FILE_NAME))?;
        fs4::fs_std::FileExt::try_lock_exclusive(&file)?;

        Ok(SingleDiskFarmInfoLock { _file: file })
    }

    /// ID of the farm
    pub fn id(&self) -> &FarmId {
        let Self::V0 { id, .. } = self;
        id
    }

    /// Genesis hash of the chain used for farm creation
    pub fn genesis_hash(&self) -> &[u8; 32] {
        let Self::V0 { genesis_hash, .. } = self;
        genesis_hash
    }

    /// Public key of identity used for farm creation
    pub fn public_key(&self) -> &PublicKey {
        let Self::V0 { public_key, .. } = self;
        public_key
    }

    /// How many pieces does one sector contain.
    pub fn pieces_in_sector(&self) -> u16 {
        match self {
            SingleDiskFarmInfo::V0 {
                pieces_in_sector, ..
            } => *pieces_in_sector,
        }
    }

    /// How much space in bytes is allocated for this farm
    pub fn allocated_space(&self) -> u64 {
        match self {
            SingleDiskFarmInfo::V0 {
                allocated_space, ..
            } => *allocated_space,
        }
    }
}

/// Summary of single disk farm for presentational purposes
#[derive(Debug)]
pub enum SingleDiskFarmSummary {
    /// Farm was found and read successfully
    Found {
        /// Farm info
        info: SingleDiskFarmInfo,
        /// Path to directory where farm is stored.
        directory: PathBuf,
    },
    /// Farm was not found
    NotFound {
        /// Path to directory where farm is stored.
        directory: PathBuf,
    },
    /// Failed to open farm
    Error {
        /// Path to directory where farm is stored.
        directory: PathBuf,
        /// Error itself
        error: io::Error,
    },
}

#[derive(Debug, Encode, Decode)]
struct PlotMetadataHeader {
    version: u8,
    plotted_sector_count: SectorIndex,
}

impl PlotMetadataHeader {
    #[inline]
    fn encoded_size() -> usize {
        let default = PlotMetadataHeader {
            version: 0,
            plotted_sector_count: 0,
        };

        default.encoded_size()
    }
}

/// Options used to open single disk farm
#[derive(Debug)]
pub struct SingleDiskFarmOptions<'a, NC>
where
    NC: Clone,
{
    /// Path to directory where farm is stored.
    pub directory: PathBuf,
    /// Information necessary for farmer application
    pub farmer_app_info: FarmerAppInfo,
    /// How much space in bytes was allocated
    pub allocated_space: u64,
    /// How many pieces one sector is supposed to contain (max)
    pub max_pieces_in_sector: u16,
    /// RPC client connected to Subspace node
    pub node_client: NC,
    /// Address where farming rewards should go
    pub reward_address: PublicKey,
    /// Plotter
    pub plotter: Arc<dyn Plotter + Send + Sync>,
    /// Kzg instance to use.
    pub kzg: Kzg,
    /// Erasure coding instance to use.
    pub erasure_coding: ErasureCoding,
    /// Percentage of allocated space dedicated for caching purposes
    pub cache_percentage: u8,
    /// Thread pool size used for farming (mostly for blocking I/O, but also for some
    /// compute-intensive operations during proving)
    pub farming_thread_pool_size: usize,
    /// Notification for plotter to start, can be used to delay plotting until some initialization
    /// has happened externally
    pub plotting_delay: Option<oneshot::Receiver<()>>,
    /// Global mutex that can restrict concurrency of resource-intensive operations and make sure
    /// that those operations that are very sensitive (like proving) have all the resources
    /// available to them for the highest probability of success
    pub global_mutex: Arc<AsyncMutex<()>>,
    /// Disable farm locking, for example if file system doesn't support it
    pub disable_farm_locking: bool,
    /// Explicit mode to use for reading of sector record chunks instead of doing internal
    /// benchmarking
    pub read_sector_record_chunks_mode: Option<ReadSectorRecordChunksMode>,
    /// Barrier before internal benchmarking between different farms
    pub faster_read_sector_record_chunks_mode_barrier: Arc<Barrier>,
    /// Limit concurrency of internal benchmarking between different farms
    pub faster_read_sector_record_chunks_mode_concurrency: Arc<Semaphore>,
    /// Prometheus registry
    pub registry: Option<&'a Mutex<&'a mut Registry>>,
    /// Whether to create a farm if it doesn't yet exist
    pub create: bool,
}

/// Errors happening when trying to create/open single disk farm
#[derive(Debug, Error)]
pub enum SingleDiskFarmError {
    /// Failed to open or create identity
    #[error("Failed to open or create identity: {0}")]
    FailedToOpenIdentity(#[from] IdentityError),
    /// Farm is likely already in use, make sure no other farmer is using it
    #[error("Farm is likely already in use, make sure no other farmer is using it: {0}")]
    LikelyAlreadyInUse(io::Error),
    /// I/O error occurred
    #[error("Single disk farm I/O error: {0}")]
    Io(#[from] io::Error),
    /// Failed to spawn task for blocking thread
    #[error("Failed to spawn task for blocking thread: {0}")]
    TokioJoinError(#[from] task::JoinError),
    /// Piece cache error
    #[error("Piece cache error: {0}")]
    PieceCacheError(#[from] DiskPieceCacheError),
    /// Can't preallocate metadata file, probably not enough space on disk
    #[error("Can't preallocate metadata file, probably not enough space on disk: {0}")]
    CantPreallocateMetadataFile(io::Error),
    /// Can't preallocate plot file, probably not enough space on disk
    #[error("Can't preallocate plot file, probably not enough space on disk: {0}")]
    CantPreallocatePlotFile(io::Error),
    /// Wrong chain (genesis hash)
    #[error(
        "Genesis hash of farm {id} {wrong_chain} is different from {correct_chain} when farm was \
        created, it is not possible to use farm on a different chain"
    )]
    WrongChain {
        /// Farm ID
        id: FarmId,
        /// Hex-encoded genesis hash during farm creation
        // TODO: Wrapper type with `Display` impl for genesis hash
        correct_chain: String,
        /// Hex-encoded current genesis hash
        wrong_chain: String,
    },
    /// Public key in identity doesn't match metadata
    #[error(
        "Public key of farm {id} {wrong_public_key} is different from {correct_public_key} when \
        farm was created, something went wrong, likely due to manual edits"
    )]
    IdentityMismatch {
        /// Farm ID
        id: FarmId,
        /// Public key used during farm creation
        correct_public_key: PublicKey,
        /// Current public key
        wrong_public_key: PublicKey,
    },
    /// Invalid number pieces in sector
    #[error(
        "Invalid number pieces in sector: max supported {max_supported}, farm initialized with \
        {initialized_with}"
    )]
    InvalidPiecesInSector {
        /// Farm ID
        id: FarmId,
        /// Max supported pieces in sector
        max_supported: u16,
        /// Number of pieces in sector farm is initialized with
        initialized_with: u16,
    },
    /// Failed to decode metadata header
    #[error("Failed to decode metadata header: {0}")]
    FailedToDecodeMetadataHeader(parity_scale_codec::Error),
    /// Unexpected metadata version
    #[error("Unexpected metadata version {0}")]
    UnexpectedMetadataVersion(u8),
    /// Allocated space is not enough for one sector
    #[error(
        "Allocated space is not enough for one sector. \
        The lowest acceptable value for allocated space is {min_space} bytes, \
        provided {allocated_space} bytes."
    )]
    InsufficientAllocatedSpace {
        /// Minimal allocated space
        min_space: u64,
        /// Current allocated space
        allocated_space: u64,
    },
    /// Farm is too large
    #[error(
        "Farm is too large: allocated {allocated_sectors} sectors ({allocated_space} bytes), max \
        supported is {max_sectors} ({max_space} bytes). Consider creating multiple smaller farms \
        instead."
    )]
    FarmTooLarge {
        /// Allocated space
        allocated_space: u64,
        /// Allocated space in sectors
        allocated_sectors: u64,
        /// Max supported allocated space
        max_space: u64,
        /// Max supported allocated space in sectors
        max_sectors: u16,
    },
    /// Failed to create thread pool
    #[error("Failed to create thread pool: {0}")]
    FailedToCreateThreadPool(ThreadPoolBuildError),
}

/// Errors happening during scrubbing
#[derive(Debug, Error)]
pub enum SingleDiskFarmScrubError {
    /// Farm is likely already in use, make sure no other farmer is using it
    #[error("Farm is likely already in use, make sure no other farmer is using it: {0}")]
    LikelyAlreadyInUse(io::Error),
    /// Failed to determine file size
    #[error("Failed to file size of {file}: {error}")]
    FailedToDetermineFileSize {
        /// Affected file
        file: PathBuf,
        /// Low-level error
        error: io::Error,
    },
    /// Failed to read bytes from file
    #[error("Failed to read {size} bytes from {file} at offset {offset}: {error}")]
    FailedToReadBytes {
        /// Affected file
        file: PathBuf,
        /// Number of bytes to read
        size: u64,
        /// Offset in the file
        offset: u64,
        /// Low-level error
        error: io::Error,
    },
    /// Failed to write bytes from file
    #[error("Failed to write {size} bytes from {file} at offset {offset}: {error}")]
    FailedToWriteBytes {
        /// Affected file
        file: PathBuf,
        /// Number of bytes to read
        size: u64,
        /// Offset in the file
        offset: u64,
        /// Low-level error
        error: io::Error,
    },
    /// Farm info file does not exist
    #[error("Farm info file does not exist at {file}")]
    FarmInfoFileDoesNotExist {
        /// Info file
        file: PathBuf,
    },
    /// Farm info can't be opened
    #[error("Farm info at {file} can't be opened: {error}")]
    FarmInfoCantBeOpened {
        /// Info file
        file: PathBuf,
        /// Low-level error
        error: io::Error,
    },
    /// Identity file does not exist
    #[error("Identity file does not exist at {file}")]
    IdentityFileDoesNotExist {
        /// Identity file
        file: PathBuf,
    },
    /// Identity can't be opened
    #[error("Identity at {file} can't be opened: {error}")]
    IdentityCantBeOpened {
        /// Identity file
        file: PathBuf,
        /// Low-level error
        error: IdentityError,
    },
    /// Identity public key doesn't match public key in the disk farm info
    #[error(
        "Identity public key {identity} doesn't match public key in the disk farm info {info}"
    )]
    PublicKeyMismatch {
        /// Identity public key
        identity: PublicKey,
        /// Disk farm info public key
        info: PublicKey,
    },
    /// Metadata file does not exist
    #[error("Metadata file does not exist at {file}")]
    MetadataFileDoesNotExist {
        /// Metadata file
        file: PathBuf,
    },
    /// Metadata can't be opened
    #[error("Metadata at {file} can't be opened: {error}")]
    MetadataCantBeOpened {
        /// Metadata file
        file: PathBuf,
        /// Low-level error
        error: io::Error,
    },
    /// Metadata file too small
    #[error(
        "Metadata file at {file} is too small: reserved size is {reserved_size} bytes, file size \
        is {size}"
    )]
    MetadataFileTooSmall {
        /// Metadata file
        file: PathBuf,
        /// Reserved size
        reserved_size: u64,
        /// File size
        size: u64,
    },
    /// Failed to decode metadata header
    #[error("Failed to decode metadata header: {0}")]
    FailedToDecodeMetadataHeader(parity_scale_codec::Error),
    /// Unexpected metadata version
    #[error("Unexpected metadata version {0}")]
    UnexpectedMetadataVersion(u8),
    /// Cache can't be opened
    #[error("Cache at {file} can't be opened: {error}")]
    CacheCantBeOpened {
        /// Cache file
        file: PathBuf,
        /// Low-level error
        error: io::Error,
    },
}

/// Errors that happen in background tasks
#[derive(Debug, Error)]
pub enum BackgroundTaskError {
    /// Plotting error
    #[error(transparent)]
    Plotting(#[from] PlottingError),
    /// Farming error
    #[error(transparent)]
    Farming(#[from] FarmingError),
    /// Reward signing
    #[error(transparent)]
    RewardSigning(#[from] Box<dyn Error + Send + Sync + 'static>),
    /// Background task panicked
    #[error("Background task {task} panicked")]
    BackgroundTaskPanicked {
        /// Name of the task
        task: String,
    },
}

type BackgroundTask = Pin<Box<dyn Future<Output = Result<(), BackgroundTaskError>> + Send>>;

/// Scrub target
#[derive(Debug, Copy, Clone)]
pub enum ScrubTarget {
    /// Scrub everything
    All,
    /// Scrub just metadata
    Metadata,
    /// Scrub metadata and corresponding plot
    Plot,
    /// Only scrub cache
    Cache,
}

impl fmt::Display for ScrubTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("all"),
            Self::Metadata => f.write_str("metadata"),
            Self::Plot => f.write_str("plot"),
            Self::Cache => f.write_str("cache"),
        }
    }
}

impl FromStr for ScrubTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(Self::All),
            "metadata" => Ok(Self::Metadata),
            "plot" => Ok(Self::Plot),
            "cache" => Ok(Self::Cache),
            s => Err(format!("Can't parse {s} as `ScrubTarget`")),
        }
    }
}

impl ScrubTarget {
    fn metadata(&self) -> bool {
        match self {
            Self::All | Self::Metadata | Self::Plot => true,
            Self::Cache => false,
        }
    }

    fn plot(&self) -> bool {
        match self {
            Self::All | Self::Plot => true,
            Self::Metadata | Self::Cache => false,
        }
    }

    fn cache(&self) -> bool {
        match self {
            Self::All | Self::Cache => true,
            Self::Metadata | Self::Plot => false,
        }
    }
}

struct AllocatedSpaceDistribution {
    piece_cache_file_size: u64,
    piece_cache_capacity: u32,
    plot_file_size: u64,
    target_sector_count: u16,
    metadata_file_size: u64,
}

impl AllocatedSpaceDistribution {
    fn new(
        allocated_space: u64,
        sector_size: u64,
        cache_percentage: u8,
        sector_metadata_size: u64,
    ) -> Result<Self, SingleDiskFarmError> {
        let single_sector_overhead = sector_size + sector_metadata_size;
        // Fixed space usage regardless of plot size
        let fixed_space_usage = RESERVED_PLOT_METADATA
            + RESERVED_FARM_INFO
            + Identity::file_size() as u64
            + KnownPeersManager::file_size(KNOWN_PEERS_CACHE_SIZE) as u64;
        // Calculate how many sectors can fit
        let target_sector_count = {
            let potentially_plottable_space = allocated_space.saturating_sub(fixed_space_usage)
                / 100
                * (100 - u64::from(cache_percentage));
            // Do the rounding to make sure we have exactly as much space as fits whole number of
            // sectors, account for disk sector size just in case
            (potentially_plottable_space - DISK_SECTOR_SIZE as u64) / single_sector_overhead
        };

        if target_sector_count == 0 {
            let mut single_plot_with_cache_space =
                single_sector_overhead.div_ceil(100 - u64::from(cache_percentage)) * 100;
            // Cache must not be empty, ensure it contains at least one element even if
            // percentage-wise it will use more space
            if single_plot_with_cache_space - single_sector_overhead
                < DiskPieceCache::element_size() as u64
            {
                single_plot_with_cache_space =
                    single_sector_overhead + DiskPieceCache::element_size() as u64;
            }

            return Err(SingleDiskFarmError::InsufficientAllocatedSpace {
                min_space: fixed_space_usage + single_plot_with_cache_space,
                allocated_space,
            });
        }
        let plot_file_size = target_sector_count * sector_size;
        // Align plot file size for disk sector size
        let plot_file_size =
            plot_file_size.div_ceil(DISK_SECTOR_SIZE as u64) * DISK_SECTOR_SIZE as u64;

        // Remaining space will be used for caching purposes
        let piece_cache_capacity = if cache_percentage > 0 {
            let cache_space = allocated_space
                - fixed_space_usage
                - plot_file_size
                - (sector_metadata_size * target_sector_count);
            (cache_space / u64::from(DiskPieceCache::element_size())) as u32
        } else {
            0
        };
        let target_sector_count = match SectorIndex::try_from(target_sector_count) {
            Ok(target_sector_count) if target_sector_count < SectorIndex::MAX => {
                target_sector_count
            }
            _ => {
                // We use this for both count and index, hence index must not reach actual `MAX`
                // (consensus doesn't care about this, just farmer implementation detail)
                let max_sectors = SectorIndex::MAX - 1;
                return Err(SingleDiskFarmError::FarmTooLarge {
                    allocated_space: target_sector_count * sector_size,
                    allocated_sectors: target_sector_count,
                    max_space: max_sectors as u64 * sector_size,
                    max_sectors,
                });
            }
        };

        Ok(Self {
            piece_cache_file_size: u64::from(piece_cache_capacity)
                * u64::from(DiskPieceCache::element_size()),
            piece_cache_capacity,
            plot_file_size,
            target_sector_count,
            metadata_file_size: RESERVED_PLOT_METADATA
                + sector_metadata_size * u64::from(target_sector_count),
        })
    }
}

type Handler<A> = Bag<HandlerFn<A>, A>;

#[derive(Default, Debug)]
struct Handlers {
    sector_update: Handler<(SectorIndex, SectorUpdate)>,
    farming_notification: Handler<FarmingNotification>,
    solution: Handler<SolutionResponse>,
}

struct SingleDiskFarmInit {
    identity: Identity,
    single_disk_farm_info: SingleDiskFarmInfo,
    single_disk_farm_info_lock: Option<SingleDiskFarmInfoLock>,
    plot_file: Arc<DirectIoFile>,
    metadata_file: DirectIoFile,
    metadata_header: PlotMetadataHeader,
    target_sector_count: u16,
    sectors_metadata: Arc<AsyncRwLock<Vec<SectorMetadataChecksummed>>>,
    piece_cache_capacity: u32,
    plot_cache: DiskPlotCache,
}

/// Single disk farm abstraction is a container for everything necessary to plot/farm with a single
/// disk.
///
/// Farm starts operating during creation and doesn't stop until dropped (or error happens).
#[derive(Debug)]
#[must_use = "Plot does not function properly unless run() method is called"]
pub struct SingleDiskFarm {
    farmer_protocol_info: FarmerProtocolInfo,
    single_disk_farm_info: SingleDiskFarmInfo,
    /// Metadata of all sectors plotted so far
    sectors_metadata: Arc<AsyncRwLock<Vec<SectorMetadataChecksummed>>>,
    pieces_in_sector: u16,
    total_sectors_count: SectorIndex,
    span: Span,
    tasks: FuturesUnordered<BackgroundTask>,
    handlers: Arc<Handlers>,
    piece_cache: SingleDiskPieceCache,
    plot_cache: DiskPlotCache,
    piece_reader: DiskPieceReader,
    /// Sender that will be used to signal to background threads that they should start
    start_sender: Option<broadcast::Sender<()>>,
    /// Sender that will be used to signal to background threads that they must stop
    stop_sender: Option<broadcast::Sender<()>>,
    _single_disk_farm_info_lock: Option<SingleDiskFarmInfoLock>,
}

impl Drop for SingleDiskFarm {
    #[inline]
    fn drop(&mut self) {
        self.piece_reader.close_all_readers();
        // Make background threads that are waiting to do something exit immediately
        self.start_sender.take();
        // Notify background tasks that they must stop
        self.stop_sender.take();
    }
}

#[async_trait(?Send)]
impl Farm for SingleDiskFarm {
    fn id(&self) -> &FarmId {
        self.id()
    }

    fn total_sectors_count(&self) -> SectorIndex {
        self.total_sectors_count
    }

    fn plotted_sectors(&self) -> Arc<dyn PlottedSectors + 'static> {
        Arc::new(self.plotted_sectors())
    }

    fn piece_reader(&self) -> Arc<dyn PieceReader + 'static> {
        Arc::new(self.piece_reader())
    }

    fn on_sector_update(
        &self,
        callback: HandlerFn<(SectorIndex, SectorUpdate)>,
    ) -> Box<dyn farm::HandlerId> {
        Box::new(self.on_sector_update(callback))
    }

    fn on_farming_notification(
        &self,
        callback: HandlerFn<FarmingNotification>,
    ) -> Box<dyn farm::HandlerId> {
        Box::new(self.on_farming_notification(callback))
    }

    fn on_solution(&self, callback: HandlerFn<SolutionResponse>) -> Box<dyn farm::HandlerId> {
        Box::new(self.on_solution(callback))
    }

    fn run(self: Box<Self>) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> {
        Box::pin((*self).run())
    }
}

impl SingleDiskFarm {
    /// Name of the plot file
    pub const PLOT_FILE: &'static str = "plot.bin";
    /// Name of the metadata file
    pub const METADATA_FILE: &'static str = "metadata.bin";
    const SUPPORTED_PLOT_VERSION: u8 = 0;

    /// Create new single disk farm instance
    pub async fn new<NC, PosTable>(
        options: SingleDiskFarmOptions<'_, NC>,
        farm_index: usize,
    ) -> Result<Self, SingleDiskFarmError>
    where
        NC: NodeClient + Clone,
        PosTable: Table,
    {
        let span = Span::current();

        let SingleDiskFarmOptions {
            directory,
            farmer_app_info,
            allocated_space,
            max_pieces_in_sector,
            node_client,
            reward_address,
            plotter,
            kzg,
            erasure_coding,
            cache_percentage,
            farming_thread_pool_size,
            plotting_delay,
            global_mutex,
            disable_farm_locking,
            read_sector_record_chunks_mode,
            faster_read_sector_record_chunks_mode_barrier,
            faster_read_sector_record_chunks_mode_concurrency,
            registry,
            create,
        } = options;

        let single_disk_farm_init_fut = task::spawn_blocking({
            let directory = directory.clone();
            let farmer_app_info = farmer_app_info.clone();
            let span = span.clone();

            move || {
                let _span_guard = span.enter();
                Self::init(
                    &directory,
                    &farmer_app_info,
                    allocated_space,
                    max_pieces_in_sector,
                    cache_percentage,
                    disable_farm_locking,
                    create,
                )
            }
        });

        let single_disk_farm_init =
            AsyncJoinOnDrop::new(single_disk_farm_init_fut, false).await??;

        let SingleDiskFarmInit {
            identity,
            single_disk_farm_info,
            single_disk_farm_info_lock,
            plot_file,
            metadata_file,
            metadata_header,
            target_sector_count,
            sectors_metadata,
            piece_cache_capacity,
            plot_cache,
        } = single_disk_farm_init;

        let piece_cache = {
            // Convert farm ID into cache ID for single disk farm
            let FarmId::Ulid(id) = *single_disk_farm_info.id();
            let id = PieceCacheId::Ulid(id);

            SingleDiskPieceCache::new(
                id,
                if piece_cache_capacity == 0 {
                    None
                } else {
                    Some(task::block_in_place(|| {
                        if let Some(registry) = registry {
                            DiskPieceCache::open(
                                &directory,
                                piece_cache_capacity,
                                Some(id),
                                Some(*registry.lock()),
                            )
                        } else {
                            DiskPieceCache::open(&directory, piece_cache_capacity, Some(id), None)
                        }
                    })?)
                },
            )
        };

        let public_key = *single_disk_farm_info.public_key();
        let pieces_in_sector = single_disk_farm_info.pieces_in_sector();
        let sector_size = sector_size(pieces_in_sector);

        let metrics = registry.map(|registry| {
            Arc::new(SingleDiskFarmMetrics::new(
                *registry.lock(),
                single_disk_farm_info.id(),
                target_sector_count,
                sectors_metadata.read_blocking().len() as SectorIndex,
            ))
        });

        let (error_sender, error_receiver) = oneshot::channel();
        let error_sender = Arc::new(Mutex::new(Some(error_sender)));

        let tasks = FuturesUnordered::<BackgroundTask>::new();

        tasks.push(Box::pin(async move {
            if let Ok(error) = error_receiver.await {
                return Err(error);
            }

            Ok(())
        }));

        let handlers = Arc::<Handlers>::default();
        let (start_sender, mut start_receiver) = broadcast::channel::<()>(1);
        let (stop_sender, mut stop_receiver) = broadcast::channel::<()>(1);
        let sectors_being_modified = Arc::<AsyncRwLock<HashSet<SectorIndex>>>::default();
        let (sectors_to_plot_sender, sectors_to_plot_receiver) = mpsc::channel(1);
        // Some sectors may already be plotted, skip them
        let sectors_indices_left_to_plot =
            metadata_header.plotted_sector_count..target_sector_count;

        let farming_thread_pool = ThreadPoolBuilder::new()
            .thread_name(move |thread_index| format!("farming-{farm_index}.{thread_index}"))
            .num_threads(farming_thread_pool_size)
            .spawn_handler(tokio_rayon_spawn_handler())
            .build()
            .map_err(SingleDiskFarmError::FailedToCreateThreadPool)?;
        let farming_plot_fut = task::spawn_blocking(|| {
            farming_thread_pool
                .install(move || {
                    RayonFiles::open_with(&directory.join(Self::PLOT_FILE), DirectIoFile::open)
                })
                .map(|farming_plot| (farming_plot, farming_thread_pool))
        });

        let (farming_plot, farming_thread_pool) =
            AsyncJoinOnDrop::new(farming_plot_fut, false).await??;

        faster_read_sector_record_chunks_mode_barrier.wait().await;

        let (read_sector_record_chunks_mode, farming_plot, farming_thread_pool) =
            if let Some(mode) = read_sector_record_chunks_mode {
                (mode, farming_plot, farming_thread_pool)
            } else {
                // Error doesn't matter here
                let _permit = faster_read_sector_record_chunks_mode_concurrency
                    .acquire()
                    .await;
                let span = span.clone();
                let plot_file = Arc::clone(&plot_file);

                let read_sector_record_chunks_mode_fut = task::spawn_blocking(move || {
                    farming_thread_pool
                        .install(move || {
                            let _span_guard = span.enter();

                            faster_read_sector_record_chunks_mode(
                                &*plot_file,
                                &farming_plot,
                                sector_size,
                                metadata_header.plotted_sector_count,
                            )
                            .map(|mode| (mode, farming_plot))
                        })
                        .map(|(mode, farming_plot)| (mode, farming_plot, farming_thread_pool))
                });

                AsyncJoinOnDrop::new(read_sector_record_chunks_mode_fut, false).await??
            };

        faster_read_sector_record_chunks_mode_barrier.wait().await;

        let plotting_join_handle = task::spawn_blocking({
            let sectors_metadata = Arc::clone(&sectors_metadata);
            let handlers = Arc::clone(&handlers);
            let sectors_being_modified = Arc::clone(&sectors_being_modified);
            let node_client = node_client.clone();
            let plot_file = Arc::clone(&plot_file);
            let error_sender = Arc::clone(&error_sender);
            let span = span.clone();
            let global_mutex = Arc::clone(&global_mutex);
            let metrics = metrics.clone();

            move || {
                let _span_guard = span.enter();

                let plotting_options = PlottingOptions {
                    metadata_header,
                    sectors_metadata: &sectors_metadata,
                    sectors_being_modified: &sectors_being_modified,
                    sectors_to_plot_receiver,
                    sector_plotting_options: SectorPlottingOptions {
                        public_key,
                        node_client: &node_client,
                        pieces_in_sector,
                        sector_size,
                        plot_file,
                        metadata_file: Arc::new(metadata_file),
                        handlers: &handlers,
                        global_mutex: &global_mutex,
                        plotter,
                        metrics,
                    },
                };

                let plotting_fut = async {
                    if start_receiver.recv().await.is_err() {
                        // Dropped before starting
                        return Ok(());
                    }

                    if let Some(plotting_delay) = plotting_delay {
                        if plotting_delay.await.is_err() {
                            // Dropped before resolving
                            return Ok(());
                        }
                    }

                    plotting(plotting_options).await
                };

                Handle::current().block_on(async {
                    select! {
                        plotting_result = plotting_fut.fuse() => {
                            if let Err(error) = plotting_result
                                && let Some(error_sender) = error_sender.lock().take()
                                && let Err(error) = error_sender.send(error.into())
                            {
                                error!(
                                    %error,
                                    "Plotting failed to send error to background task"
                                );
                            }
                        }
                        _ = stop_receiver.recv().fuse() => {
                            // Nothing, just exit
                        }
                    }
                });
            }
        });
        let plotting_join_handle = AsyncJoinOnDrop::new(plotting_join_handle, false);

        tasks.push(Box::pin(async move {
            // Panic will already be printed by now
            plotting_join_handle.await.map_err(|_error| {
                BackgroundTaskError::BackgroundTaskPanicked {
                    task: format!("plotting-{farm_index}"),
                }
            })
        }));

        let plotting_scheduler_options = PlottingSchedulerOptions {
            public_key_hash: public_key.hash(),
            sectors_indices_left_to_plot,
            target_sector_count,
            last_archived_segment_index: farmer_app_info.protocol_info.history_size.segment_index(),
            min_sector_lifetime: farmer_app_info.protocol_info.min_sector_lifetime,
            node_client: node_client.clone(),
            handlers: Arc::clone(&handlers),
            sectors_metadata: Arc::clone(&sectors_metadata),
            sectors_to_plot_sender,
            new_segment_processing_delay: NEW_SEGMENT_PROCESSING_DELAY,
            metrics: metrics.clone(),
        };
        tasks.push(Box::pin(plotting_scheduler(plotting_scheduler_options)));

        let (slot_info_forwarder_sender, slot_info_forwarder_receiver) = mpsc::channel(0);

        tasks.push(Box::pin({
            let node_client = node_client.clone();
            let metrics = metrics.clone();

            async move {
                slot_notification_forwarder(&node_client, slot_info_forwarder_sender, metrics)
                    .await
                    .map_err(BackgroundTaskError::Farming)
            }
        }));

        let farming_join_handle = task::spawn_blocking({
            let erasure_coding = erasure_coding.clone();
            let handlers = Arc::clone(&handlers);
            let sectors_being_modified = Arc::clone(&sectors_being_modified);
            let sectors_metadata = Arc::clone(&sectors_metadata);
            let mut start_receiver = start_sender.subscribe();
            let mut stop_receiver = stop_sender.subscribe();
            let node_client = node_client.clone();
            let span = span.clone();
            let global_mutex = Arc::clone(&global_mutex);

            move || {
                let _span_guard = span.enter();

                let farming_fut = async move {
                    if start_receiver.recv().await.is_err() {
                        // Dropped before starting
                        return Ok(());
                    }

                    let plot_audit = PlotAudit::new(&farming_plot);

                    let farming_options = FarmingOptions {
                        public_key,
                        reward_address,
                        node_client,
                        plot_audit,
                        sectors_metadata,
                        kzg,
                        erasure_coding,
                        handlers,
                        sectors_being_modified,
                        slot_info_notifications: slot_info_forwarder_receiver,
                        thread_pool: farming_thread_pool,
                        read_sector_record_chunks_mode,
                        global_mutex,
                        metrics,
                    };
                    farming::<PosTable, _, _>(farming_options).await
                };

                Handle::current().block_on(async {
                    select! {
                        farming_result = farming_fut.fuse() => {
                            if let Err(error) = farming_result
                                && let Some(error_sender) = error_sender.lock().take()
                                && let Err(error) = error_sender.send(error.into())
                            {
                                error!(
                                    %error,
                                    "Farming failed to send error to background task",
                                );
                            }
                        }
                        _ = stop_receiver.recv().fuse() => {
                            // Nothing, just exit
                        }
                    }
                });
            }
        });
        let farming_join_handle = AsyncJoinOnDrop::new(farming_join_handle, false);

        tasks.push(Box::pin(async move {
            // Panic will already be printed by now
            farming_join_handle.await.map_err(|_error| {
                BackgroundTaskError::BackgroundTaskPanicked {
                    task: format!("farming-{farm_index}"),
                }
            })
        }));

        let (piece_reader, reading_fut) = DiskPieceReader::new::<PosTable>(
            public_key,
            pieces_in_sector,
            plot_file,
            Arc::clone(&sectors_metadata),
            erasure_coding,
            sectors_being_modified,
            read_sector_record_chunks_mode,
            global_mutex,
        );

        let reading_join_handle = task::spawn_blocking({
            let mut stop_receiver = stop_sender.subscribe();
            let reading_fut = reading_fut.instrument(span.clone());

            move || {
                Handle::current().block_on(async {
                    select! {
                        _ = reading_fut.fuse() => {
                            // Nothing, just exit
                        }
                        _ = stop_receiver.recv().fuse() => {
                            // Nothing, just exit
                        }
                    }
                });
            }
        });

        let reading_join_handle = AsyncJoinOnDrop::new(reading_join_handle, false);

        tasks.push(Box::pin(async move {
            // Panic will already be printed by now
            reading_join_handle.await.map_err(|_error| {
                BackgroundTaskError::BackgroundTaskPanicked {
                    task: format!("reading-{farm_index}"),
                }
            })
        }));

        tasks.push(Box::pin(async move {
            match reward_signing(node_client, identity).await {
                Ok(reward_signing_fut) => {
                    reward_signing_fut.await;
                }
                Err(error) => {
                    return Err(BackgroundTaskError::RewardSigning(
                        format!("Failed to subscribe to reward signing notifications: {error}")
                            .into(),
                    ));
                }
            }

            Ok(())
        }));

        let farm = Self {
            farmer_protocol_info: farmer_app_info.protocol_info,
            single_disk_farm_info,
            sectors_metadata,
            pieces_in_sector,
            total_sectors_count: target_sector_count,
            span,
            tasks,
            handlers,
            piece_cache,
            plot_cache,
            piece_reader,
            start_sender: Some(start_sender),
            stop_sender: Some(stop_sender),
            _single_disk_farm_info_lock: single_disk_farm_info_lock,
        };
        Ok(farm)
    }

    fn init(
        directory: &PathBuf,
        farmer_app_info: &FarmerAppInfo,
        allocated_space: u64,
        max_pieces_in_sector: u16,
        cache_percentage: u8,
        disable_farm_locking: bool,
        create: bool,
    ) -> Result<SingleDiskFarmInit, SingleDiskFarmError> {
        fs::create_dir_all(directory)?;

        let identity = if create {
            Identity::open_or_create(directory)?
        } else {
            Identity::open(directory)?.ok_or_else(|| {
                IdentityError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Farm does not exist and creation was explicitly disabled",
                ))
            })?
        };
        let public_key = identity.public_key().to_bytes().into();

        let single_disk_farm_info = match SingleDiskFarmInfo::load_from(directory)? {
            Some(mut single_disk_farm_info) => {
                if &farmer_app_info.genesis_hash != single_disk_farm_info.genesis_hash() {
                    return Err(SingleDiskFarmError::WrongChain {
                        id: *single_disk_farm_info.id(),
                        correct_chain: hex::encode(single_disk_farm_info.genesis_hash()),
                        wrong_chain: hex::encode(farmer_app_info.genesis_hash),
                    });
                }

                if &public_key != single_disk_farm_info.public_key() {
                    return Err(SingleDiskFarmError::IdentityMismatch {
                        id: *single_disk_farm_info.id(),
                        correct_public_key: *single_disk_farm_info.public_key(),
                        wrong_public_key: public_key,
                    });
                }

                let pieces_in_sector = single_disk_farm_info.pieces_in_sector();

                if max_pieces_in_sector < pieces_in_sector {
                    return Err(SingleDiskFarmError::InvalidPiecesInSector {
                        id: *single_disk_farm_info.id(),
                        max_supported: max_pieces_in_sector,
                        initialized_with: pieces_in_sector,
                    });
                }

                if max_pieces_in_sector > pieces_in_sector {
                    info!(
                        pieces_in_sector,
                        max_pieces_in_sector,
                        "Farm initialized with smaller number of pieces in sector, farm needs to \
                        be re-created for increase"
                    );
                }

                if allocated_space != single_disk_farm_info.allocated_space() {
                    info!(
                        old_space = %bytesize::to_string(single_disk_farm_info.allocated_space(), true),
                        new_space = %bytesize::to_string(allocated_space, true),
                        "Farm size has changed"
                    );

                    let new_allocated_space = allocated_space;
                    match &mut single_disk_farm_info {
                        SingleDiskFarmInfo::V0 {
                            allocated_space, ..
                        } => {
                            *allocated_space = new_allocated_space;
                        }
                    }

                    single_disk_farm_info.store_to(directory)?;
                }

                single_disk_farm_info
            }
            None => {
                let single_disk_farm_info = SingleDiskFarmInfo::new(
                    FarmId::new(),
                    farmer_app_info.genesis_hash,
                    public_key,
                    max_pieces_in_sector,
                    allocated_space,
                );

                single_disk_farm_info.store_to(directory)?;

                single_disk_farm_info
            }
        };

        let single_disk_farm_info_lock = if disable_farm_locking {
            None
        } else {
            Some(
                SingleDiskFarmInfo::try_lock(directory)
                    .map_err(SingleDiskFarmError::LikelyAlreadyInUse)?,
            )
        };

        let pieces_in_sector = single_disk_farm_info.pieces_in_sector();
        let sector_size = sector_size(pieces_in_sector) as u64;
        let sector_metadata_size = SectorMetadataChecksummed::encoded_size();
        let allocated_space_distribution = AllocatedSpaceDistribution::new(
            allocated_space,
            sector_size,
            cache_percentage,
            sector_metadata_size as u64,
        )?;
        let target_sector_count = allocated_space_distribution.target_sector_count;

        let metadata_file_path = directory.join(Self::METADATA_FILE);
        let metadata_file = DirectIoFile::open(&metadata_file_path)?;

        let metadata_size = metadata_file.size()?;
        let expected_metadata_size = allocated_space_distribution.metadata_file_size;
        // Align plot file size for disk sector size
        let expected_metadata_size =
            expected_metadata_size.div_ceil(DISK_SECTOR_SIZE as u64) * DISK_SECTOR_SIZE as u64;
        let metadata_header = if metadata_size == 0 {
            let metadata_header = PlotMetadataHeader {
                version: SingleDiskFarm::SUPPORTED_PLOT_VERSION,
                plotted_sector_count: 0,
            };

            metadata_file
                .preallocate(expected_metadata_size)
                .map_err(SingleDiskFarmError::CantPreallocateMetadataFile)?;
            metadata_file.write_all_at(metadata_header.encode().as_slice(), 0)?;

            metadata_header
        } else {
            if metadata_size != expected_metadata_size {
                // Allocating the whole file (`set_len` below can create a sparse file, which will
                // cause writes to fail later)
                metadata_file
                    .preallocate(expected_metadata_size)
                    .map_err(SingleDiskFarmError::CantPreallocateMetadataFile)?;
                // Truncating file (if necessary)
                metadata_file.set_len(expected_metadata_size)?;
            }

            let mut metadata_header_bytes = vec![0; PlotMetadataHeader::encoded_size()];
            metadata_file.read_exact_at(&mut metadata_header_bytes, 0)?;

            let mut metadata_header =
                PlotMetadataHeader::decode(&mut metadata_header_bytes.as_ref())
                    .map_err(SingleDiskFarmError::FailedToDecodeMetadataHeader)?;

            if metadata_header.version != SingleDiskFarm::SUPPORTED_PLOT_VERSION {
                return Err(SingleDiskFarmError::UnexpectedMetadataVersion(
                    metadata_header.version,
                ));
            }

            if metadata_header.plotted_sector_count > target_sector_count {
                metadata_header.plotted_sector_count = target_sector_count;
                metadata_file.write_all_at(&metadata_header.encode(), 0)?;
            }

            metadata_header
        };

        let sectors_metadata = {
            let mut sectors_metadata =
                Vec::<SectorMetadataChecksummed>::with_capacity(usize::from(target_sector_count));

            let mut sector_metadata_bytes = vec![0; sector_metadata_size];
            for sector_index in 0..metadata_header.plotted_sector_count {
                let sector_offset =
                    RESERVED_PLOT_METADATA + sector_metadata_size as u64 * u64::from(sector_index);
                metadata_file.read_exact_at(&mut sector_metadata_bytes, sector_offset)?;

                let sector_metadata =
                    match SectorMetadataChecksummed::decode(&mut sector_metadata_bytes.as_ref()) {
                        Ok(sector_metadata) => sector_metadata,
                        Err(error) => {
                            warn!(
                                path = %metadata_file_path.display(),
                                %error,
                                %sector_index,
                                "Failed to decode sector metadata, replacing with dummy expired \
                                sector metadata"
                            );

                            let dummy_sector = SectorMetadataChecksummed::from(SectorMetadata {
                                sector_index,
                                pieces_in_sector,
                                s_bucket_sizes: Box::new([0; Record::NUM_S_BUCKETS]),
                                history_size: HistorySize::from(SegmentIndex::ZERO),
                            });
                            metadata_file.write_all_at(&dummy_sector.encode(), sector_offset)?;

                            dummy_sector
                        }
                    };
                sectors_metadata.push(sector_metadata);
            }

            Arc::new(AsyncRwLock::new(sectors_metadata))
        };

        let plot_file = DirectIoFile::open(&directory.join(Self::PLOT_FILE))?;

        if plot_file.size()? != allocated_space_distribution.plot_file_size {
            // Allocating the whole file (`set_len` below can create a sparse file, which will cause
            // writes to fail later)
            plot_file
                .preallocate(allocated_space_distribution.plot_file_size)
                .map_err(SingleDiskFarmError::CantPreallocatePlotFile)?;
            // Truncating file (if necessary)
            plot_file.set_len(allocated_space_distribution.plot_file_size)?;
        }

        let plot_file = Arc::new(plot_file);

        let plot_cache = DiskPlotCache::new(
            &plot_file,
            &sectors_metadata,
            target_sector_count,
            sector_size,
        );

        Ok(SingleDiskFarmInit {
            identity,
            single_disk_farm_info,
            single_disk_farm_info_lock,
            plot_file,
            metadata_file,
            metadata_header,
            target_sector_count,
            sectors_metadata,
            piece_cache_capacity: allocated_space_distribution.piece_cache_capacity,
            plot_cache,
        })
    }

    /// Collect summary of single disk farm for presentational purposes
    pub fn collect_summary(directory: PathBuf) -> SingleDiskFarmSummary {
        let single_disk_farm_info = match SingleDiskFarmInfo::load_from(&directory) {
            Ok(Some(single_disk_farm_info)) => single_disk_farm_info,
            Ok(None) => {
                return SingleDiskFarmSummary::NotFound { directory };
            }
            Err(error) => {
                return SingleDiskFarmSummary::Error { directory, error };
            }
        };

        SingleDiskFarmSummary::Found {
            info: single_disk_farm_info,
            directory,
        }
    }

    /// Effective on-disk allocation of the files related to the farm (takes some buffer space
    /// into consideration).
    ///
    /// This is a helpful number in case some files were not allocated properly or were removed and
    /// do not correspond to allocated space in the farm info accurately.
    pub fn effective_disk_usage(
        directory: &Path,
        cache_percentage: u8,
    ) -> Result<u64, SingleDiskFarmError> {
        let mut effective_disk_usage;
        match SingleDiskFarmInfo::load_from(directory)? {
            Some(single_disk_farm_info) => {
                let allocated_space_distribution = AllocatedSpaceDistribution::new(
                    single_disk_farm_info.allocated_space(),
                    sector_size(single_disk_farm_info.pieces_in_sector()) as u64,
                    cache_percentage,
                    SectorMetadataChecksummed::encoded_size() as u64,
                )?;

                effective_disk_usage = single_disk_farm_info.allocated_space();
                effective_disk_usage -= Identity::file_size() as u64;
                effective_disk_usage -= allocated_space_distribution.metadata_file_size;
                effective_disk_usage -= allocated_space_distribution.plot_file_size;
                effective_disk_usage -= allocated_space_distribution.piece_cache_file_size;
            }
            None => {
                // No farm info, try to collect actual file sizes is any
                effective_disk_usage = 0;
            }
        };

        if Identity::open(directory)?.is_some() {
            effective_disk_usage += Identity::file_size() as u64;
        }

        match OpenOptions::new()
            .read(true)
            .open(directory.join(Self::METADATA_FILE))
        {
            Ok(metadata_file) => {
                effective_disk_usage += metadata_file.size()?;
            }
            Err(error) => {
                if error.kind() == io::ErrorKind::NotFound {
                    // File is not stored on disk
                } else {
                    return Err(error.into());
                }
            }
        };

        match OpenOptions::new()
            .read(true)
            .open(directory.join(Self::PLOT_FILE))
        {
            Ok(plot_file) => {
                effective_disk_usage += plot_file.size()?;
            }
            Err(error) => {
                if error.kind() == io::ErrorKind::NotFound {
                    // File is not stored on disk
                } else {
                    return Err(error.into());
                }
            }
        };

        match OpenOptions::new()
            .read(true)
            .open(directory.join(DiskPieceCache::FILE_NAME))
        {
            Ok(piece_cache) => {
                effective_disk_usage += piece_cache.size()?;
            }
            Err(error) => {
                if error.kind() == io::ErrorKind::NotFound {
                    // File is not stored on disk
                } else {
                    return Err(error.into());
                }
            }
        };

        Ok(effective_disk_usage)
    }

    /// Read all sectors metadata
    pub fn read_all_sectors_metadata(
        directory: &Path,
    ) -> io::Result<Vec<SectorMetadataChecksummed>> {
        let metadata_file = DirectIoFile::open(&directory.join(Self::METADATA_FILE))?;

        let metadata_size = metadata_file.size()?;
        let sector_metadata_size = SectorMetadataChecksummed::encoded_size();

        let mut metadata_header_bytes = vec![0; PlotMetadataHeader::encoded_size()];
        metadata_file.read_exact_at(&mut metadata_header_bytes, 0)?;

        let metadata_header = PlotMetadataHeader::decode(&mut metadata_header_bytes.as_ref())
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to decode metadata header: {}", error),
                )
            })?;

        if metadata_header.version != SingleDiskFarm::SUPPORTED_PLOT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unsupported metadata version {}", metadata_header.version),
            ));
        }

        let mut sectors_metadata = Vec::<SectorMetadataChecksummed>::with_capacity(
            ((metadata_size - RESERVED_PLOT_METADATA) / sector_metadata_size as u64) as usize,
        );

        let mut sector_metadata_bytes = vec![0; sector_metadata_size];
        for sector_index in 0..metadata_header.plotted_sector_count {
            metadata_file.read_exact_at(
                &mut sector_metadata_bytes,
                RESERVED_PLOT_METADATA + sector_metadata_size as u64 * u64::from(sector_index),
            )?;
            sectors_metadata.push(
                SectorMetadataChecksummed::decode(&mut sector_metadata_bytes.as_ref()).map_err(
                    |error| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("Failed to decode sector metadata: {}", error),
                        )
                    },
                )?,
            );
        }

        Ok(sectors_metadata)
    }

    /// ID of this farm
    pub fn id(&self) -> &FarmId {
        self.single_disk_farm_info.id()
    }

    /// Info of this farm
    pub fn info(&self) -> &SingleDiskFarmInfo {
        &self.single_disk_farm_info
    }

    /// Number of sectors in this farm
    pub fn total_sectors_count(&self) -> SectorIndex {
        self.total_sectors_count
    }

    /// Read information about sectors plotted so far
    pub fn plotted_sectors(&self) -> SingleDiskPlottedSectors {
        SingleDiskPlottedSectors {
            public_key: *self.single_disk_farm_info.public_key(),
            pieces_in_sector: self.pieces_in_sector,
            farmer_protocol_info: self.farmer_protocol_info,
            sectors_metadata: Arc::clone(&self.sectors_metadata),
        }
    }

    /// Get piece cache instance
    pub fn piece_cache(&self) -> SingleDiskPieceCache {
        self.piece_cache.clone()
    }

    /// Get plot cache instance
    pub fn plot_cache(&self) -> DiskPlotCache {
        self.plot_cache.clone()
    }

    /// Get piece reader to read plotted pieces later
    pub fn piece_reader(&self) -> DiskPieceReader {
        self.piece_reader.clone()
    }

    /// Subscribe to sector updates
    pub fn on_sector_update(&self, callback: HandlerFn<(SectorIndex, SectorUpdate)>) -> HandlerId {
        self.handlers.sector_update.add(callback)
    }

    /// Subscribe to farming notifications
    pub fn on_farming_notification(&self, callback: HandlerFn<FarmingNotification>) -> HandlerId {
        self.handlers.farming_notification.add(callback)
    }

    /// Subscribe to new solution notification
    pub fn on_solution(&self, callback: HandlerFn<SolutionResponse>) -> HandlerId {
        self.handlers.solution.add(callback)
    }

    /// Run and wait for background threads to exit or return an error
    pub async fn run(mut self) -> anyhow::Result<()> {
        if let Some(start_sender) = self.start_sender.take() {
            // Do not care if anyone is listening on the other side
            let _ = start_sender.send(());
        }

        while let Some(result) = self.tasks.next().instrument(self.span.clone()).await {
            result?;
        }

        Ok(())
    }

    /// Wipe everything that belongs to this single disk farm
    pub fn wipe(directory: &Path) -> io::Result<()> {
        let single_disk_info_info_path = directory.join(SingleDiskFarmInfo::FILE_NAME);
        match SingleDiskFarmInfo::load_from(directory) {
            Ok(Some(single_disk_farm_info)) => {
                info!("Found single disk farm {}", single_disk_farm_info.id());
            }
            Ok(None) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "Single disk farm info not found at {}",
                        single_disk_info_info_path.display()
                    ),
                ));
            }
            Err(error) => {
                warn!("Found unknown single disk farm: {}", error);
            }
        }

        {
            let plot = directory.join(Self::PLOT_FILE);
            if plot.exists() {
                info!("Deleting plot file at {}", plot.display());
                fs::remove_file(plot)?;
            }
        }
        {
            let metadata = directory.join(Self::METADATA_FILE);
            if metadata.exists() {
                info!("Deleting metadata file at {}", metadata.display());
                fs::remove_file(metadata)?;
            }
        }
        // TODO: Identity should be able to wipe itself instead of assuming a specific file name
        //  here
        {
            let identity = directory.join("identity.bin");
            if identity.exists() {
                info!("Deleting identity file at {}", identity.display());
                fs::remove_file(identity)?;
            }
        }

        DiskPieceCache::wipe(directory)?;

        info!(
            "Deleting info file at {}",
            single_disk_info_info_path.display()
        );
        fs::remove_file(single_disk_info_info_path)
    }

    /// Check the farm for corruption and repair errors (caused by disk errors or something else),
    /// returns an error when irrecoverable errors occur.
    pub fn scrub(
        directory: &Path,
        disable_farm_locking: bool,
        target: ScrubTarget,
        dry_run: bool,
    ) -> Result<(), SingleDiskFarmScrubError> {
        let span = Span::current();

        if dry_run {
            info!("Dry run is used, no changes will be written to disk");
        }

        if target.metadata() || target.plot() {
            let info = {
                let file = directory.join(SingleDiskFarmInfo::FILE_NAME);
                info!(path = %file.display(), "Checking info file");

                match SingleDiskFarmInfo::load_from(directory) {
                    Ok(Some(info)) => info,
                    Ok(None) => {
                        return Err(SingleDiskFarmScrubError::FarmInfoFileDoesNotExist { file });
                    }
                    Err(error) => {
                        return Err(SingleDiskFarmScrubError::FarmInfoCantBeOpened { file, error });
                    }
                }
            };

            let _single_disk_farm_info_lock = if disable_farm_locking {
                None
            } else {
                Some(
                    SingleDiskFarmInfo::try_lock(directory)
                        .map_err(SingleDiskFarmScrubError::LikelyAlreadyInUse)?,
                )
            };

            let identity = {
                let file = directory.join(Identity::FILE_NAME);
                info!(path = %file.display(), "Checking identity file");

                match Identity::open(directory) {
                    Ok(Some(identity)) => identity,
                    Ok(None) => {
                        return Err(SingleDiskFarmScrubError::IdentityFileDoesNotExist { file });
                    }
                    Err(error) => {
                        return Err(SingleDiskFarmScrubError::IdentityCantBeOpened { file, error });
                    }
                }
            };

            if PublicKey::from(identity.public.to_bytes()) != *info.public_key() {
                return Err(SingleDiskFarmScrubError::PublicKeyMismatch {
                    identity: PublicKey::from(identity.public.to_bytes()),
                    info: *info.public_key(),
                });
            }

            let sector_metadata_size = SectorMetadataChecksummed::encoded_size();

            let metadata_file_path = directory.join(Self::METADATA_FILE);
            let (metadata_file, mut metadata_header) = {
                info!(path = %metadata_file_path.display(), "Checking metadata file");

                let metadata_file = match OpenOptions::new()
                    .read(true)
                    .write(!dry_run)
                    .open(&metadata_file_path)
                {
                    Ok(metadata_file) => metadata_file,
                    Err(error) => {
                        return Err(if error.kind() == io::ErrorKind::NotFound {
                            SingleDiskFarmScrubError::MetadataFileDoesNotExist {
                                file: metadata_file_path,
                            }
                        } else {
                            SingleDiskFarmScrubError::MetadataCantBeOpened {
                                file: metadata_file_path,
                                error,
                            }
                        });
                    }
                };

                // Error doesn't matter here
                let _ = metadata_file.advise_sequential_access();

                let metadata_size = match metadata_file.size() {
                    Ok(metadata_size) => metadata_size,
                    Err(error) => {
                        return Err(SingleDiskFarmScrubError::FailedToDetermineFileSize {
                            file: metadata_file_path,
                            error,
                        });
                    }
                };

                if metadata_size < RESERVED_PLOT_METADATA {
                    return Err(SingleDiskFarmScrubError::MetadataFileTooSmall {
                        file: metadata_file_path,
                        reserved_size: RESERVED_PLOT_METADATA,
                        size: metadata_size,
                    });
                }

                let mut metadata_header = {
                    let mut reserved_metadata = vec![0; RESERVED_PLOT_METADATA as usize];

                    if let Err(error) = metadata_file.read_exact_at(&mut reserved_metadata, 0) {
                        return Err(SingleDiskFarmScrubError::FailedToReadBytes {
                            file: metadata_file_path,
                            size: RESERVED_PLOT_METADATA,
                            offset: 0,
                            error,
                        });
                    }

                    PlotMetadataHeader::decode(&mut reserved_metadata.as_slice())
                        .map_err(SingleDiskFarmScrubError::FailedToDecodeMetadataHeader)?
                };

                if metadata_header.version != SingleDiskFarm::SUPPORTED_PLOT_VERSION {
                    return Err(SingleDiskFarmScrubError::UnexpectedMetadataVersion(
                        metadata_header.version,
                    ));
                }

                let plotted_sector_count = metadata_header.plotted_sector_count;

                let expected_metadata_size = RESERVED_PLOT_METADATA
                    + sector_metadata_size as u64 * u64::from(plotted_sector_count);

                if metadata_size < expected_metadata_size {
                    warn!(
                        %metadata_size,
                        %expected_metadata_size,
                        "Metadata file size is smaller than expected, shrinking number of plotted \
                        sectors to correct value"
                    );

                    metadata_header.plotted_sector_count =
                        ((metadata_size - RESERVED_PLOT_METADATA) / sector_metadata_size as u64)
                            as SectorIndex;
                    let metadata_header_bytes = metadata_header.encode();

                    if !dry_run {
                        if let Err(error) = metadata_file.write_all_at(&metadata_header_bytes, 0) {
                            return Err(SingleDiskFarmScrubError::FailedToWriteBytes {
                                file: metadata_file_path,
                                size: metadata_header_bytes.len() as u64,
                                offset: 0,
                                error,
                            });
                        }
                    }
                }

                (metadata_file, metadata_header)
            };

            let pieces_in_sector = info.pieces_in_sector();
            let sector_size = sector_size(pieces_in_sector) as u64;

            let plot_file_path = directory.join(Self::PLOT_FILE);
            let plot_file = {
                let plot_file_path = directory.join(Self::PLOT_FILE);
                info!(path = %plot_file_path.display(), "Checking plot file");

                let plot_file = match OpenOptions::new()
                    .read(true)
                    .write(!dry_run)
                    .open(&plot_file_path)
                {
                    Ok(plot_file) => plot_file,
                    Err(error) => {
                        return Err(if error.kind() == io::ErrorKind::NotFound {
                            SingleDiskFarmScrubError::MetadataFileDoesNotExist {
                                file: plot_file_path,
                            }
                        } else {
                            SingleDiskFarmScrubError::MetadataCantBeOpened {
                                file: plot_file_path,
                                error,
                            }
                        });
                    }
                };

                // Error doesn't matter here
                let _ = plot_file.advise_sequential_access();

                let plot_size = match plot_file.size() {
                    Ok(metadata_size) => metadata_size,
                    Err(error) => {
                        return Err(SingleDiskFarmScrubError::FailedToDetermineFileSize {
                            file: plot_file_path,
                            error,
                        });
                    }
                };

                let min_expected_plot_size =
                    u64::from(metadata_header.plotted_sector_count) * sector_size;
                if plot_size < min_expected_plot_size {
                    warn!(
                        %plot_size,
                        %min_expected_plot_size,
                        "Plot file size is smaller than expected, shrinking number of plotted \
                        sectors to correct value"
                    );

                    metadata_header.plotted_sector_count = (plot_size / sector_size) as SectorIndex;
                    let metadata_header_bytes = metadata_header.encode();

                    if !dry_run {
                        if let Err(error) = metadata_file.write_all_at(&metadata_header_bytes, 0) {
                            return Err(SingleDiskFarmScrubError::FailedToWriteBytes {
                                file: plot_file_path,
                                size: metadata_header_bytes.len() as u64,
                                offset: 0,
                                error,
                            });
                        }
                    }
                }

                plot_file
            };

            let sector_bytes_range = 0..(sector_size as usize - Blake3Hash::SIZE);

            info!("Checking sectors and corresponding metadata");
            (0..metadata_header.plotted_sector_count)
                .into_par_iter()
                .map_init(
                    || vec![0u8; Record::SIZE],
                    |scratch_buffer, sector_index| {
                        let _span_guard = span.enter();

                        let offset = RESERVED_PLOT_METADATA
                            + u64::from(sector_index) * sector_metadata_size as u64;
                        if let Err(error) = metadata_file
                            .read_exact_at(&mut scratch_buffer[..sector_metadata_size], offset)
                        {
                            warn!(
                                path = %metadata_file_path.display(),
                                %error,
                                %offset,
                                size = %sector_metadata_size,
                                %sector_index,
                                "Failed to read sector metadata, replacing with dummy expired \
                                sector metadata"
                            );

                            if !dry_run {
                                write_dummy_sector_metadata(
                                    &metadata_file,
                                    &metadata_file_path,
                                    sector_index,
                                    pieces_in_sector,
                                )?;
                            }
                            return Ok(());
                        }

                        let sector_metadata = match SectorMetadataChecksummed::decode(
                            &mut &scratch_buffer[..sector_metadata_size],
                        ) {
                            Ok(sector_metadata) => sector_metadata,
                            Err(error) => {
                                warn!(
                                    path = %metadata_file_path.display(),
                                    %error,
                                    %sector_index,
                                    "Failed to decode sector metadata, replacing with dummy \
                                    expired sector metadata"
                                );

                                if !dry_run {
                                    write_dummy_sector_metadata(
                                        &metadata_file,
                                        &metadata_file_path,
                                        sector_index,
                                        pieces_in_sector,
                                    )?;
                                }
                                return Ok(());
                            }
                        };

                        if sector_metadata.sector_index != sector_index {
                            warn!(
                                path = %metadata_file_path.display(),
                                %sector_index,
                                found_sector_index = sector_metadata.sector_index,
                                "Sector index mismatch, replacing with dummy expired sector \
                                metadata"
                            );

                            if !dry_run {
                                write_dummy_sector_metadata(
                                    &metadata_file,
                                    &metadata_file_path,
                                    sector_index,
                                    pieces_in_sector,
                                )?;
                            }
                            return Ok(());
                        }

                        if sector_metadata.pieces_in_sector != pieces_in_sector {
                            warn!(
                                path = %metadata_file_path.display(),
                                %sector_index,
                                %pieces_in_sector,
                                found_pieces_in_sector = sector_metadata.pieces_in_sector,
                                "Pieces in sector mismatch, replacing with dummy expired sector \
                                metadata"
                            );

                            if !dry_run {
                                write_dummy_sector_metadata(
                                    &metadata_file,
                                    &metadata_file_path,
                                    sector_index,
                                    pieces_in_sector,
                                )?;
                            }
                            return Ok(());
                        }

                        if target.plot() {
                            let mut hasher = blake3::Hasher::new();
                            // Read sector bytes and compute checksum
                            for offset_in_sector in
                                sector_bytes_range.clone().step_by(scratch_buffer.len())
                            {
                                let offset =
                                    u64::from(sector_index) * sector_size + offset_in_sector as u64;
                                let bytes_to_read = (offset_in_sector + scratch_buffer.len())
                                    .min(sector_bytes_range.end)
                                    - offset_in_sector;

                                let bytes = &mut scratch_buffer[..bytes_to_read];

                                if let Err(error) = plot_file.read_exact_at(bytes, offset) {
                                    warn!(
                                        path = %plot_file_path.display(),
                                        %error,
                                        %sector_index,
                                        %offset,
                                        size = %bytes.len() as u64,
                                        "Failed to read sector bytes"
                                    );

                                    continue;
                                }

                                hasher.update(bytes);
                            }

                            let actual_checksum = *hasher.finalize().as_bytes();
                            let mut expected_checksum = [0; Blake3Hash::SIZE];
                            {
                                let offset = u64::from(sector_index) * sector_size
                                    + sector_bytes_range.end as u64;
                                if let Err(error) =
                                    plot_file.read_exact_at(&mut expected_checksum, offset)
                                {
                                    warn!(
                                        path = %plot_file_path.display(),
                                        %error,
                                        %sector_index,
                                        %offset,
                                        size = %expected_checksum.len() as u64,
                                        "Failed to read sector checksum bytes"
                                    );
                                }
                            }

                            // Verify checksum
                            if actual_checksum != expected_checksum {
                                warn!(
                                    path = %plot_file_path.display(),
                                    %sector_index,
                                    actual_checksum = %hex::encode(actual_checksum),
                                    expected_checksum = %hex::encode(expected_checksum),
                                    "Plotted sector checksum mismatch, replacing with dummy \
                                    expired sector"
                                );

                                if !dry_run {
                                    write_dummy_sector_metadata(
                                        &metadata_file,
                                        &metadata_file_path,
                                        sector_index,
                                        pieces_in_sector,
                                    )?;
                                }

                                scratch_buffer.fill(0);

                                hasher.reset();
                                // Fill sector with zeroes and compute checksum
                                for offset_in_sector in
                                    sector_bytes_range.clone().step_by(scratch_buffer.len())
                                {
                                    let offset = u64::from(sector_index) * sector_size
                                        + offset_in_sector as u64;
                                    let bytes_to_write = (offset_in_sector + scratch_buffer.len())
                                        .min(sector_bytes_range.end)
                                        - offset_in_sector;
                                    let bytes = &mut scratch_buffer[..bytes_to_write];

                                    if !dry_run {
                                        if let Err(error) = plot_file.write_all_at(bytes, offset) {
                                            return Err(
                                                SingleDiskFarmScrubError::FailedToWriteBytes {
                                                    file: plot_file_path.clone(),
                                                    size: scratch_buffer.len() as u64,
                                                    offset,
                                                    error,
                                                },
                                            );
                                        }
                                    }

                                    hasher.update(bytes);
                                }
                                // Write checksum
                                {
                                    let checksum = *hasher.finalize().as_bytes();
                                    let offset = u64::from(sector_index) * sector_size
                                        + sector_bytes_range.end as u64;
                                    if !dry_run {
                                        if let Err(error) =
                                            plot_file.write_all_at(&checksum, offset)
                                        {
                                            return Err(
                                                SingleDiskFarmScrubError::FailedToWriteBytes {
                                                    file: plot_file_path.clone(),
                                                    size: checksum.len() as u64,
                                                    offset,
                                                    error,
                                                },
                                            );
                                        }
                                    }
                                }

                                return Ok(());
                            }
                        }

                        trace!(%sector_index, "Sector is in good shape");

                        Ok(())
                    },
                )
                .try_for_each({
                    let span = &span;
                    let checked_sectors = AtomicUsize::new(0);

                    move |result| {
                        let _span_guard = span.enter();

                        let checked_sectors = checked_sectors.fetch_add(1, Ordering::Relaxed);
                        if checked_sectors > 1 && checked_sectors % 10 == 0 {
                            info!(
                                "Checked {}/{} sectors",
                                checked_sectors, metadata_header.plotted_sector_count
                            );
                        }

                        result
                    }
                })?;
        }

        if target.cache() {
            Self::scrub_cache(directory, dry_run)?;
        }

        info!("Farm check completed");

        Ok(())
    }

    fn scrub_cache(directory: &Path, dry_run: bool) -> Result<(), SingleDiskFarmScrubError> {
        let span = Span::current();

        let file = directory.join(DiskPieceCache::FILE_NAME);
        info!(path = %file.display(), "Checking cache file");

        let cache_file = match OpenOptions::new().read(true).write(!dry_run).open(&file) {
            Ok(plot_file) => plot_file,
            Err(error) => {
                return if error.kind() == io::ErrorKind::NotFound {
                    warn!(
                        file = %file.display(),
                        "Cache file does not exist, this is expected in farming cluster"
                    );
                    Ok(())
                } else {
                    Err(SingleDiskFarmScrubError::CacheCantBeOpened { file, error })
                };
            }
        };

        // Error doesn't matter here
        let _ = cache_file.advise_sequential_access();

        let cache_size = match cache_file.size() {
            Ok(metadata_size) => metadata_size,
            Err(error) => {
                return Err(SingleDiskFarmScrubError::FailedToDetermineFileSize { file, error });
            }
        };

        let element_size = DiskPieceCache::element_size();
        let number_of_cached_elements = cache_size / u64::from(element_size);
        let dummy_element = vec![0; element_size as usize];
        (0..number_of_cached_elements)
            .into_par_iter()
            .map_with(vec![0; element_size as usize], |element, cache_offset| {
                let _span_guard = span.enter();

                let offset = cache_offset * u64::from(element_size);
                if let Err(error) = cache_file.read_exact_at(element, offset) {
                    warn!(
                        path = %file.display(),
                        %cache_offset,
                        size = %element.len() as u64,
                        %offset,
                        %error,
                        "Failed to read cached piece, replacing with dummy element"
                    );

                    if !dry_run {
                        if let Err(error) = cache_file.write_all_at(&dummy_element, offset) {
                            return Err(SingleDiskFarmScrubError::FailedToWriteBytes {
                                file: file.clone(),
                                size: u64::from(element_size),
                                offset,
                                error,
                            });
                        }
                    }

                    return Ok(());
                }

                let (index_and_piece_bytes, expected_checksum) =
                    element.split_at(element_size as usize - Blake3Hash::SIZE);
                let actual_checksum = blake3_hash(index_and_piece_bytes);
                if *actual_checksum != *expected_checksum && element != &dummy_element {
                    warn!(
                        %cache_offset,
                        actual_checksum = %hex::encode(actual_checksum),
                        expected_checksum = %hex::encode(expected_checksum),
                        "Cached piece checksum mismatch, replacing with dummy element"
                    );

                    if !dry_run {
                        if let Err(error) = cache_file.write_all_at(&dummy_element, offset) {
                            return Err(SingleDiskFarmScrubError::FailedToWriteBytes {
                                file: file.clone(),
                                size: u64::from(element_size),
                                offset,
                                error,
                            });
                        }
                    }

                    return Ok(());
                }

                Ok(())
            })
            .try_for_each({
                let span = &span;
                let checked_elements = AtomicUsize::new(0);

                move |result| {
                    let _span_guard = span.enter();

                    let checked_elements = checked_elements.fetch_add(1, Ordering::Relaxed);
                    if checked_elements > 1 && checked_elements % 1000 == 0 {
                        info!(
                            "Checked {}/{} cache elements",
                            checked_elements, number_of_cached_elements
                        );
                    }

                    result
                }
            })?;

        Ok(())
    }
}

fn write_dummy_sector_metadata(
    metadata_file: &File,
    metadata_file_path: &Path,
    sector_index: SectorIndex,
    pieces_in_sector: u16,
) -> Result<(), SingleDiskFarmScrubError> {
    let dummy_sector_bytes = SectorMetadataChecksummed::from(SectorMetadata {
        sector_index,
        pieces_in_sector,
        s_bucket_sizes: Box::new([0; Record::NUM_S_BUCKETS]),
        history_size: HistorySize::from(SegmentIndex::ZERO),
    })
    .encode();
    let sector_offset = RESERVED_PLOT_METADATA
        + u64::from(sector_index) * SectorMetadataChecksummed::encoded_size() as u64;
    metadata_file
        .write_all_at(&dummy_sector_bytes, sector_offset)
        .map_err(|error| SingleDiskFarmScrubError::FailedToWriteBytes {
            file: metadata_file_path.to_path_buf(),
            size: dummy_sector_bytes.len() as u64,
            offset: sector_offset,
            error,
        })
}

fn faster_read_sector_record_chunks_mode<OP, FP>(
    original_plot: &OP,
    farming_plot: &FP,
    sector_size: usize,
    mut plotted_sector_count: SectorIndex,
) -> Result<ReadSectorRecordChunksMode, SingleDiskFarmError>
where
    OP: FileExt + Sync,
    FP: ReadAtSync,
{
    info!("Benchmarking faster proving method");

    let mut sector_bytes = vec![0u8; sector_size];

    if plotted_sector_count == 0 {
        thread_rng().fill_bytes(&mut sector_bytes);
        original_plot.write_all_at(&sector_bytes, 0)?;

        plotted_sector_count = 1;
    }

    let mut fastest_mode = ReadSectorRecordChunksMode::ConcurrentChunks;
    let mut fastest_time = Duration::MAX;

    for _ in 0..3 {
        let sector_offset =
            sector_size as u64 * thread_rng().gen_range(0..plotted_sector_count) as u64;
        let farming_plot = farming_plot.offset(sector_offset);

        // Reading the whole sector at once
        {
            let start = Instant::now();
            farming_plot.read_at(&mut sector_bytes, 0)?;
            let elapsed = start.elapsed();

            debug!(?elapsed, "Whole sector");

            if elapsed >= INTERNAL_BENCHMARK_READ_TIMEOUT {
                debug!(
                    ?elapsed,
                    "Reading whole sector is too slow, using chunks instead"
                );

                fastest_mode = ReadSectorRecordChunksMode::ConcurrentChunks;
                break;
            }

            if fastest_time > elapsed {
                fastest_mode = ReadSectorRecordChunksMode::WholeSector;
                fastest_time = elapsed;
            }
        }

        // A lot simplified version of concurrent chunks
        {
            let start = Instant::now();
            (0..Record::NUM_CHUNKS).into_par_iter().try_for_each(|_| {
                let offset = thread_rng().gen_range(0_usize..sector_size / Scalar::FULL_BYTES)
                    * Scalar::FULL_BYTES;
                farming_plot.read_at(&mut [0; Scalar::FULL_BYTES], offset as u64)
            })?;
            let elapsed = start.elapsed();

            debug!(?elapsed, "Chunks");

            if fastest_time > elapsed {
                fastest_mode = ReadSectorRecordChunksMode::ConcurrentChunks;
                fastest_time = elapsed;
            }
        }
    }

    info!(?fastest_mode, "Faster proving method found");

    Ok(fastest_mode)
}
