pub mod farming;
pub mod piece_cache;
pub mod piece_reader;
mod plotting;

use crate::identity::{Identity, IdentityError};
use crate::node_client::NodeClient;
use crate::reward_signing::reward_signing;
use crate::single_disk_farm::farming::rayon_files::RayonFiles;
pub use crate::single_disk_farm::farming::FarmingError;
use crate::single_disk_farm::farming::{
    farming, slot_notification_forwarder, AuditEvent, FarmingOptions, PlotAudit,
};
use crate::single_disk_farm::piece_cache::{DiskPieceCache, DiskPieceCacheError};
use crate::single_disk_farm::piece_reader::PieceReader;
pub use crate::single_disk_farm::plotting::PlottingError;
use crate::single_disk_farm::plotting::{
    plotting, plotting_scheduler, PlottingOptions, PlottingSchedulerOptions,
};
use crate::utils::{tokio_rayon_spawn_handler, AsyncJoinOnDrop};
use crate::KNOWN_PEERS_CACHE_SIZE;
use async_lock::RwLock;
use derive_more::{Display, From};
use event_listener_primitives::{Bag, HandlerId};
use futures::channel::{mpsc, oneshot};
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use static_assertions::const_assert;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{Seek, SeekFrom};
use std::num::NonZeroU8;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{fs, io, mem};
use subspace_core_primitives::crypto::blake3_hash;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    Blake3Hash, HistorySize, Piece, PieceOffset, PublicKey, Record, SectorId, SectorIndex,
    SegmentIndex,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::file_ext::{FileExt, OpenOptionsExt};
use subspace_farmer_components::plotting::{PieceGetter, PlottedSector};
use subspace_farmer_components::sector::{sector_size, SectorMetadata, SectorMetadataChecksummed};
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_networking::KnownPeersManager;
use subspace_proof_of_space::Table;
use subspace_rpc_primitives::{FarmerAppInfo, SolutionResponse};
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::sync::{broadcast, Semaphore};
use tracing::{debug, error, info, info_span, trace, warn, Instrument, Span};
use ulid::Ulid;

// Refuse to compile on non-64-bit platforms, offsets may fail on those when converting from u64 to
// usize depending on chain parameters
const_assert!(mem::size_of::<usize>() >= mem::size_of::<u64>());

/// Reserve 1M of space for plot metadata (for potential future expansion)
const RESERVED_PLOT_METADATA: u64 = 1024 * 1024;
/// Reserve 1M of space for farm info (for potential future expansion)
const RESERVED_FARM_INFO: u64 = 1024 * 1024;
const NEW_SEGMENT_PROCESSING_DELAY: Duration = Duration::from_secs(30);

/// An identifier for single disk farm, can be used for in logs, thread names, etc.
#[derive(
    Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Display, From,
)]
#[serde(untagged)]
pub enum SingleDiskFarmId {
    /// Farm ID
    Ulid(Ulid),
}

#[allow(clippy::new_without_default)]
impl SingleDiskFarmId {
    /// Creates new ID
    pub fn new() -> Self {
        Self::Ulid(Ulid::new())
    }
}

/// Exclusive lock for single disk farm info file, ensuring no concurrent edits by cooperating processes is done
#[must_use = "Lock file must be kept around or as long as farm is used"]
pub struct SingleDiskFarmInfoLock {
    _file: File,
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

    pub fn new(
        id: SingleDiskFarmId,
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
        // TODO: Remove this compatibility hack after enough time has passed
        if directory.join("single_disk_plot.json").exists() {
            fs::rename(
                directory.join("single_disk_plot.json"),
                directory.join(Self::FILE_NAME),
            )?;
        }
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

    /// Store `SingleDiskFarm` info to path so it can be loaded again upon restart.
    pub fn store_to(&self, directory: &Path) -> io::Result<()> {
        fs::write(
            directory.join(Self::FILE_NAME),
            serde_json::to_vec(self).expect("Info serialization never fails; qed"),
        )
    }

    /// Try to acquire exclusive lock on the single disk farm info file, ensuring no concurrent edits by cooperating
    /// processes is done
    pub fn try_lock(directory: &Path) -> io::Result<SingleDiskFarmInfoLock> {
        let file = File::open(directory.join(Self::FILE_NAME))?;
        fs4::FileExt::try_lock_exclusive(&file)?;

        Ok(SingleDiskFarmInfoLock { _file: file })
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

    // Public key of identity used for farm creation
    pub fn public_key(&self) -> &PublicKey {
        let Self::V0 { public_key, .. } = self;
        public_key
    }

    /// How many pieces does one sector contain.
    pub fn pieces_in_sector(&self) -> u16 {
        let Self::V0 {
            pieces_in_sector, ..
        } = self;
        *pieces_in_sector
    }

    /// How much space in bytes is allocated for this farm
    pub fn allocated_space(&self) -> u64 {
        let Self::V0 {
            allocated_space, ..
        } = self;
        *allocated_space
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
pub struct SingleDiskFarmOptions<NC, PG> {
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
    /// Piece receiver implementation for plotting purposes.
    pub piece_getter: PG,
    /// Kzg instance to use.
    pub kzg: Kzg,
    /// Erasure coding instance to use.
    pub erasure_coding: ErasureCoding,
    /// Percentage of allocated space dedicated for caching purposes
    pub cache_percentage: NonZeroU8,
    /// Semaphore for part of the plotting when farmer downloads new sector, allows to limit memory
    /// usage of the plotting process, permit will be held until the end of the plotting process
    pub downloading_semaphore: Arc<Semaphore>,
    /// Semaphore for part of the plotting when farmer encodes downloaded sector, should typically
    /// allow one permit at a time for efficient CPU utilization
    pub encoding_semaphore: Arc<Semaphore>,
    /// Whether to farm during initial plotting
    pub farm_during_initial_plotting: bool,
    /// Thread pool size used for farming (mostly for blocking I/O, but also for some
    /// compute-intensive operations during proving)
    pub farming_thread_pool_size: usize,
    /// Thread pool size used for plotting
    pub plotting_thread_pool_size: usize,
    /// Thread pool size used for replotting, typically smaller pool than for plotting to not affect
    /// farming as much
    pub replotting_thread_pool_size: usize,
    /// Notification for plotter to start, can be used to delay plotting until some initialization
    /// has happened externally
    pub plotting_delay: Option<oneshot::Receiver<()>>,
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
    // TODO: Make more variants out of this generic one
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
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
        id: SingleDiskFarmId,
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
        id: SingleDiskFarmId,
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
        id: SingleDiskFarmId,
        /// Max supported pieces in sector
        max_supported: u16,
        /// Number of pieces in sector farm is initialized with
        initialized_with: u16,
    },
    /// Failed to decode metadata header
    #[error("Failed to decode metadata header: {0}")]
    FailedToDecodeMetadataHeader(parity_scale_codec::Error),
    /// Failed to decode sector metadata
    #[error("Failed to decode sector metadata: {0}")]
    FailedToDecodeSectorMetadata(parity_scale_codec::Error),
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
        allocated_space: u64,
        allocated_sectors: u64,
        max_space: u64,
        max_sectors: u16,
    },
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
    /// Cache file does not exist
    #[error("Cache file does not exist at {file}")]
    CacheFileDoesNotExist {
        /// Cache file
        file: PathBuf,
    },
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
    BackgroundTaskPanicked { task: String },
}

type BackgroundTask = Pin<Box<dyn Future<Output = Result<(), BackgroundTaskError>> + Send>>;

type HandlerFn<A> = Arc<dyn Fn(&A) + Send + Sync + 'static>;
type Handler<A> = Bag<HandlerFn<A>, A>;

/// Details about sector currently being plotted
pub struct SectorPlottingDetails {
    /// Sector index
    pub sector_index: SectorIndex,
    /// Progress so far in % (not including this sector)
    pub progress: f32,
    /// Whether sector is being replotted
    pub replotting: bool,
    /// Whether this is the last sector queued so far
    pub last_queued: bool,
}

#[derive(Default, Debug)]
struct Handlers {
    sector_plotting: Handler<SectorPlottingDetails>,
    sector_plotted: Handler<(PlottedSector, Option<PlottedSector>)>,
    solution: Handler<SolutionResponse>,
    plot_audited: Handler<AuditEvent>,
}

/// Single disk farm abstraction is a container for everything necessary to plot/farm with a single
/// disk.
///
/// Farm starts operating during creation and doesn't stop until dropped (or error happens).
#[must_use = "Plot does not function properly unless run() method is called"]
pub struct SingleDiskFarm {
    farmer_protocol_info: FarmerProtocolInfo,
    single_disk_farm_info: SingleDiskFarmInfo,
    /// Metadata of all sectors plotted so far
    sectors_metadata: Arc<RwLock<Vec<SectorMetadataChecksummed>>>,
    pieces_in_sector: u16,
    total_sectors_count: SectorIndex,
    span: Span,
    tasks: FuturesUnordered<BackgroundTask>,
    handlers: Arc<Handlers>,
    piece_cache: DiskPieceCache,
    piece_reader: PieceReader,
    /// Sender that will be used to signal to background threads that they should start
    start_sender: Option<broadcast::Sender<()>>,
    /// Sender that will be used to signal to background threads that they must stop
    stop_sender: Option<broadcast::Sender<()>>,
    _single_disk_farm_info_lock: SingleDiskFarmInfoLock,
}

impl Drop for SingleDiskFarm {
    fn drop(&mut self) {
        self.piece_reader.close_all_readers();
        // Make background threads that are waiting to do something exit immediately
        self.start_sender.take();
        // Notify background tasks that they must stop
        self.stop_sender.take();
    }
}

impl SingleDiskFarm {
    pub const PLOT_FILE: &'static str = "plot.bin";
    pub const METADATA_FILE: &'static str = "metadata.bin";
    const SUPPORTED_PLOT_VERSION: u8 = 0;

    /// Create new single disk farm instance
    ///
    /// NOTE: Though this function is async, it will do some blocking I/O.
    pub async fn new<NC, PG, PosTable>(
        options: SingleDiskFarmOptions<NC, PG>,
        disk_farm_index: usize,
    ) -> Result<Self, SingleDiskFarmError>
    where
        NC: NodeClient,
        PG: PieceGetter + Clone + Send + Sync + 'static,
        PosTable: Table,
    {
        let SingleDiskFarmOptions {
            directory,
            farmer_app_info,
            allocated_space,
            max_pieces_in_sector,
            node_client,
            reward_address,
            piece_getter,
            kzg,
            erasure_coding,
            cache_percentage,
            downloading_semaphore,
            encoding_semaphore,
            farming_thread_pool_size,
            plotting_thread_pool_size,
            replotting_thread_pool_size,
            plotting_delay,
            farm_during_initial_plotting,
        } = options;
        fs::create_dir_all(&directory)?;

        let identity = Identity::open_or_create(&directory)?;
        let public_key = identity.public_key().to_bytes().into();

        let single_disk_farm_info = match SingleDiskFarmInfo::load_from(&directory)? {
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

                    {
                        let new_allocated_space = allocated_space;
                        let SingleDiskFarmInfo::V0 {
                            allocated_space, ..
                        } = &mut single_disk_farm_info;
                        *allocated_space = new_allocated_space;
                    }

                    single_disk_farm_info.store_to(&directory)?;
                }

                single_disk_farm_info
            }
            None => {
                let single_disk_farm_info = SingleDiskFarmInfo::new(
                    SingleDiskFarmId::new(),
                    farmer_app_info.genesis_hash,
                    public_key,
                    max_pieces_in_sector,
                    allocated_space,
                );

                single_disk_farm_info.store_to(&directory)?;

                single_disk_farm_info
            }
        };
        let farm_id = *single_disk_farm_info.id();

        let single_disk_farm_info_lock = SingleDiskFarmInfo::try_lock(&directory)
            .map_err(SingleDiskFarmError::LikelyAlreadyInUse)?;

        let pieces_in_sector = single_disk_farm_info.pieces_in_sector();
        let sector_size = sector_size(pieces_in_sector);
        let sector_metadata_size = SectorMetadataChecksummed::encoded_size();
        let single_sector_overhead = (sector_size + sector_metadata_size) as u64;
        // Fixed space usage regardless of plot size
        let fixed_space_usage = RESERVED_PLOT_METADATA
            + RESERVED_FARM_INFO
            + Identity::file_size() as u64
            + KnownPeersManager::file_size(KNOWN_PEERS_CACHE_SIZE) as u64;
        // Calculate how many sectors can fit
        let target_sector_count = {
            let potentially_plottable_space = allocated_space.saturating_sub(fixed_space_usage)
                / 100
                * (100 - u64::from(cache_percentage.get()));
            // Do the rounding to make sure we have exactly as much space as fits whole number of
            // sectors
            potentially_plottable_space / single_sector_overhead
        };

        if target_sector_count == 0 {
            let mut single_plot_with_cache_space =
                single_sector_overhead.div_ceil(100 - u64::from(cache_percentage.get())) * 100;
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

        // Remaining space will be used for caching purposes
        let cache_capacity = {
            let cache_space = allocated_space
                - fixed_space_usage
                - (target_sector_count * single_sector_overhead);
            cache_space as usize / DiskPieceCache::element_size()
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
                    allocated_space: target_sector_count * sector_size as u64,
                    allocated_sectors: target_sector_count,
                    max_space: max_sectors as u64 * sector_size as u64,
                    max_sectors,
                });
            }
        };

        let mut metadata_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .advise_random_access()
            .open(directory.join(Self::METADATA_FILE))?;

        metadata_file.advise_random_access()?;

        let metadata_size = metadata_file.seek(SeekFrom::End(0))?;
        let expected_metadata_size =
            RESERVED_PLOT_METADATA + sector_metadata_size as u64 * u64::from(target_sector_count);
        let metadata_header = if metadata_size == 0 {
            let metadata_header = PlotMetadataHeader {
                version: 0,
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

            if metadata_header.version != Self::SUPPORTED_PLOT_VERSION {
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
                metadata_file.read_exact_at(
                    &mut sector_metadata_bytes,
                    RESERVED_PLOT_METADATA + sector_metadata_size as u64 * u64::from(sector_index),
                )?;
                sectors_metadata.push(
                    SectorMetadataChecksummed::decode(&mut sector_metadata_bytes.as_ref())
                        .map_err(SingleDiskFarmError::FailedToDecodeSectorMetadata)?,
                );
            }

            Arc::new(RwLock::new(sectors_metadata))
        };

        let plot_file = Arc::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .advise_random_access()
                .open(directory.join(Self::PLOT_FILE))?,
        );

        plot_file.advise_random_access()?;

        // Allocating the whole file (`set_len` below can create a sparse file, which will cause
        // writes to fail later)
        plot_file
            .preallocate(sector_size as u64 * u64::from(target_sector_count))
            .map_err(SingleDiskFarmError::CantPreallocatePlotFile)?;
        // Truncating file (if necessary)
        plot_file.set_len(sector_size as u64 * u64::from(target_sector_count))?;

        let piece_cache = DiskPieceCache::open(&directory, cache_capacity)?;

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
        let modifying_sector_index = Arc::<RwLock<Option<SectorIndex>>>::default();
        let (sectors_to_plot_sender, sectors_to_plot_receiver) = mpsc::channel(1);
        // Some sectors may already be plotted, skip them
        let sectors_indices_left_to_plot =
            metadata_header.plotted_sector_count..target_sector_count;

        let (farming_delay_sender, delay_farmer_receiver) = if farm_during_initial_plotting {
            (None, None)
        } else {
            let (sender, receiver) = oneshot::channel();
            (Some(sender), Some(receiver))
        };

        let span = info_span!("single_disk_farm", %disk_farm_index);

        let plotting_join_handle = tokio::task::spawn_blocking({
            let sectors_metadata = Arc::clone(&sectors_metadata);
            let kzg = kzg.clone();
            let erasure_coding = erasure_coding.clone();
            let handlers = Arc::clone(&handlers);
            let modifying_sector_index = Arc::clone(&modifying_sector_index);
            let node_client = node_client.clone();
            let plot_file = Arc::clone(&plot_file);
            let error_sender = Arc::clone(&error_sender);
            let span = span.clone();

            move || {
                let _span_guard = span.enter();
                let plotting_thread_pool = match ThreadPoolBuilder::new()
                    .thread_name(move |thread_index| {
                        format!("plotting-{disk_farm_index}.{thread_index}")
                    })
                    .num_threads(plotting_thread_pool_size)
                    .spawn_handler(tokio_rayon_spawn_handler())
                    .build()
                    .map_err(PlottingError::FailedToCreateThreadPool)
                {
                    Ok(thread_pool) => thread_pool,
                    Err(error) => {
                        if let Some(error_sender) = error_sender.lock().take() {
                            if let Err(error) = error_sender.send(error.into()) {
                                error!(
                                    %error,
                                    "Plotting failed to send error to background task",
                                );
                            }
                        }
                        return;
                    }
                };
                let replotting_thread_pool = match ThreadPoolBuilder::new()
                    .thread_name(move |thread_index| {
                        format!("replotting-{disk_farm_index}.{thread_index}")
                    })
                    .num_threads(replotting_thread_pool_size)
                    .spawn_handler(tokio_rayon_spawn_handler())
                    .build()
                    .map_err(PlottingError::FailedToCreateThreadPool)
                {
                    Ok(thread_pool) => thread_pool,
                    Err(error) => {
                        if let Some(error_sender) = error_sender.lock().take() {
                            if let Err(error) = error_sender.send(error.into()) {
                                error!(
                                    %error,
                                    "Plotting failed to send error to background task",
                                );
                            }
                        }
                        return;
                    }
                };

                let plotting_options = PlottingOptions {
                    public_key,
                    node_client: &node_client,
                    pieces_in_sector,
                    sector_size,
                    sector_metadata_size,
                    metadata_header,
                    plot_file,
                    metadata_file,
                    sectors_metadata,
                    piece_getter: &piece_getter,
                    kzg: &kzg,
                    erasure_coding: &erasure_coding,
                    handlers,
                    modifying_sector_index,
                    sectors_to_plot_receiver,
                    downloading_semaphore,
                    encoding_semaphore: &encoding_semaphore,
                    plotting_thread_pool,
                    replotting_thread_pool,
                    stop_receiver: &mut stop_receiver.resubscribe(),
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

                    plotting::<_, _, PosTable>(plotting_options).await
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
                    task: format!("plotting-{disk_farm_index}"),
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
            sectors_metadata: Arc::clone(&sectors_metadata),
            sectors_to_plot_sender,
            initial_plotting_finished: farming_delay_sender,
            new_segment_processing_delay: NEW_SEGMENT_PROCESSING_DELAY,
        };
        tasks.push(Box::pin(plotting_scheduler(plotting_scheduler_options)));

        let (slot_info_forwarder_sender, slot_info_forwarder_receiver) = mpsc::channel(0);

        tasks.push(Box::pin({
            let node_client = node_client.clone();

            async move {
                slot_notification_forwarder(&node_client, slot_info_forwarder_sender)
                    .await
                    .map_err(BackgroundTaskError::Farming)
            }
        }));

        let farming_join_handle = tokio::task::spawn_blocking({
            let erasure_coding = erasure_coding.clone();
            let handlers = Arc::clone(&handlers);
            let modifying_sector_index = Arc::clone(&modifying_sector_index);
            let sectors_metadata = Arc::clone(&sectors_metadata);
            let mut start_receiver = start_sender.subscribe();
            let mut stop_receiver = stop_sender.subscribe();
            let node_client = node_client.clone();
            let span = span.clone();

            move || {
                let _span_guard = span.enter();
                let thread_pool = match ThreadPoolBuilder::new()
                    .thread_name(move |thread_index| {
                        format!("farming-{disk_farm_index}.{thread_index}")
                    })
                    .num_threads(farming_thread_pool_size)
                    .spawn_handler(tokio_rayon_spawn_handler())
                    .build()
                    .map_err(FarmingError::FailedToCreateThreadPool)
                {
                    Ok(thread_pool) => thread_pool,
                    Err(error) => {
                        if let Some(error_sender) = error_sender.lock().take() {
                            if let Err(error) = error_sender.send(error.into()) {
                                error!(
                                    %error,
                                    "Farming failed to send error to background task",
                                );
                            }
                        }
                        return;
                    }
                };

                let handle = Handle::current();
                let span = span.clone();
                thread_pool.install(move || {
                    let _span_guard = span.enter();

                    let farming_fut = async move {
                        if start_receiver.recv().await.is_err() {
                            // Dropped before starting
                            return Ok(());
                        }

                        if let Some(farming_delay) = delay_farmer_receiver {
                            if farming_delay.await.is_err() {
                                // Dropped before resolving
                                return Ok(());
                            }
                        }

                        let plot = RayonFiles::open(&directory.join(Self::PLOT_FILE))?;
                        let plot_audit = PlotAudit::new(&plot);

                        let farming_options = FarmingOptions {
                            public_key,
                            reward_address,
                            node_client,
                            plot_audit,
                            sectors_metadata,
                            kzg,
                            erasure_coding,
                            handlers,
                            modifying_sector_index,
                            slot_info_notifications: slot_info_forwarder_receiver,
                            farm_id,
                        };
                        farming::<PosTable, _, _>(farming_options).await
                    };

                    handle.block_on(async {
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
                })
            }
        });
        let farming_join_handle = AsyncJoinOnDrop::new(farming_join_handle, false);

        tasks.push(Box::pin(async move {
            // Panic will already be printed by now
            farming_join_handle.await.map_err(|_error| {
                BackgroundTaskError::BackgroundTaskPanicked {
                    task: format!("farming-{disk_farm_index}"),
                }
            })
        }));

        let (piece_reader, reading_fut) = PieceReader::new::<PosTable>(
            public_key,
            pieces_in_sector,
            plot_file,
            Arc::clone(&sectors_metadata),
            erasure_coding,
            modifying_sector_index,
        );

        let reading_join_handle = tokio::task::spawn_blocking({
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
                    task: format!("reading-{disk_farm_index}"),
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
            piece_reader,
            start_sender: Some(start_sender),
            stop_sender: Some(stop_sender),
            _single_disk_farm_info_lock: single_disk_farm_info_lock,
        };

        Ok(farm)
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

    /// Read all sectors metadata
    pub fn read_all_sectors_metadata(
        directory: &Path,
    ) -> io::Result<Vec<SectorMetadataChecksummed>> {
        let mut metadata_file = OpenOptions::new()
            .read(true)
            .open(directory.join(Self::METADATA_FILE))?;

        let metadata_size = metadata_file.seek(SeekFrom::End(0))?;
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
    pub fn id(&self) -> &SingleDiskFarmId {
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

    /// Number of sectors successfully plotted so far
    pub async fn plotted_sectors_count(&self) -> usize {
        self.sectors_metadata.read().await.len()
    }

    /// Read information about sectors plotted so far
    pub async fn plotted_sectors(
        &self,
    ) -> impl Iterator<Item = Result<PlottedSector, parity_scale_codec::Error>> + '_ {
        let public_key = self.single_disk_farm_info.public_key();
        let sectors_metadata = self.sectors_metadata.read().await.clone();

        (0..)
            .zip(sectors_metadata)
            .map(move |(sector_index, sector_metadata)| {
                let sector_id = SectorId::new(public_key.hash(), sector_index);

                let mut piece_indexes = Vec::with_capacity(usize::from(self.pieces_in_sector));
                (PieceOffset::ZERO..)
                    .take(usize::from(self.pieces_in_sector))
                    .map(|piece_offset| {
                        sector_id.derive_piece_index(
                            piece_offset,
                            sector_metadata.history_size,
                            self.farmer_protocol_info.max_pieces_in_sector,
                            self.farmer_protocol_info.recent_segments,
                            self.farmer_protocol_info.recent_history_fraction,
                        )
                    })
                    .collect_into(&mut piece_indexes);

                Ok(PlottedSector {
                    sector_id,
                    sector_index,
                    sector_metadata,
                    piece_indexes,
                })
            })
    }

    /// Get piece cache instance
    pub fn piece_cache(&self) -> DiskPieceCache {
        self.piece_cache.clone()
    }

    /// Get piece reader to read plotted pieces later
    pub fn piece_reader(&self) -> PieceReader {
        self.piece_reader.clone()
    }

    /// Subscribe to sector plotting notification
    pub fn on_sector_plotting(&self, callback: HandlerFn<SectorPlottingDetails>) -> HandlerId {
        self.handlers.sector_plotting.add(callback)
    }

    /// Subscribe to notification about plotted sectors
    pub fn on_sector_plotted(
        &self,
        callback: HandlerFn<(PlottedSector, Option<PlottedSector>)>,
    ) -> HandlerId {
        self.handlers.sector_plotted.add(callback)
    }

    /// Subscribe to notification about audited plots
    pub fn on_plot_audited(&self, callback: HandlerFn<AuditEvent>) -> HandlerId {
        self.handlers.plot_audited.add(callback)
    }

    /// Subscribe to new solution notification
    pub fn on_solution(&self, callback: HandlerFn<SolutionResponse>) -> HandlerId {
        self.handlers.solution.add(callback)
    }

    /// Run and wait for background threads to exit or return an error
    pub async fn run(mut self) -> anyhow::Result<SingleDiskFarmId> {
        if let Some(start_sender) = self.start_sender.take() {
            // Do not care if anyone is listening on the other side
            let _ = start_sender.send(());
        }

        while let Some(result) = self.tasks.next().instrument(self.span.clone()).await {
            result?;
        }

        Ok(*self.id())
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

        // TODO: Remove this compatibility hack after enough time has passed
        if directory.join("single_disk_plot.json").exists() {
            info!(
                "Deleting info file at {}",
                directory.join("single_disk_plot.json").display()
            );
            fs::remove_file(directory.join("single_disk_plot.json"))
        } else {
            info!(
                "Deleting info file at {}",
                single_disk_info_info_path.display()
            );
            fs::remove_file(single_disk_info_info_path)
        }
    }

    /// Check the farm for corruption and repair errors (caused by disk errors or something else),
    /// returns an error when irrecoverable errors occur.
    pub fn scrub(directory: &Path) -> Result<(), SingleDiskFarmScrubError> {
        let span = Span::current();

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

        let _single_disk_farm_info_lock = SingleDiskFarmInfo::try_lock(directory)
            .map_err(SingleDiskFarmScrubError::LikelyAlreadyInUse)?;

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

            let mut metadata_file = match OpenOptions::new()
                .read(true)
                .write(true)
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

            let metadata_size = match metadata_file.seek(SeekFrom::End(0)) {
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

            if metadata_header.version != Self::SUPPORTED_PLOT_VERSION {
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

                metadata_header.plotted_sector_count = ((metadata_size - RESERVED_PLOT_METADATA)
                    / sector_metadata_size as u64)
                    as SectorIndex;
                let metadata_header_bytes = metadata_header.encode();
                if let Err(error) = metadata_file.write_all_at(&metadata_header_bytes, 0) {
                    return Err(SingleDiskFarmScrubError::FailedToWriteBytes {
                        file: metadata_file_path,
                        size: metadata_header_bytes.len() as u64,
                        offset: 0,
                        error,
                    });
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

            let mut plot_file = match OpenOptions::new()
                .read(true)
                .write(true)
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

            let plot_size = match plot_file.seek(SeekFrom::End(0)) {
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
                if let Err(error) = metadata_file.write_all_at(&metadata_header_bytes, 0) {
                    return Err(SingleDiskFarmScrubError::FailedToWriteBytes {
                        file: plot_file_path,
                        size: metadata_header_bytes.len() as u64,
                        offset: 0,
                        error,
                    });
                }
            }

            plot_file
        };

        info!("Checking sectors and corresponding metadata");
        (0..metadata_header.plotted_sector_count)
            .into_par_iter()
            .map_init(
                || {
                    let sector_metadata_bytes = vec![0; sector_metadata_size];
                    let piece = Piece::default();

                    (sector_metadata_bytes, piece)
                },
                |(sector_metadata_bytes, piece), sector_index| {
                    let _span_guard = span.enter();

                    let offset = RESERVED_PLOT_METADATA
                        + u64::from(sector_index) * sector_metadata_size as u64;
                    if let Err(error) = metadata_file.read_exact_at(sector_metadata_bytes, offset) {
                        warn!(
                            path = %metadata_file_path.display(),
                            %error,
                            %sector_index,
                            %offset,
                            "Failed to read sector metadata, replacing with dummy expired sector \
                            metadata"
                        );

                        write_dummy_sector_metadata(
                            &metadata_file,
                            &metadata_file_path,
                            sector_index,
                            pieces_in_sector,
                        )?;
                        return Ok(());
                    }

                    let sector_metadata = match SectorMetadataChecksummed::decode(
                        &mut sector_metadata_bytes.as_slice(),
                    ) {
                        Ok(sector_metadata) => sector_metadata,
                        Err(error) => {
                            warn!(
                                path = %metadata_file_path.display(),
                                %error,
                                %sector_index,
                                "Failed to decode sector metadata, replacing with dummy expired \
                                sector metadata"
                            );

                            write_dummy_sector_metadata(
                                &metadata_file,
                                &metadata_file_path,
                                sector_index,
                                pieces_in_sector,
                            )?;
                            return Ok(());
                        }
                    };

                    if sector_metadata.sector_index != sector_index {
                        warn!(
                            path = %metadata_file_path.display(),
                            %sector_index,
                            found_sector_index = sector_metadata.sector_index,
                            "Sector index mismatch, replacing with dummy expired sector metadata"
                        );

                        write_dummy_sector_metadata(
                            &metadata_file,
                            &metadata_file_path,
                            sector_index,
                            pieces_in_sector,
                        )?;
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

                        write_dummy_sector_metadata(
                            &metadata_file,
                            &metadata_file_path,
                            sector_index,
                            pieces_in_sector,
                        )?;
                        return Ok(());
                    }

                    let mut hasher = blake3::Hasher::new();
                    for piece_offset in 0..pieces_in_sector {
                        let offset = u64::from(sector_index) * sector_size
                            + u64::from(piece_offset) * Piece::SIZE as u64;

                        if let Err(error) = plot_file.read_exact_at(piece.as_mut(), offset) {
                            warn!(
                                path = %plot_file_path.display(),
                                %error,
                                %sector_index,
                                %piece_offset,
                                size = %piece.len() as u64,
                                %offset,
                                "Failed to read piece bytes"
                            );
                            return Err(SingleDiskFarmScrubError::FailedToReadBytes {
                                file: plot_file_path.clone(),
                                size: piece.len() as u64,
                                offset,
                                error,
                            });
                        }

                        hasher.update(piece.as_ref());
                    }

                    let actual_checksum = *hasher.finalize().as_bytes();
                    let mut expected_checksum = [0; mem::size_of::<Blake3Hash>()];
                    {
                        let offset = u64::from(sector_index) * sector_size
                            + u64::from(pieces_in_sector) * Piece::SIZE as u64;
                        if let Err(error) = plot_file.read_exact_at(&mut expected_checksum, offset)
                        {
                            return Err(SingleDiskFarmScrubError::FailedToReadBytes {
                                file: plot_file_path.clone(),
                                size: expected_checksum.len() as u64,
                                offset,
                                error,
                            });
                        }
                    }

                    // Verify checksum
                    if actual_checksum != expected_checksum {
                        debug!(
                            path = %plot_file_path.display(),
                            %sector_index,
                            actual_checksum = %hex::encode(actual_checksum),
                            expected_checksum = %hex::encode(expected_checksum),
                            "Plotted sector checksum mismatch, replacing with dummy expired sector"
                        );

                        write_dummy_sector_metadata(
                            &metadata_file,
                            &metadata_file_path,
                            sector_index,
                            pieces_in_sector,
                        )?;

                        *piece = Piece::default();

                        // Write dummy pieces
                        let mut hasher = blake3::Hasher::new();
                        for piece_offset in 0..pieces_in_sector {
                            let offset = u64::from(sector_index) * sector_size
                                + u64::from(piece_offset) * Piece::SIZE as u64;

                            if let Err(error) = plot_file.write_all_at(piece.as_ref(), offset) {
                                return Err(SingleDiskFarmScrubError::FailedToWriteBytes {
                                    file: plot_file_path.clone(),
                                    size: piece.len() as u64,
                                    offset,
                                    error,
                                });
                            }

                            hasher.update(piece.as_ref());
                        }

                        let offset = u64::from(sector_index) * sector_size
                            + u64::from(pieces_in_sector) * Piece::SIZE as u64;

                        // Write checksum
                        if let Err(error) =
                            plot_file.write_all_at(hasher.finalize().as_bytes(), offset)
                        {
                            return Err(SingleDiskFarmScrubError::FailedToWriteBytes {
                                file: plot_file_path.clone(),
                                size: hasher.finalize().as_bytes().len() as u64,
                                offset,
                                error,
                            });
                        }

                        return Ok(());
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

        {
            let file = directory.join(DiskPieceCache::FILE_NAME);
            info!(path = %file.display(), "Checking cache file");

            let mut cache_file = match OpenOptions::new().read(true).write(true).open(&file) {
                Ok(plot_file) => plot_file,
                Err(error) => {
                    return Err(if error.kind() == io::ErrorKind::NotFound {
                        SingleDiskFarmScrubError::CacheFileDoesNotExist { file }
                    } else {
                        SingleDiskFarmScrubError::CacheCantBeOpened { file, error }
                    });
                }
            };

            // Error doesn't matter here
            let _ = cache_file.advise_sequential_access();

            let cache_size = match cache_file.seek(SeekFrom::End(0)) {
                Ok(metadata_size) => metadata_size,
                Err(error) => {
                    return Err(SingleDiskFarmScrubError::FailedToDetermineFileSize {
                        file,
                        error,
                    });
                }
            };

            let element_size = DiskPieceCache::element_size();
            let number_of_cached_elements = cache_size / element_size as u64;
            let dummy_element = vec![0; element_size];
            (0..number_of_cached_elements)
                .into_par_iter()
                .map_with(vec![0; element_size], |element, cache_offset| {
                    let _span_guard = span.enter();

                    let offset = cache_offset * element_size as u64;
                    if let Err(error) = cache_file.read_exact_at(element, offset) {
                        warn!(
                            path = %file.display(),
                            %cache_offset,
                            size = %element.len() as u64,
                            %offset,
                            %error,
                            "Failed to read cached piece, replacing with dummy element"
                        );

                        if let Err(error) = cache_file.write_all_at(&dummy_element, offset) {
                            return Err(SingleDiskFarmScrubError::FailedToWriteBytes {
                                file: file.clone(),
                                size: element_size as u64,
                                offset,
                                error,
                            });
                        }

                        return Ok(());
                    }

                    let (index_and_piece_bytes, expected_checksum) =
                        element.split_at(element_size - mem::size_of::<Blake3Hash>());
                    let actual_checksum = blake3_hash(index_and_piece_bytes);
                    if actual_checksum != expected_checksum && element != &dummy_element {
                        warn!(
                            %cache_offset,
                            actual_checksum = %hex::encode(actual_checksum),
                            expected_checksum = %hex::encode(expected_checksum),
                            "Cached piece checksum mismatch, replacing with dummy element"
                        );

                        if let Err(error) = cache_file.write_all_at(&dummy_element, offset) {
                            return Err(SingleDiskFarmScrubError::FailedToWriteBytes {
                                file: file.clone(),
                                size: element_size as u64,
                                offset,
                                error,
                            });
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
        }

        info!("Farm check completed");

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
