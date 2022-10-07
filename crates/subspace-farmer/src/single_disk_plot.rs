use crate::file_ext::FileExt;
use crate::identity::Identity;
use crate::reward_signing::reward_signing;
use crate::rpc_client;
use crate::rpc_client::RpcClient;
use crate::single_disk_farm::SingleDiskSemaphore;
use crate::utils::JoinOnDrop;
use bitvec::prelude::*;
use bytesize::ByteSize;
use derive_more::{Display, From};
use futures::channel::oneshot;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use memmap2::{MmapMut, MmapOptions};
use parity_db::const_assert;
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::future::Future;
use std::io::{Seek, SeekFrom};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use std::{fs, io, thread};
use subspace_core_primitives::crypto::blake2b_256_254_hash;
use subspace_core_primitives::crypto::kzg::Witness;
use subspace_core_primitives::{
    plot_sector_size, Chunk, Piece, PieceIndex, PublicKey, SectorId, SegmentIndex, Solution,
    PIECE_SIZE,
};
use subspace_rpc_primitives::SolutionResponse;
use subspace_solving::{derive_chunk_otp, SubspaceCodec};
use subspace_verification::is_within_solution_range2;
use thiserror::Error;
use tokio::runtime::Handle;
use tracing::{debug, error, info, info_span, trace, Instrument, Span};
use ulid::Ulid;

// Refuse to compile on non-64-bit platforms, offsets may fail on those when converting from u64 to
// usize depending on chain parameters
const_assert!(std::mem::size_of::<usize>() >= std::mem::size_of::<u64>());

/// Reserve 1M of space for plot metadata (for potential future expansion)
const RESERVED_PLOT_METADATA: u64 = 1024 * 1024;

/// An identifier for single disk plot, can be used for in logs, thread names, etc.
#[derive(
    Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Display, From,
)]
#[serde(untagged)]
pub enum SingleDiskPlotId {
    /// Plot ID
    Ulid(Ulid),
}

#[allow(clippy::new_without_default)]
impl SingleDiskPlotId {
    /// Creates new ID
    pub fn new() -> Self {
        Self::Ulid(Ulid::new())
    }
}

/// Important information about the contents of the `SingleDiskPlot`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SingleDiskPlotInfo {
    /// V0 of the info
    #[serde(rename_all = "camelCase")]
    V0 {
        /// ID of the plot
        id: SingleDiskPlotId,
        /// Genesis hash of the chain used for plot creation
        #[serde(with = "hex::serde")]
        genesis_hash: [u8; 32],
        /// Public key of identity used for plot creation
        public_key: PublicKey,
        /// First sector index in this plot
        ///
        /// Multiple plots can reuse the same identity, but they have to use different ranges for
        /// sector indexes or else they'll essentially plot the same data and will not result in
        /// increased probability of winning the reward.
        first_sector_index: u64,
        /// How much space in bytes is allocated for this plot
        allocated_space: u64,
    },
}

impl SingleDiskPlotInfo {
    const FILE_NAME: &'static str = "single_disk_plot.json";

    pub fn new(
        id: SingleDiskPlotId,
        genesis_hash: [u8; 32],
        public_key: PublicKey,
        first_sector_index: u64,
        allocated_space: u64,
    ) -> Self {
        Self::V0 {
            id,
            genesis_hash,
            public_key,
            first_sector_index,
            allocated_space,
        }
    }

    /// Load `SingleDiskPlot` from path is supposed to be stored, `None` means no info file was
    /// found, happens during first start.
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

    /// Store `SingleDiskPlot` info to path so it can be loaded again upon restart.
    pub fn store_to(&self, directory: &Path) -> io::Result<()> {
        fs::write(
            directory.join(Self::FILE_NAME),
            serde_json::to_vec(self).expect("Info serialization never fails; qed"),
        )
    }

    // ID of the plot
    pub fn id(&self) -> &SingleDiskPlotId {
        let Self::V0 { id, .. } = self;
        id
    }

    // Genesis hash of the chain used for plot creation
    pub fn genesis_hash(&self) -> &[u8; 32] {
        let Self::V0 { genesis_hash, .. } = self;
        genesis_hash
    }

    // Public key of identity used for plot creation
    pub fn public_key(&self) -> &PublicKey {
        let Self::V0 { public_key, .. } = self;
        public_key
    }

    /// First sector index in this plot
    ///
    /// Multiple plots can reuse the same identity, but they have to use different ranges for
    /// sector indexes or else they'll essentially plot the same data and will not result in
    /// increased probability of winning the reward.
    pub fn first_sector_index(&self) -> u64 {
        let Self::V0 {
            first_sector_index, ..
        } = self;
        *first_sector_index
    }

    /// How much space in bytes is allocated for this plot
    pub fn allocated_space(&self) -> u64 {
        let Self::V0 {
            allocated_space, ..
        } = self;
        *allocated_space
    }
}

/// Summary of single disk plot for presentational purposes
pub enum SingleDiskPlotSummary {
    /// Plot was found and read successfully
    Found {
        /// Plot info
        info: SingleDiskPlotInfo,
        /// Path to directory where plot is stored.
        directory: PathBuf,
    },
    /// Plot was not found
    NotFound {
        /// Path to directory where plot is stored.
        directory: PathBuf,
    },
    /// Failed to open plot
    Error {
        /// Path to directory where plot is stored.
        directory: PathBuf,
        /// Error itself
        error: io::Error,
    },
}

#[derive(Debug, Encode, Decode)]
struct PlotMetadataHeader {
    version: u8,
    sector_count: u64,
}

impl PlotMetadataHeader {
    fn encoded_size() -> usize {
        let default = PlotMetadataHeader {
            version: 0,
            sector_count: 0,
        };

        default.encoded_size()
    }
}

#[derive(Debug, Encode, Decode)]
struct SectorMetadata {
    total_pieces: PieceIndex,
    expires_at: SegmentIndex,
}

impl SectorMetadata {
    fn encoded_size() -> usize {
        let default = SectorMetadata {
            total_pieces: 0,
            expires_at: 0,
        };

        default.encoded_size()
    }
}

/// Options used to open single dis plot
pub struct SingleDiskPlotOptions<RC> {
    /// Path to directory where plot are stored.
    pub directory: PathBuf,
    /// How much space in bytes can plot use for plot
    pub allocated_space: u64,
    /// RPC client connected to Subspace node
    pub rpc_client: RC,
    /// Address where farming rewards should go
    pub reward_address: PublicKey,
}

/// Errors happening when trying to create/open single disk plot
#[derive(Debug, Error)]
pub enum SingleDiskPlotError {
    // TODO: Make more variants out of this generic one
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Can't resize plot after creation
    #[error(
        "Usable plotting space of plot {id} {new_space} is different from {old_space} when plot was \
        created, resizing isn't supported yet"
    )]
    CantResize {
        /// Plot ID
        id: SingleDiskPlotId,
        /// Space allocated during plot creation
        old_space: ByteSize,
        /// New desired plot size
        new_space: ByteSize,
    },
    /// Wrong chain (genesis hash)
    #[error(
        "Genesis hash of plot {id} {wrong_chain} is different from {correct_chain} when plot was \
        created, it is not possible to use plot on a different chain"
    )]
    WrongChain {
        /// Plot ID
        id: SingleDiskPlotId,
        /// Hex-encoded genesis hash during plot creation
        // TODO: Wrapper type with `Display` impl for genesis hash
        correct_chain: String,
        /// Hex-encoded current genesis hash
        wrong_chain: String,
    },
    /// Public key in identity doesn't match metadata
    #[error(
        "Public key of plot {id} {wrong_public_key} is different from {correct_public_key} when \
        plot was created, something went wrong, likely due to manual edits"
    )]
    IdentityMismatch {
        /// Plot ID
        id: SingleDiskPlotId,
        /// Public key used during plot creation
        correct_public_key: PublicKey,
        /// Current public key
        wrong_public_key: PublicKey,
    },
    /// Failed to decode metadata header
    #[error("Failed to decode metadata header: {0}")]
    FailedToDecodeMetadataHeader(parity_scale_codec::Error),
    /// Unexpected metadata version
    #[error("Unexpected metadata version {0}")]
    UnexpectedMetadataVersion(u8),
    /// Node RPC error
    #[error("Node RPC error: {0}")]
    NodeRpcError(Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Errors that happen during plotting
#[derive(Debug, Error)]
pub enum PlottingError {
    /// Failed to retriever farmer protocol info
    #[error("Failed to retriever farmer protocol info: {error}")]
    FailedToGetFarmerProtocolInfo {
        /// Lower-level error
        error: rpc_client::Error,
    },
    /// Piece not found, can't create sector, this should never happen
    #[error("Piece {piece_index} not found, can't create sector, this should never happen")]
    PieceNotFound {
        /// Piece index
        piece_index: PieceIndex,
    },
    /// Failed to retrieve piece
    #[error("Failed to retrieve piece {piece_index}: {error}")]
    FailedToRetrievePiece {
        /// Piece index
        piece_index: PieceIndex,
        /// Lower-level error
        error: rpc_client::Error,
    },
}

/// Errors that happen during farming
#[derive(Debug, Error)]
pub enum FarmingError {
    /// Failed to retriever farmer protocol info
    #[error("Failed to retriever farmer protocol info: {error}")]
    FailedToGetFarmerProtocolInfo {
        /// Lower-level error
        error: rpc_client::Error,
    },
    /// Failed to create memory mapping for plot
    #[error("Failed to create memory mapping for plot: {error}")]
    FailedToMapPlot {
        /// Lower-level error
        error: io::Error,
    },
    /// Failed to create memory mapping for metadata
    #[error("Failed to create memory mapping for metadata: {error}")]
    FailedToMapMetadata {
        /// Lower-level error
        error: io::Error,
    },
    /// Failed to decode sector metadata
    #[error("Failed to decode sector metadata: {error}")]
    FailedToDecodeMetadata {
        /// Lower-level error
        error: parity_scale_codec::Error,
    },
    /// Failed to submit solutions response
    #[error("Failed to submit solutions response: {error}")]
    FailedToSubmitSolutionsResponse {
        /// Lower-level error
        error: rpc_client::Error,
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
}

type BackgroundTask = Pin<Box<dyn Future<Output = Result<(), BackgroundTaskError>> + Send>>;

/// Single disk plot abstraction is a container for everything necessary to plot/farm with a single
/// disk plot.
///
/// Plot starts operating during creation and doesn't stop until dropped (or error happens).
#[must_use = "Plot does not function properly unless run() method is called"]
pub struct SingleDiskPlot {
    id: SingleDiskPlotId,
    span: Span,
    tasks: FuturesUnordered<BackgroundTask>,
    _plotting_join_handle: JoinOnDrop,
    _farming_join_handle: JoinOnDrop,
    shutting_down: Arc<AtomicBool>,
}

impl Drop for SingleDiskPlot {
    fn drop(&mut self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }
}

impl SingleDiskPlot {
    const PLOT_FILE: &'static str = "plot.bin";
    const METADATA_FILE: &'static str = "metadata.bin";

    /// Create new single disk plot instance
    pub fn new<RC>(options: SingleDiskPlotOptions<RC>) -> Result<Self, SingleDiskPlotError>
    where
        RC: RpcClient,
    {
        let handle = Handle::current();

        let SingleDiskPlotOptions {
            directory,
            allocated_space,
            rpc_client,
            reward_address,
        } = options;

        fs::create_dir_all(&directory)?;

        // TODO: Parametrize concurrency, much higher default due to SSD focus
        // TODO: Use this or remove
        let _single_disk_semaphore =
            SingleDiskSemaphore::new(NonZeroU16::new(10).expect("Not a zero; qed"));

        // TODO: Update `Identity` to use more specific error type and remove this `.unwrap()`
        let identity = Identity::open_or_create(&directory).unwrap();
        let public_key = identity.public_key().to_bytes().into();

        let farmer_protocol_info = tokio::task::block_in_place(|| {
            Handle::current()
                .block_on(rpc_client.farmer_protocol_info())
                .map_err(SingleDiskPlotError::NodeRpcError)
        })?;
        // TODO: In case `space_l` changes on the fly, code below will break horribly
        let space_l = farmer_protocol_info.space_l;
        let plot_sector_size = plot_sector_size(space_l);

        assert_eq!(
            plot_sector_size % PIECE_SIZE as u64,
            0,
            "Sector size must be multiple of piece size"
        );

        let single_disk_plot_info = match SingleDiskPlotInfo::load_from(&directory)? {
            Some(single_disk_plot_info) => {
                if allocated_space != single_disk_plot_info.allocated_space() {
                    return Err(SingleDiskPlotError::CantResize {
                        id: *single_disk_plot_info.id(),
                        old_space: ByteSize::b(single_disk_plot_info.allocated_space()),
                        new_space: ByteSize::b(allocated_space),
                    });
                }

                if &farmer_protocol_info.genesis_hash != single_disk_plot_info.genesis_hash() {
                    return Err(SingleDiskPlotError::WrongChain {
                        id: *single_disk_plot_info.id(),
                        correct_chain: hex::encode(single_disk_plot_info.genesis_hash()),
                        wrong_chain: hex::encode(farmer_protocol_info.genesis_hash),
                    });
                }

                if &public_key != single_disk_plot_info.public_key() {
                    return Err(SingleDiskPlotError::IdentityMismatch {
                        id: *single_disk_plot_info.id(),
                        correct_public_key: *single_disk_plot_info.public_key(),
                        wrong_public_key: public_key,
                    });
                }

                single_disk_plot_info
            }
            None => {
                // TODO: Global generator that makes sure to avoid returning the same sector index
                //  for multiple disks
                let first_sector_index = SystemTime::UNIX_EPOCH
                    .elapsed()
                    .expect("Unix epoch is always in the past; qed")
                    .as_secs()
                    .wrapping_mul(u64::from(u32::MAX));

                let single_disk_plot_info = SingleDiskPlotInfo::new(
                    SingleDiskPlotId::new(),
                    farmer_protocol_info.genesis_hash,
                    public_key,
                    first_sector_index,
                    allocated_space,
                );

                single_disk_plot_info.store_to(&directory)?;

                single_disk_plot_info
            }
        };

        let single_disk_plot_id = *single_disk_plot_info.id();
        let first_sector_index = single_disk_plot_info.first_sector_index();

        // TODO: Account for plot overhead
        let target_sector_count = allocated_space / plot_sector_size;

        // TODO: Consider file locking to prevent other apps from modifying it
        let mut metadata_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(directory.join(Self::METADATA_FILE))?;

        let (metadata_header, mut metadata_header_mmap) = if metadata_file.seek(SeekFrom::End(0))?
            == 0
        {
            let metadata_header = PlotMetadataHeader {
                version: 0,
                sector_count: 0,
            };

            metadata_file.preallocate(
                RESERVED_PLOT_METADATA
                    + SectorMetadata::encoded_size() as u64 * target_sector_count,
            )?;
            metadata_file.write_all_at(metadata_header.encode().as_slice(), 0)?;

            let metadata_header_mmap = unsafe {
                MmapOptions::new()
                    .len(PlotMetadataHeader::encoded_size())
                    .map_mut(&metadata_file)?
            };

            (metadata_header, metadata_header_mmap)
        } else {
            let metadata_header_mmap = unsafe {
                MmapOptions::new()
                    .len(PlotMetadataHeader::encoded_size())
                    .map_mut(&metadata_file)?
            };

            let metadata_header = PlotMetadataHeader::decode(&mut metadata_header_mmap.as_ref())
                .map_err(SingleDiskPlotError::FailedToDecodeMetadataHeader)?;

            if metadata_header.version != 0 {
                return Err(SingleDiskPlotError::UnexpectedMetadataVersion(
                    metadata_header.version,
                ));
            }

            (metadata_header, metadata_header_mmap)
        };

        metadata_file.advise_random_access()?;

        let metadata_header = Arc::new(Mutex::new(metadata_header));

        let mut metadata_mmap_mut = unsafe {
            MmapOptions::new()
                .offset(RESERVED_PLOT_METADATA)
                .len(SectorMetadata::encoded_size() * target_sector_count as usize)
                .map_mut(&metadata_file)?
        };

        let plot_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(directory.join(Self::PLOT_FILE))?;

        plot_file.preallocate(plot_sector_size * target_sector_count)?;
        plot_file.advise_random_access()?;

        let mut plot_mmap_mut = unsafe { MmapMut::map_mut(&plot_file)? };

        // TODO: Use this or remove
        let _codec = SubspaceCodec::new_with_gpu(public_key.as_ref());

        let (error_sender, error_receiver) = oneshot::channel();
        let error_sender = Arc::new(Mutex::new(Some(error_sender)));

        let tasks = FuturesUnordered::<BackgroundTask>::new();

        tasks.push(Box::pin(async move {
            if let Ok(error) = error_receiver.await {
                return Err(error);
            }

            Ok(())
        }));

        let shutting_down = Arc::new(AtomicBool::new(false));

        let plotting_join_handle = thread::Builder::new()
            .name(format!("p-{single_disk_plot_id}"))
            .spawn({
                let handle = handle.clone();
                let metadata_header = Arc::clone(&metadata_header);
                let shutting_down = Arc::clone(&shutting_down);
                let rpc_client = rpc_client.clone();
                let error_sender = Arc::clone(&error_sender);

                move || {
                    let _tokio_handle_guard = handle.enter();
                    let span = info_span!("single_disk_plot", %single_disk_plot_id);
                    let _span_guard = span.enter();

                    // Initial plotting
                    let initial_plotting_result = try {
                        let chunked_sectors = plot_mmap_mut
                            .as_mut()
                            .chunks_exact_mut(plot_sector_size as usize);
                        let chunked_metadata = metadata_mmap_mut
                            .as_mut()
                            .chunks_exact_mut(SectorMetadata::encoded_size());
                        let plot_initial_sector = chunked_sectors
                            .zip(chunked_metadata)
                            .enumerate()
                            .skip(
                                // Some sectors may already be plotted, skip them
                                metadata_header.lock().sector_count as usize,
                            )
                            .map(|(sector_index, (sector, metadata))| {
                                (sector_index as u64 + first_sector_index, sector, metadata)
                            });

                        // TODO: Concurrency
                        'sector: for (sector_index, sector, sector_metadata) in plot_initial_sector
                        {
                            if shutting_down.load(Ordering::Acquire) {
                                debug!(
                                    %sector_index,
                                    "Instance is shutting down, interrupting plotting"
                                );
                                return;
                            }
                            let sector_id = SectorId::new(&public_key, sector_index);
                            let farmer_protocol_info =
                                handle.block_on(rpc_client.farmer_protocol_info()).map_err(
                                    |error| PlottingError::FailedToGetFarmerProtocolInfo { error },
                                )?;
                            let total_pieces: PieceIndex = farmer_protocol_info.total_pieces;
                            // TODO: Consider adding number of pieces in a sector to protocol info
                            //  explicitly and, ideally, we need to remove 2x replication
                            //  expectation from other places too
                            let current_segment_index = farmer_protocol_info.total_pieces
                                / u64::from(farmer_protocol_info.recorded_history_segment_size)
                                / u64::from(farmer_protocol_info.record_size.get())
                                * 2;
                            let expires_at =
                                current_segment_index + farmer_protocol_info.sector_expiration;

                            for (piece_offset, sector_piece) in
                                sector.chunks_exact_mut(PIECE_SIZE).enumerate()
                            {
                                if shutting_down.load(Ordering::Acquire) {
                                    debug!(
                                        %sector_index,
                                        "Instance is shutting down, interrupting plotting"
                                    );
                                    return;
                                }
                                let piece_index = match sector_id
                                    .derive_piece_index(piece_offset as PieceIndex, total_pieces)
                                {
                                    Ok(piece_index) => piece_index,
                                    Err(()) => {
                                        error!(
                                            "Total number of pieces received from node is 0, this \
                                            should never happen! Aborting sector plotting."
                                        );
                                        break 'sector;
                                    }
                                };

                                let mut piece: Piece = handle
                                    .block_on(rpc_client.get_piece(piece_index))
                                    .map_err(|error| PlottingError::FailedToRetrievePiece {
                                        piece_index,
                                        error,
                                    })?
                                    .ok_or(PlottingError::PieceNotFound { piece_index })?;

                                let piece_witness = match Witness::try_from_bytes(
                                    &<[u8; 48]>::try_from(
                                        &piece[farmer_protocol_info.record_size.get() as usize..],
                                    )
                                    .expect(
                                        "Witness must have correct size unless implementation \
                                        is broken in a big way; qed",
                                    ),
                                ) {
                                    Ok(piece_witness) => piece_witness,
                                    Err(error) => {
                                        // TODO: This will have to change once we pull pieces from
                                        //  DSN
                                        panic!(
                                            "Failed to decode witness for piece {piece_index}, \
                                            must be a bug on the node: {error:?}"
                                        );
                                    }
                                };
                                // TODO: We are skipping witness part of the piece or else it is not
                                //  decodable
                                // TODO: Last bits may not be encoded if record size is not multiple
                                //  of `space_l`
                                // Encode piece
                                piece[..farmer_protocol_info.record_size.get() as usize]
                                    .view_bits_mut::<Lsb0>()
                                    .chunks_mut(space_l.get() as usize)
                                    .enumerate()
                                    .par_bridge()
                                    .for_each(|(chunk_index, bits)| {
                                        // Derive one-time pad
                                        let mut otp = derive_chunk_otp(
                                            &sector_id,
                                            &piece_witness,
                                            chunk_index as u32,
                                        );
                                        // XOR chunk bit by bit with one-time pad
                                        bits.iter_mut()
                                            .zip(otp.view_bits_mut::<Lsb0>().iter())
                                            .for_each(|(mut a, b)| {
                                                *a ^= *b;
                                            });
                                    });

                                sector_piece.copy_from_slice(&piece);
                            }

                            // TODO: Invert table in future

                            sector_metadata.copy_from_slice(
                                &SectorMetadata {
                                    total_pieces,
                                    expires_at,
                                }
                                .encode(),
                            );
                            let mut metadata_header = metadata_header.lock();
                            metadata_header.sector_count += 1;
                            metadata_header_mmap
                                .copy_from_slice(metadata_header.encode().as_slice());
                        }
                    };

                    if let Err(error) = initial_plotting_result {
                        if let Some(error_sender) = error_sender.lock().take() {
                            if let Err(error) = error_sender.send(error) {
                                error!(%error, "Plotting failed to send error to background task");
                            }
                        }
                    }
                }
            })?;

        let farming_join_handle = thread::Builder::new()
            .name(format!("f-{single_disk_plot_id}"))
            .spawn({
                let shutting_down = Arc::clone(&shutting_down);
                let identity = identity.clone();
                let rpc_client = rpc_client.clone();

                move || {
                    let _tokio_handle_guard = handle.enter();
                    let span = info_span!("single_disk_plot", %single_disk_plot_id);
                    let _span_guard = span.enter();

                    let farming_result = try {
                        info!("Subscribing to slot info notifications");
                        let mut slot_info_notifications = handle
                            .block_on(rpc_client.subscribe_slot_info())
                            .map_err(|error| FarmingError::FailedToGetFarmerProtocolInfo {
                                error,
                            })?;
                        let chunks_in_sector = u64::from(farmer_protocol_info.record_size.get())
                            * u64::from(u8::BITS)
                            / u64::from(space_l.get());

                        while let Some(slot_info) = handle.block_on(slot_info_notifications.next())
                        {
                            debug!(?slot_info, "New slot");

                            let sector_count = metadata_header.lock().sector_count;
                            let plot_mmap = unsafe {
                                MmapOptions::new()
                                    .len((plot_sector_size * sector_count) as usize)
                                    .map_mut(&plot_file)
                                    .map_err(|error| FarmingError::FailedToMapPlot { error })?
                            };
                            let metadata_mmap = unsafe {
                                MmapOptions::new()
                                    .offset(RESERVED_PLOT_METADATA)
                                    .len(SectorMetadata::encoded_size() * sector_count as usize)
                                    .map(&metadata_file)
                                    .map_err(|error| FarmingError::FailedToMapMetadata { error })?
                            };
                            let shutting_down = Arc::clone(&shutting_down);

                            let mut solutions = Vec::<Solution<PublicKey, PublicKey>>::new();

                            // TODO: This loop should happen in a blocking task
                            for (sector_index, sector, sector_metadata) in plot_mmap
                                .chunks_exact(plot_sector_size as usize)
                                .zip(metadata_mmap.chunks_exact(SectorMetadata::encoded_size()))
                                .enumerate()
                                .map(|(sector_index, (sector, metadata))| {
                                    (sector_index as u64 + first_sector_index, sector, metadata)
                                })
                            {
                                if shutting_down.load(Ordering::Acquire) {
                                    debug!(
                                        %sector_index,
                                        "Instance is shutting down, interrupting plotting"
                                    );
                                    return;
                                }

                                let sector_id = SectorId::new(&public_key, sector_index);

                                let local_challenge =
                                    sector_id.derive_local_challenge(&slot_info.global_challenge);
                                let audit_index: u64 = local_challenge % chunks_in_sector;
                                // Offset of the piece in sector (in bytes)
                                let audit_piece_offset = (audit_index / u64::from(u8::BITS))
                                    / PIECE_SIZE as u64
                                    * PIECE_SIZE as u64;
                                // Audit index (chunk) within corresponding piece
                                let audit_index_within_piece =
                                    audit_index - audit_piece_offset * u64::from(u8::BITS);
                                let mut piece = Piece::try_from(
                                    &sector[audit_piece_offset as usize..][..PIECE_SIZE],
                                )
                                .expect("Slice is guaranteed to have correct length; qed");

                                let record_size = farmer_protocol_info.record_size.get() as usize;
                                // TODO: We are skipping witness part of the piece or else it is not
                                //  decodable
                                let maybe_chunk = piece[..record_size]
                                    .view_bits()
                                    .chunks_exact(space_l.get() as usize)
                                    .nth(audit_index_within_piece as usize);

                                let chunk = match maybe_chunk {
                                    Some(chunk) => Chunk::from(chunk),
                                    None => {
                                        // TODO: Record size is not multiple of `space_l`, last bits
                                        //  were not encoded and should not be used for solving
                                        continue;
                                    }
                                };

                                // TODO: This just have 20 bits of entropy as input, should we add
                                //  something else?
                                let expanded_chunk = chunk.expand(local_challenge);

                                if is_within_solution_range2(
                                    local_challenge,
                                    expanded_chunk,
                                    slot_info.voting_solution_range,
                                ) {
                                    let sector_metadata =
                                        SectorMetadata::decode(&mut &*sector_metadata).map_err(
                                            |error| FarmingError::FailedToDecodeMetadata { error },
                                        )?;

                                    debug!("Solution found");

                                    let piece_witness = match Witness::try_from_bytes(
                                        &<[u8; 48]>::try_from(&piece[record_size..]).expect(
                                            "Witness must have correct size unless implementation \
                                            is broken in a big way; qed",
                                        ),
                                    ) {
                                        Ok(piece_witness) => piece_witness,
                                        Err(error) => {
                                            if let Ok(piece_index) = sector_id.derive_piece_index(
                                                audit_piece_offset / PIECE_SIZE as u64,
                                                sector_metadata.total_pieces,
                                            ) {
                                                error!(
                                                    ?error,
                                                    ?sector_id,
                                                    %audit_piece_offset,
                                                    %piece_index,
                                                    "Failed to decode witness for piece, likely \
                                                    caused by on-disk data corruption"
                                                );
                                            } else {
                                                error!(
                                                    ?sector_id,
                                                    %audit_piece_offset,
                                                    "Failed to decode witness for piece, likely \
                                                    caused by on-disk data corruption"
                                                );
                                                error!(
                                                    ?sector_id,
                                                    %audit_piece_offset,
                                                    "Total number of pieces in sector metadata is \
                                                    0, this means on-disk data were corrupted or \
                                                    severe implementation bug!"
                                                );
                                            }
                                            continue;
                                        }
                                    };
                                    // Decode piece
                                    piece[..record_size]
                                        .view_bits_mut::<Lsb0>()
                                        .chunks_mut(space_l.get() as usize)
                                        .enumerate()
                                        .par_bridge()
                                        .for_each(|(chunk_index, bits)| {
                                            // Derive one-time pad
                                            let mut otp = derive_chunk_otp(
                                                &sector_id,
                                                &piece_witness,
                                                chunk_index as u32,
                                            );
                                            // XOR chunk bit by bit with one-time pad
                                            bits.iter_mut()
                                                .zip(otp.view_bits_mut::<Lsb0>().iter())
                                                .for_each(|(mut a, b)| {
                                                    *a ^= *b;
                                                });
                                        });

                                    let solution = Solution {
                                        public_key,
                                        reward_address,
                                        sector_index,
                                        total_pieces: sector_metadata.total_pieces,
                                        piece_offset: audit_piece_offset,
                                        piece_record_hash: blake2b_256_254_hash(
                                            &piece[..record_size],
                                        ),
                                        piece_witness,
                                        chunk,
                                        chunk_signature: identity.create_chunk_signature(&chunk),
                                    };

                                    trace!(?solution, "Solution found");

                                    solutions.push(solution);
                                }
                            }

                            handle
                                .block_on(rpc_client.submit_solution_response(SolutionResponse {
                                    slot_number: slot_info.slot_number,
                                    solutions,
                                }))
                                .map_err(|error| FarmingError::FailedToSubmitSolutionsResponse {
                                    error,
                                })?;
                        }
                    };

                    if let Err(error) = farming_result {
                        if let Some(error_sender) = error_sender.lock().take() {
                            if let Err(error) = error_sender.send(error) {
                                error!(%error, "Farming failed to send error to background task");
                            }
                        }
                    }
                }
            })?;

        tasks.push(Box::pin(async move {
            // TODO: Error handling here
            reward_signing(rpc_client, identity).await.unwrap().await;

            Ok(())
        }));

        let farm = Self {
            id: single_disk_plot_id,
            span: Span::current(),
            tasks,
            _plotting_join_handle: JoinOnDrop::new(plotting_join_handle),
            _farming_join_handle: JoinOnDrop::new(farming_join_handle),
            shutting_down,
        };

        Ok(farm)
    }

    /// Collect summary of single disk plot for presentational purposes
    pub fn collect_summary(directory: PathBuf) -> SingleDiskPlotSummary {
        let single_disk_plot_info = match SingleDiskPlotInfo::load_from(&directory) {
            Ok(Some(single_disk_plot_info)) => single_disk_plot_info,
            Ok(None) => {
                return SingleDiskPlotSummary::NotFound { directory };
            }
            Err(error) => {
                return SingleDiskPlotSummary::Error { directory, error };
            }
        };

        SingleDiskPlotSummary::Found {
            info: single_disk_plot_info,
            directory,
        }
    }

    /// ID of this farm
    pub fn id(&self) -> &SingleDiskPlotId {
        &self.id
    }

    /// Wait for background threads to exit or return an error
    pub async fn wait(mut self) -> anyhow::Result<()> {
        while let Some(result) = self.tasks.next().instrument(self.span.clone()).await {
            result?;
        }

        Ok(())
    }
}
