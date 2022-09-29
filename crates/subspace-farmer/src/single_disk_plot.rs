use crate::file_ext::FileExt;
use crate::identity::Identity;
use crate::rpc_client::RpcClient;
use crate::single_disk_farm::SingleDiskSemaphore;
use crate::utils::JoinOnDrop;
use bytesize::ByteSize;
use derive_more::{Display, From};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use memmap2::{MmapMut, MmapOptions};
use parity_db::const_assert;
use parity_scale_codec::{Decode, Encode};
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
use subspace_core_primitives::{plot_sector_size, PieceIndex, PublicKey, SectorId, PIECE_SIZE};
use subspace_networking::Node;
use subspace_rpc_primitives::FarmerProtocolInfo;
use subspace_solving::SubspaceCodec;
use thiserror::Error;
use tokio::runtime::Handle;
use tracing::{debug, error, info_span, Instrument, Span};
use ulid::Ulid;

// Refuse to compile on non-64-bit platforms, offsets may fail on those when converting from u64 to
// usize depending on chain parameters
const_assert!(std::mem::size_of::<usize>() >= std::mem::size_of::<u64>());

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
        // ID of the plot
        id: SingleDiskPlotId,
        // Genesis hash of the chain used for plot creation
        genesis_hash: [u8; 32],
        // Public key of identity used for plot creation
        public_key: PublicKey,
        /// First sector index in this plot
        first_sector_index: u64,
        // How much space in bytes can plot use for plot (metadata space is not included)
        allocated_space: u64,
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
struct SectorMetadata {}

impl SectorMetadata {
    fn encoded_size() -> usize {
        let default = SectorMetadata {};

        default.encoded_size()
    }
}

/// Options used to open single dis plot
pub struct SingleDiskPlotOptions<RC> {
    /// Path to directory where plot are stored.
    pub directory: PathBuf,
    /// How much space in bytes can plot use for plot
    pub allocated_space: u64,
    /// Identity associated with plot
    pub identity: Identity,
    /// Networking instance for external communication with DSN
    pub node: Node,
    /// RPC client connected to Subspace node
    pub rpc_client: RC,
    /// Address where farming rewards should go
    pub reward_address: PublicKey,
    /// Information about protocol necessary for farmer
    pub farmer_protocol_info: FarmerProtocolInfo,
}

/// Errors happening when trying to create/open single disk plot
#[derive(Debug, Error)]
pub enum SingleDiskPlotError {
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
        created, is is not possible to use plot on a different chain"
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
}

/// Single disk plot abstraction is a container for everything necessary to plot/farm with a single
/// disk plot.
#[must_use = "Plot does not function properly unless run() method is called"]
pub struct SingleDiskPlot {
    id: SingleDiskPlotId,
    span: Span,
    tasks: FuturesUnordered<Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>>,
    _plotting_join_handle: JoinOnDrop,
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
        let SingleDiskPlotOptions {
            directory,
            allocated_space,
            identity,
            // TODO: Use this or remove
            node: _,
            farmer_protocol_info,
            // TODO: Use this or remove
            rpc_client,
            // TODO: Use this or remove
            reward_address: _,
        } = options;

        fs::create_dir_all(&directory)?;

        // TODO: Parametrize concurrency, much higher default due to SSD focus
        // TODO: Use this or remove
        let _single_disk_semaphore =
            SingleDiskSemaphore::new(NonZeroU16::new(10).expect("Not a zero; qed"));

        let public_key = identity.public_key().to_bytes().into();

        // TODO: In case `space_l` changes on the fly, code below will break horribly
        let plot_sector_size = plot_sector_size(farmer_protocol_info.space_l);

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
                // TODO: Global generator that makes sure to avoid returning the same sector index for multiple disks
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

        // TODO: Account for plot overhead
        let target_sector_count = allocated_space / plot_sector_size;
        let plot_file_size = target_sector_count * plot_sector_size;

        let mut metadata_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(directory.join(Self::METADATA_FILE))?;

        metadata_file.advise_random_access()?;

        let (mut metadata_header, mut metadata_header_mmap) =
            if metadata_file.seek(SeekFrom::End(0))? == 0 {
                let metadata_header = PlotMetadataHeader {
                    version: 0,
                    sector_count: 0,
                };

                metadata_file.preallocate(
                    PlotMetadataHeader::encoded_size() as u64
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

                let metadata_header =
                    PlotMetadataHeader::decode(&mut metadata_header_mmap.as_ref())
                        .map_err(SingleDiskPlotError::FailedToDecodeMetadataHeader)?;

                if metadata_header.version != 0 {
                    return Err(SingleDiskPlotError::UnexpectedMetadataVersion(
                        metadata_header.version,
                    ));
                }

                (metadata_header, metadata_header_mmap)
            };

        let mut metadata_mmap = unsafe {
            MmapOptions::new()
                .offset(metadata_header.encoded_size() as u64)
                .len(SectorMetadata::encoded_size())
                .map_mut(&metadata_file)?
        };

        let plot_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(directory.join(Self::PLOT_FILE))?;

        plot_file.preallocate(plot_file_size)?;

        let mut plot_mmap = unsafe { MmapMut::map_mut(&plot_file)? };

        // TODO: Use this or remove
        let _codec = SubspaceCodec::new_with_gpu(public_key.as_ref());

        let tasks =
            FuturesUnordered::<Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>>::new();

        let shutting_down = Arc::new(AtomicBool::new(false));

        // Plotting
        let plotting_join_handle = thread::Builder::new()
            .name(format!("p-{single_disk_plot_id}"))
            .spawn({
                let handle = Handle::current();
                let shutting_down = Arc::clone(&shutting_down);
                let pieces_per_sector = plot_sector_size.div_ceil(PIECE_SIZE as u64);

                move || {
                    let _tokio_handle_guard = handle.enter();
                    let span = info_span!("single_disk_plot", %single_disk_plot_id);
                    let _span_guard = span.enter();

                    // Initial plotting
                    {
                        let chunked_sectors = plot_mmap
                            .as_mut()
                            .chunks_exact_mut(plot_sector_size as usize);
                        let chunked_metadata = metadata_mmap
                            .as_mut()
                            .chunks_exact_mut(SectorMetadata::encoded_size());
                        let plot_initial_sector = chunked_sectors
                            .zip(chunked_metadata)
                            .enumerate()
                            .skip(
                                // Some sectors may already be plotted, skip them
                                metadata_header.sector_count as usize,
                            )
                            .map(|(sector_index, (sector, metadata))| {
                                (
                                    sector_index as u64
                                        + single_disk_plot_info.first_sector_index(),
                                    sector,
                                    metadata,
                                )
                            });

                        // TODO: Concurrency
                        for (sector_index, sector, metadata) in plot_initial_sector {
                            if shutting_down.load(Ordering::Acquire) {
                                debug!(
                                    %sector_index,
                                    "Instance is shutting down, interrupting plotting"
                                );
                                return;
                            }
                            let sector_id = SectorId::new(&public_key, sector_index);
                            // TODO: Query from node before every sector such that sectors are
                            //  always created with latest value
                            let total_pieces: PieceIndex = farmer_protocol_info.total_pieces;
                            let mut pieces =
                                Vec::with_capacity(pieces_per_sector as usize * PIECE_SIZE);

                            for piece_offset in 0..pieces_per_sector {
                                if shutting_down.load(Ordering::Acquire) {
                                    debug!(
                                        %sector_index,
                                        "Instance is shutting down, interrupting plotting"
                                    );
                                    return;
                                }
                                let piece_index =
                                    sector_id.derive_piece_index(piece_offset, total_pieces);

                                let piece = match handle.block_on(rpc_client.get_piece(piece_index))
                                {
                                    Ok(Some(piece)) => piece,
                                    Ok(None) => {
                                        error!(
                                            %piece_index,
                                            "Piece not found, can't create sector, this should \
                                            never happen"
                                        );
                                        return;
                                    }
                                    Err(error) => {
                                        error!(%error, "Failed to retriever piece");
                                        return;
                                    }
                                };

                                pieces.extend_from_slice(&piece);
                            }

                            // TODO: Encode pieces
                            // TODO: Create table
                            // TODO: Write table to sector
                            // TODO: Write sector metadata

                            metadata_header.sector_count += 1;
                            metadata_header_mmap
                                .copy_from_slice(metadata_header.encode().as_slice());
                        }
                    }
                }
            })?;

        let farm = Self {
            id: single_disk_plot_id,
            span: Span::current(),
            tasks,
            _plotting_join_handle: JoinOnDrop::new(plotting_join_handle),
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

        return SingleDiskPlotSummary::Found {
            id: *single_disk_plot_info.id(),
            genesis_hash: *single_disk_plot_info.genesis_hash(),
            public_key: *single_disk_plot_info.public_key(),
            first_sector_index: single_disk_plot_info.first_sector_index(),
            allocated_space: single_disk_plot_info.allocated_space(),
            directory,
        };
    }

    /// ID of this farm
    pub fn id(&self) -> &SingleDiskPlotId {
        &self.id
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        while let Some(result) = self.tasks.next().instrument(self.span.clone()).await {
            result?;
        }

        Ok(())
    }
}
