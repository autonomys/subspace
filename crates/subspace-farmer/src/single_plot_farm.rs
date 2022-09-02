pub mod dsn_archiving;
#[cfg(test)]
mod tests;

use crate::commitments::{CommitmentError, Commitments};
use crate::dsn::{self, OnSync, PieceIndexHashNumber, SyncOptions};
use crate::farming::Farming;
use crate::identity::Identity;
use crate::object_mappings::ObjectMappings;
use crate::plot::{Plot, PlotError};
use crate::rpc_client::RpcClient;
use crate::single_disk_farm::SingleDiskSemaphore;
use crate::single_plot_farm::dsn_archiving::start_archiving;
use crate::utils::CallOnDrop;
use crate::ws_rpc_server::PieceGetter;
use anyhow::anyhow;
use async_trait::async_trait;
use derive_more::{Display, From};
use futures::future::try_join_all;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use num_traits::Zero;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::{fs, io, mem};
use subspace_archiving::archiver::is_piece_valid;
use subspace_core_primitives::{
    FlatPieces, Piece, PieceIndex, PieceIndexHash, PublicKey, Sha256Hash,
};
use subspace_networking::libp2p::identity::sr25519;
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::multimess::MultihashCode;
use subspace_networking::{
    BootstrappedNetworkingParameters, Config, Node, ObjectMappingsRequest,
    ObjectMappingsRequestHandler, ObjectMappingsResponse, PeerInfo, PeerInfoRequestHandler,
    PeerInfoResponse, PeerSyncStatus, PiecesByRangeRequest, PiecesByRangeRequestHandler,
    PiecesByRangeResponse, PiecesToPlot,
};
use subspace_rpc_primitives::{FarmerProtocolInfo, MAX_SEGMENT_INDEXES_PER_REQUEST};
use subspace_solving::{BatchEncodeError, SubspaceCodec};
use thiserror::Error;
use tokio::runtime::Handle;
use tracing::{error, info, trace, warn, Instrument, Span};
use ulid::Ulid;

/// A bit more than 4M. Should correspond to requested range size from DSN.
const SYNC_PIECES_AT_ONCE: u64 = 1100;
/// 100 MiB worth of object mappings per plot
const MAX_OBJECT_MAPPINGS_SIZE: u64 = 100 * 1024 * 1024;

/// An identifier for single plot farm, can be used for in logs, thread names, etc.
#[derive(
    Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Display, From,
)]
#[serde(untagged)]
pub enum SinglePlotFarmId {
    /// New farm ID
    Ulid(Ulid),
}

#[allow(clippy::new_without_default)]
impl SinglePlotFarmId {
    /// Creates new ID
    pub fn new() -> Self {
        Self::Ulid(Ulid::new())
    }
}

/// An alias defining a peer status providing callback.
pub type PeerSyncStatusProvider = Box<dyn Fn() -> PeerSyncStatus + Send>;

/// Important information about the contents of the `SinglePlotFarm`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SinglePlotFarmInfo {
    /// V0 of the info
    #[serde(rename_all = "camelCase")]
    V0 {
        /// ID of the farm
        id: SinglePlotFarmId,
        // Public key of identity used for farm creation
        public_key: PublicKey,
        // How much space in bytes is allocated for plot in this farm (metadata space is not
        // included)
        allocated_plotting_space: u64,
    },
}

impl SinglePlotFarmInfo {
    const FILE_NAME: &'static str = "single_plot_farm.json";

    pub fn new(id: SinglePlotFarmId, public_key: PublicKey, allocated_plotting_space: u64) -> Self {
        Self::V0 {
            id,
            public_key,
            allocated_plotting_space,
        }
    }

    /// Load `SinglePlotFarm` from path is supposed to be stored, `None` means no info file was
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

    /// Store `SinglePlotFarm` info to path so it can be loaded again upon restart.
    pub fn store_to(&self, metadata_directory: &Path) -> io::Result<()> {
        fs::write(
            metadata_directory.join(Self::FILE_NAME),
            serde_json::to_vec(self).expect("Info serialization never fails; qed"),
        )
    }

    // ID of the farm
    pub fn id(&self) -> &SinglePlotFarmId {
        let Self::V0 { id, .. } = self;
        id
    }

    // Public key of identity used for farm creation
    pub fn public_key(&self) -> &PublicKey {
        let Self::V0 { public_key, .. } = self;
        public_key
    }

    // How much space in bytes is allocated for plot in this farm (metadata space is not included)
    pub fn allocated_plotting_space(&self) -> u64 {
        let Self::V0 {
            allocated_plotting_space,
            ..
        } = self;
        *allocated_plotting_space
    }
}

/// Summary of single plot farm for presentational purposes
pub enum SinglePlotFarmSummary {
    /// Farm was found and read successfully
    Found {
        // ID of the farm
        id: SinglePlotFarmId,
        // Public key of identity used for farm creation
        public_key: PublicKey,
        // How much space in bytes can farm use for plots (metadata space is not included)
        allocated_plotting_space: u64,
        /// Path to directory where plots are stored, typically HDD.
        plot_directory: PathBuf,
        /// Path to directory for storing metadata, typically SSD.
        metadata_directory: PathBuf,
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

#[derive(Debug, Clone)]
pub struct SinglePlotPieceGetter {
    codec: SubspaceCodec,
    plot: Plot,
}

impl SinglePlotPieceGetter {
    pub fn new(codec: SubspaceCodec, plot: Plot) -> Self {
        Self { codec, plot }
    }
}

impl PieceGetter for SinglePlotPieceGetter {
    fn get_piece(
        &self,
        piece_index: PieceIndex,
        piece_index_hash: PieceIndexHash,
    ) -> Option<Piece> {
        match self.plot.read_piece(piece_index_hash) {
            Ok(mut piece) => match self.codec.decode(&mut piece, piece_index) {
                Ok(()) => {
                    return Some(piece);
                }
                Err(error) => {
                    trace!(
                        %error,
                        "Failed to decode piece with piece index hash {}",
                        hex::encode(piece_index_hash)
                    );
                }
            },
            Err(error) => {
                trace!(
                    %error,
                    "Piece with piece index hash {} not found in plot",
                    hex::encode(piece_index_hash)
                );
            }
        }

        None
    }
}

/// Errors that happen during plotting of pieces
#[derive(Debug, Error)]
pub enum SinglePlotPlotterError {
    /// Encode error
    #[error("Encode error: {0}")]
    Encode(#[from] BatchEncodeError),
    /// Plot error
    #[error("Plot error: {0}")]
    Plot(#[from] io::Error),
    /// Commitments error
    #[error("Commitment error: {0}")]
    Commitment(#[from] CommitmentError),
}

#[derive(Debug, Clone)]
pub struct SinglePlotPlotter {
    codec: SubspaceCodec,
    plot: Plot,
    commitments: Commitments,
    #[allow(dead_code)]
    single_disk_semaphore: SingleDiskSemaphore,
}

impl SinglePlotPlotter {
    fn new(
        codec: SubspaceCodec,
        weak_plot: Plot,
        commitments: Commitments,
        single_disk_semaphore: SingleDiskSemaphore,
    ) -> Self {
        Self {
            codec,
            plot: weak_plot,
            commitments,
            single_disk_semaphore,
        }
    }

    /// Plot specified pieces in this farm, potentially replacing some of existing pieces
    pub fn plot_pieces(&self, pieces_to_plot: PiecesToPlot) -> Result<(), SinglePlotPlotterError> {
        let PiecesToPlot {
            piece_indexes,
            mut pieces,
        } = pieces_to_plot;
        self.codec.batch_encode(&mut pieces, &piece_indexes)?;

        let pieces = Arc::new(pieces);

        // TODO: Restore limiting when better approach is figured out, right now commitments
        //  creation blocks plotting of new pieces, which is not desirable
        // // Limit concurrent updates on the same disk
        // let _guard = self.single_disk_semaphore.acquire();

        let write_result = self.plot.write_many(pieces, piece_indexes)?;

        self.commitments
            .remove_pieces(write_result.evicted_pieces())?;

        self.commitments
            .create_for_pieces(|| write_result.to_recommitment_iterator())
            .map_err(Into::into)
    }
}

#[derive(Debug)]
pub struct PlotFactoryOptions<'a> {
    pub single_plot_farm_id: &'a SinglePlotFarmId,
    pub public_key: PublicKey,
    pub plot_directory: &'a Path,
    pub metadata_directory: &'a Path,
    pub max_plot_size: u64,
}

pub trait PlotFactory =
    Fn(PlotFactoryOptions<'_>) -> Result<Plot, PlotError> + Send + Sync + 'static;

pub(crate) struct SinglePlotFarmOptions<'a, RC, PF> {
    pub(crate) id: SinglePlotFarmId,
    pub(crate) plot_directory: PathBuf,
    pub(crate) metadata_directory: PathBuf,
    pub(crate) allocated_plotting_space: u64,
    pub(crate) farmer_protocol_info: FarmerProtocolInfo,
    pub(crate) farming_client: RC,
    pub(crate) plot_factory: &'a PF,
    /// Nodes to connect to on creation, must end with `/p2p/QmFoo` at the end.
    pub(crate) bootstrap_nodes: Vec<Multiaddr>,
    /// List of [`Multiaddr`] on which to listen for incoming connections.
    pub(crate) listen_on: Vec<Multiaddr>,
    pub(crate) single_disk_semaphore: SingleDiskSemaphore,
    pub(crate) enable_farming: bool,
    pub(crate) reward_address: PublicKey,
    pub(crate) enable_dsn_archiving: bool,
    pub(crate) enable_dsn_sync: bool,
    pub(crate) relay_server_node: Option<Node>,
    /// Client used for pieces verification
    pub(crate) verification_client: RC,
}

/// Single plot farm abstraction is a container for everything necessary to plot/farm with a single
/// disk plot.
#[must_use = "Farm does not function properly unless run() method is called"]
pub struct SinglePlotFarm {
    directories: Vec<PathBuf>,
    id: SinglePlotFarmId,
    public_key: PublicKey,
    codec: SubspaceCodec,
    plot: Plot,
    commitments: Commitments,
    object_mappings: ObjectMappings,
    node: Node,
    single_disk_semaphore: SingleDiskSemaphore,
    span: Span,
    tasks: FuturesUnordered<Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>>,
}

impl SinglePlotFarm {
    pub(crate) fn new<RC, PF>(options: SinglePlotFarmOptions<'_, RC, PF>) -> anyhow::Result<Self>
    where
        RC: RpcClient,
        PF: PlotFactory,
    {
        let SinglePlotFarmOptions {
            id,
            plot_directory,
            metadata_directory,
            allocated_plotting_space,
            farmer_protocol_info,
            farming_client,
            plot_factory,
            bootstrap_nodes,
            listen_on,
            single_disk_semaphore,
            enable_farming,
            reward_address,
            enable_dsn_archiving,
            enable_dsn_sync,
            relay_server_node,
            verification_client,
        } = options;

        fs::create_dir_all(&plot_directory)?;
        fs::create_dir_all(&metadata_directory)?;

        let identity = Identity::open_or_create(&metadata_directory)?;
        let public_key = identity.public_key().to_bytes().into();

        let single_plot_farm_info = match SinglePlotFarmInfo::load_from(&metadata_directory)? {
            Some(single_plot_farm_info) => {
                if allocated_plotting_space != single_plot_farm_info.allocated_plotting_space() {
                    error!(
                        id = %single_plot_farm_info.id(),
                        plot_directory = %plot_directory.display(),
                        metadata_directory = %metadata_directory.display(),
                        "Usable plotting space {} is different from {} when farm was created, \
                        resizing isn't supported yet",
                        allocated_plotting_space,
                        single_plot_farm_info.allocated_plotting_space(),
                    );

                    return Err(anyhow!("Can't resize farm after creation"));
                }

                if &public_key != single_plot_farm_info.public_key() {
                    error!(
                        id = %single_plot_farm_info.id(),
                        "Public key {} is different from {} when farm was created, something \
                        went wrong, likely due to manual edits",
                        hex::encode(&public_key),
                        hex::encode(single_plot_farm_info.public_key()),
                    );

                    return Err(anyhow!("Public key in identity doesn't match metadata"));
                }

                single_plot_farm_info
            }
            None => {
                let single_plot_farm_info =
                    SinglePlotFarmInfo::new(id, public_key, allocated_plotting_space);

                single_plot_farm_info.store_to(&metadata_directory)?;

                single_plot_farm_info
            }
        };

        info!("Opening plot");
        let plot = plot_factory(PlotFactoryOptions {
            single_plot_farm_id: &id,
            public_key,
            plot_directory: &plot_directory,
            metadata_directory: &metadata_directory,
            max_plot_size: single_plot_farm_info.allocated_plotting_space(),
        })?;

        info!("Opening object mappings");
        let object_mappings = ObjectMappings::open_or_create(
            &metadata_directory.join("object-mappings"),
            public_key,
            MAX_OBJECT_MAPPINGS_SIZE,
        )?;

        info!("Opening commitments");
        let commitments = Commitments::new(metadata_directory.join("commitments"))?;

        let codec = SubspaceCodec::new_with_gpu(public_key.as_ref());
        let peer_sync_status_provider: Arc<Mutex<PeerSyncStatusProvider>> =
            Arc::new(Mutex::new(Box::new(|| PeerSyncStatus::Unknown)));
        let network_node_config = Config {
            networking_parameters_registry: BootstrappedNetworkingParameters::new(bootstrap_nodes)
                .boxed(),
            listen_on,
            // TODO: Do we still need it?
            value_getter: Arc::new({
                let plot = plot.clone();
                let codec = codec.clone();
                move |key| {
                    let code = key.code();

                    if code != u64::from(MultihashCode::Piece)
                        && code != u64::from(MultihashCode::PieceIndex)
                    {
                        return None;
                    }

                    let piece_index =
                        u64::from_le_bytes(key.digest()[..mem::size_of::<u64>()].try_into().ok()?);
                    plot.read_piece(PieceIndexHash::from_index(piece_index))
                        .ok()
                        .and_then(|mut piece| {
                            codec
                                .decode(&mut piece, piece_index)
                                .ok()
                                .map(move |()| piece)
                        })
                        .map(|piece| piece.to_vec())
                }
            }),
            request_response_protocols: vec![
                PiecesByRangeRequestHandler::create({
                    let plot = plot.clone();
                    let codec = codec.clone();

                    // TODO: also ask for how many pieces to read
                    move |&PiecesByRangeRequest { start, end }| {
                        let mut pieces_and_indexes = plot
                            .get_sequential_pieces(start, SYNC_PIECES_AT_ONCE)
                            .ok()?;

                        let next_piece_index_hash = if let Some(idx) =
                            pieces_and_indexes.iter().position(|(piece_index, _)| {
                                PieceIndexHash::from_index(*piece_index) > end
                            }) {
                            pieces_and_indexes.truncate(idx);
                            None
                        } else if pieces_and_indexes.len() == 1 {
                            None
                        } else {
                            pieces_and_indexes
                                .pop()
                                .map(|(index, _)| PieceIndexHash::from_index(index))
                        };

                        let (piece_indexes, pieces) = pieces_and_indexes
                            .into_iter()
                            .flat_map(|(index, mut piece)| {
                                codec.decode(&mut piece, index).ok()?;
                                Some((index, piece))
                            })
                            .unzip();

                        Some(PiecesByRangeResponse {
                            pieces: PiecesToPlot {
                                piece_indexes,
                                pieces,
                            },
                            next_piece_index_hash,
                        })
                    }
                }),
                PeerInfoRequestHandler::create({
                    let peer_sync_status_provider = peer_sync_status_provider.clone();
                    move |_req| {
                        let peer_sync_status_provider = peer_sync_status_provider.lock();

                        Some(PeerInfoResponse {
                            peer_info: PeerInfo {
                                status: peer_sync_status_provider(),
                            },
                        })
                    }
                }),
                ObjectMappingsRequestHandler::create({
                    let object_mappings = object_mappings.clone();

                    move |&ObjectMappingsRequest { object_hash }| {
                        let result = object_mappings.retrieve(&object_hash);
                        let object_mapping = match result {
                            Ok(res) => res,
                            Err(err) => {
                                error!(%err, ?object_hash, "Cannot retrieve an object mapping.");

                                None
                            }
                        };

                        Some(ObjectMappingsResponse { object_mapping })
                    }
                }),
            ],
            allow_non_globals_in_dht: true,
            ..Config::with_keypair(sr25519::Keypair::from(
                sr25519::SecretKey::from_bytes(identity.secret_key().to_bytes())
                    .expect("Always valid"),
            ))
        };

        let (node, mut node_runner) = Handle::current().block_on(async move {
            if let Some(relay_server_node) = relay_server_node {
                relay_server_node.spawn(network_node_config).await
            } else {
                subspace_networking::create(network_node_config).await
            }
        })?;

        // Replace the default peer sync status provider based on actual Node status.
        {
            let sync_status_node = node.clone();
            let mut peer_sync_status_provider = peer_sync_status_provider.lock();

            *peer_sync_status_provider = Box::new(move || {
                if sync_status_node.sync_status_handler().status() {
                    PeerSyncStatus::Syncing
                } else {
                    PeerSyncStatus::Ready
                }
            });
        }

        info!("Network peer ID {}", node.id());

        // Start the farming task
        let farming = enable_farming.then(|| {
            Farming::create(
                id,
                plot.clone(),
                commitments.clone(),
                farming_client,
                single_disk_semaphore.clone(),
                identity,
                reward_address,
            )
        });

        let tasks =
            FuturesUnordered::<Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>>::new();

        if let Some(mut farming) = farming {
            tasks.push(Box::pin(async move {
                farming.wait().await?;

                Ok(())
            }));
        }

        tasks.push(Box::pin(async move {
            node_runner.run().await;

            Ok(())
        }));

        let farm = Self {
            directories: vec![metadata_directory, plot_directory],
            id,
            public_key,
            codec,
            plot,
            commitments,
            object_mappings,
            node: node.clone(),
            single_disk_semaphore,
            span: Span::current(),
            tasks,
        };

        // Start DSN archiving
        if enable_dsn_archiving {
            let archiving_fut = start_archiving(
                id,
                farmer_protocol_info.record_size.get(),
                farmer_protocol_info.recorded_history_segment_size,
                farm.object_mappings().clone(),
                node,
                farm.plotter(),
                farm.single_disk_semaphore.clone(),
            );

            farm.tasks.push(Box::pin(async move {
                if let Err(error) = archiving_fut.await {
                    error!(%error, "DSN archiving task has ended with error");
                } else {
                    warn!("DSN archiving task has finished");
                }

                Ok(())
            }));
        }

        // Start DSN syncing
        if enable_dsn_sync {
            // TODO: operate with number of pieces to fetch, instead of range calculations
            let sync_range_size = (PieceIndexHashNumber::MAX / farmer_protocol_info.total_pieces)
                .saturating_mul(&1024u32.into()); // 4M per stream

            let dsn_sync_fut = farm.dsn_sync(
                verification_client,
                farmer_protocol_info,
                sync_range_size,
                true,
            );
            let dsn_sync_node = farm.node.clone();

            farm.tasks.push(Box::pin(async move {
                trace!("Started waiting for connected peers.");
                let wait_result = dsn_sync_node.wait_for_connected_peers().await;

                match wait_result {
                    Ok(_) => {
                        trace!("Waiting for connected peers succeeded.");
                    }
                    Err(error) => {
                        error!(?error, "Waiting for connected peers failed.");
                    }
                };

                match dsn_sync_fut.await {
                    Ok(()) => {
                        info!("DSN sync finished.");
                    }
                    Err(error) => {
                        error!(?error, "DSN sync failed");
                    }
                }

                Ok(())
            }));
        }

        Ok(farm)
    }

    pub fn directories(&self) -> &[PathBuf] {
        &self.directories
    }

    /// Collect summary of single plot farm for presentational purposes
    pub fn collect_summary(
        plot_directory: PathBuf,
        metadata_directory: PathBuf,
    ) -> SinglePlotFarmSummary {
        let single_plot_farm_info = match SinglePlotFarmInfo::load_from(&metadata_directory) {
            Ok(Some(single_plot_farm_info)) => single_plot_farm_info,
            Ok(None) => {
                return SinglePlotFarmSummary::NotFound {
                    plot_directory,
                    metadata_directory,
                };
            }
            Err(error) => {
                return SinglePlotFarmSummary::Error {
                    plot_directory,
                    metadata_directory,
                    error,
                };
            }
        };

        return SinglePlotFarmSummary::Found {
            id: *single_plot_farm_info.id(),
            public_key: *single_plot_farm_info.public_key(),
            allocated_plotting_space: single_plot_farm_info.allocated_plotting_space(),
            plot_directory,
            metadata_directory,
        };
    }

    /// ID of this farm
    pub fn id(&self) -> &SinglePlotFarmId {
        &self.id
    }

    /// Public key associated with this farm
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Access plot instance of the farm
    pub fn plot(&self) -> &Plot {
        &self.plot
    }

    /// Access commitments instance of the farm
    pub fn commitments(&self) -> &Commitments {
        &self.commitments
    }

    /// Access object mappings instance of the farm
    pub fn object_mappings(&self) -> &ObjectMappings {
        &self.object_mappings
    }

    /// Access network node instance of the farm
    pub fn node(&self) -> &Node {
        &self.node
    }

    pub fn piece_getter(&self) -> impl PieceGetter {
        SinglePlotPieceGetter::new(self.codec.clone(), self.plot.clone())
    }

    /// Plotter for this plot
    pub fn plotter(&self) -> SinglePlotPlotter {
        SinglePlotPlotter::new(
            self.codec.clone(),
            self.plot.clone(),
            self.commitments.clone(),
            self.single_disk_semaphore.clone(),
        )
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        while let Some(result) = self.tasks.next().instrument(self.span.clone()).await {
            result?;
        }

        Ok(())
    }

    pub(crate) fn dsn_sync<RC: RpcClient>(
        &self,
        verification_client: RC,
        farmer_protocol_info: FarmerProtocolInfo,
        range_size: PieceIndexHashNumber,
        pieces_verification_enabled: bool,
    ) -> impl Future<Output = anyhow::Result<()>> {
        let options = SyncOptions {
            range_size,
            public_key: self.public_key,
            max_plot_size: farmer_protocol_info.max_plot_size,
            total_pieces: farmer_protocol_info.total_pieces,
        };

        let plotter = VerifyingPlotter {
            single_plot_plotter: self.plotter(),
            span: self.span.clone(),
            verification_client,
            farmer_protocol_info,
            pieces_verification_enabled,
        };

        dsn::sync(self.node.clone(), options, plotter)
    }
}

/// Pieces verification errors.
#[derive(Error, Debug)]
pub enum PiecesVerificationError {
    /// Invalid pieces data provided
    #[error("Invalid pieces data provided")]
    InvalidRawData,
    /// Invalid farmer protocol info provided
    #[error("Invalid farmer protocol info provided")]
    InvalidFarmerProtocolInfo,
    /// Pieces verification failed.
    #[error("Pieces verification failed.")]
    InvalidPieces,
    /// RPC client failed.
    #[error("RPC client failed. jsonrpsee error: {0}")]
    RpcError(Box<dyn std::error::Error + Send + Sync>),
    /// RPC client returned empty records_root.
    #[error("RPC client returned empty records root.")]
    NoRecordsRootFound,
}

// Defines actions on receiving pieces batch. It verifies the pieces against the blockchain and
// plots them.
struct VerifyingPlotter<RC> {
    // RPC client for verification
    verification_client: RC,
    span: Span,
    single_plot_plotter: SinglePlotPlotter,
    farmer_protocol_info: FarmerProtocolInfo,
    pieces_verification_enabled: bool,
}

impl<RC: RpcClient> VerifyingPlotter<RC> {
    // Verifies pieces against the blockchain.
    async fn verify_pieces_at_blockchain(
        &self,
        piece_indexes: &[PieceIndex],
        pieces: &FlatPieces,
    ) -> Result<(), PiecesVerificationError> {
        if piece_indexes.len() != pieces.count() {
            return Err(PiecesVerificationError::InvalidRawData);
        }

        let merkle_num_leaves = (self.farmer_protocol_info.recorded_history_segment_size
            / self.farmer_protocol_info.record_size.get()
            * 2) as u64;
        if merkle_num_leaves.is_zero() {
            return Err(PiecesVerificationError::InvalidFarmerProtocolInfo);
        }

        // Calculate segment indexes collection
        let segment_indexes = piece_indexes
            .iter()
            .map(|piece_index| piece_index / merkle_num_leaves)
            .collect::<Vec<_>>();

        // Split segment indexes collection into allowed max sized chunks
        // and run a future records_roots RPC call for each chunk.
        let roots_futures = segment_indexes
            .chunks(MAX_SEGMENT_INDEXES_PER_REQUEST)
            .map(|segment_indexes_chunk| {
                self.verification_client
                    .records_roots(segment_indexes_chunk.to_vec())
            })
            .collect::<Vec<_>>();

        // Wait for all the RPC calls, flatten the results collection,
        // and check for empty result for any of the records root call.
        let roots = try_join_all(roots_futures)
            .await
            .map_err(|err| PiecesVerificationError::RpcError(err))?
            .into_iter()
            .flatten()
            .zip(piece_indexes.iter())
            .map(|(root, piece_index)| {
                if let Some(root) = root {
                    Ok(root)
                } else {
                    error!(piece_index, "No records root found for piece_index.");

                    Err(PiecesVerificationError::NoRecordsRootFound)
                }
            })
            .collect::<Result<Vec<Sha256Hash>, PiecesVerificationError>>()?;

        // Perform an actual piece validity check
        for ((piece, piece_index), root) in pieces.as_pieces().zip(piece_indexes).zip(roots) {
            let position: u64 = piece_index % merkle_num_leaves;

            if !is_piece_valid(
                piece,
                root,
                position as usize,
                self.farmer_protocol_info.record_size.get() as usize,
            ) {
                error!(?piece_index, "Piece validation failed.");

                return Err(PiecesVerificationError::InvalidPieces);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<RC: RpcClient> OnSync for VerifyingPlotter<RC> {
    #[tracing::instrument(parent = &self.span, skip_all)]
    async fn on_pieces(
        &self,
        pieces: FlatPieces,
        piece_indexes: Vec<PieceIndex>,
    ) -> anyhow::Result<()> {
        if self.pieces_verification_enabled {
            self.verify_pieces_at_blockchain(&piece_indexes, &pieces)
                .await?;
        }

        let plotter = self.single_plot_plotter.clone();
        let (farm_creation_start_sender, farm_creation_start_receiver) =
            std::sync::mpsc::sync_channel(1);
        // Makes sure background blocking task below is finished before this function's future is
        // dropped
        let _plot_pieces_guard = CallOnDrop::new(move || {
            let _ = farm_creation_start_receiver.recv();
        });
        tokio::task::spawn_blocking(move || {
            plotter.plot_pieces(PiecesToPlot {
                pieces,
                piece_indexes,
            })?;

            let _ = farm_creation_start_sender.send(());

            Ok(())
        })
        .await?
    }
}
