pub mod dsn_archiving;
#[cfg(test)]
mod tests;

use crate::commitments::Commitments;
use crate::dsn::{PieceIndexHashNumber, SyncOptions};
use crate::farming::Farming;
use crate::identity::Identity;
use crate::plot::{Plot, PlotError};
use crate::rpc_client::RpcClient;
use crate::single_plot_farm::dsn_archiving::start_archiving;
use crate::ws_rpc_server::PieceGetter;
use crate::{dsn, CommitmentError, ObjectMappings};
use futures::future::try_join;
use parking_lot::Mutex;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::{NPieces, Piece, PieceIndex, PieceIndexHash, PublicKey};
use subspace_networking::libp2p::identity::sr25519;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::{Multiaddr, PeerId};
use subspace_networking::multimess::MultihashCode;
use subspace_networking::{
    libp2p, Config, Node, NodeRunner, PiecesByRangeRequest, PiecesByRangeResponse, PiecesToPlot,
};
use subspace_rpc_primitives::FarmerMetadata;
use subspace_solving::{BatchEncodeError, SubspaceCodec};
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tracing::{error, info, trace, warn};

const SYNC_PIECES_AT_ONCE: u64 = 5000;

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
    Plot(#[from] std::io::Error),
    /// Commitments error
    #[error("Commitment error: {0}")]
    Commitment(#[from] CommitmentError),
}

#[derive(Debug, Clone)]
pub struct SinglePlotPlotter {
    codec: SubspaceCodec,
    plot: Plot,
    commitments: Commitments,
}

impl SinglePlotPlotter {
    fn new(codec: SubspaceCodec, weak_plot: Plot, commitments: Commitments) -> Self {
        Self {
            codec,
            plot: weak_plot,
            commitments,
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

        let write_result = self.plot.write_many(Arc::clone(&pieces), piece_indexes)?;

        self.commitments
            .remove_pieces(write_result.evicted_pieces())?;

        self.commitments
            .create_for_pieces(|| write_result.to_recommitment_iterator())
            .map_err(Into::into)
    }
}

pub(crate) struct SinglePlotFarmOptions<C, NewPlot>
where
    C: RpcClient,
    NewPlot: Fn(usize, PublicKey, NPieces) -> Result<Plot, PlotError> + Clone + Send + 'static,
{
    pub(crate) metadata_directory: PathBuf,
    pub(crate) plot_index: usize,
    pub(crate) max_plot_pieces: NPieces,
    pub(crate) farmer_metadata: FarmerMetadata,
    pub(crate) farming_client: C,
    pub(crate) plot_factory: NewPlot,
    pub(crate) listen_on: Vec<Multiaddr>,
    pub(crate) bootstrap_nodes: Vec<Multiaddr>,
    pub(crate) first_listen_on: Arc<Mutex<Option<Vec<Multiaddr>>>>,
    pub(crate) enable_farming: bool,
    pub(crate) reward_address: PublicKey,
    pub(crate) enable_dsn_archiving: bool,
    pub(crate) enable_dsn_sync: bool,
}

/// Single plot farm abstraction is a container for everything necessary to plot/farm with a single
/// disk plot.
// TODO: Make fields private
#[must_use = "Farm does not function properly unless run() method is called"]
pub struct SinglePlotFarm {
    public_key: PublicKey,
    codec: SubspaceCodec,
    plot: Plot,
    pub commitments: Commitments,
    farming: Option<Farming>,
    node: Node,
    node_runner: NodeRunner,
    background_task_handles: Vec<JoinHandle<()>>,
}

impl Drop for SinglePlotFarm {
    fn drop(&mut self) {
        for handle in &self.background_task_handles {
            handle.abort();
        }
    }
}

impl SinglePlotFarm {
    pub(crate) fn new<C, NewPlot>(
        SinglePlotFarmOptions {
            metadata_directory,
            plot_index,
            max_plot_pieces,
            farmer_metadata,
            farming_client,
            plot_factory,
            mut listen_on,
            mut bootstrap_nodes,
            first_listen_on,
            enable_farming,
            reward_address,
            enable_dsn_archiving,
            enable_dsn_sync,
        }: SinglePlotFarmOptions<C, NewPlot>,
    ) -> anyhow::Result<Self>
    where
        C: RpcClient,
        NewPlot: Fn(usize, PublicKey, NPieces) -> Result<Plot, PlotError> + Clone + Send + 'static,
    {
        std::fs::create_dir_all(&metadata_directory)?;

        let identity = Identity::open_or_create(&metadata_directory)?;
        let public_key = identity.public_key().to_bytes().into();

        // TODO: This doesn't account for the fact that node can
        // have a completely different history to what farmer expects
        info!("Opening plot");
        let plot = plot_factory(plot_index, public_key, max_plot_pieces)?;

        info!("Opening object mappings");
        let object_mappings =
            ObjectMappings::open_or_create(metadata_directory.join("object-mappings"))?;

        info!("Opening commitments");
        let commitments = Commitments::new(metadata_directory.join("commitments"))?;

        for multiaddr in &mut listen_on {
            if let Some(Protocol::Tcp(starting_port)) = multiaddr.pop() {
                multiaddr.push(Protocol::Tcp(starting_port + plot_index as u16));
            } else {
                return Err(anyhow::anyhow!("Unknown protocol {}", multiaddr));
            }
        }
        {
            let mut first_listen_on = first_listen_on.lock();
            // Only add the first instance to bootstrap nodes of others
            match first_listen_on.as_ref() {
                Some(first_listen_on) => {
                    bootstrap_nodes.extend_from_slice(first_listen_on);
                }
                None => {
                    let public_key = sr25519::PublicKey::from(*identity.public_key());
                    let public_key = libp2p::identity::PublicKey::Sr25519(public_key);
                    let peer_id = PeerId::from(public_key);

                    first_listen_on.replace(
                        listen_on
                            .clone()
                            .into_iter()
                            .map(|listen_on| listen_on.with(Protocol::P2p(peer_id.into())))
                            .collect(),
                    );
                }
            }
        }

        let codec = SubspaceCodec::new_with_gpu(public_key.as_ref());
        let create_networking_fut = subspace_networking::create(Config {
            bootstrap_nodes,
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

                    let piece_index = u64::from_le_bytes(
                        key.digest()[..std::mem::size_of::<u64>()].try_into().ok()?,
                    );
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
            pieces_by_range_request_handler: Arc::new({
                let plot = plot.clone();
                let codec = codec.clone();

                // TODO: also ask for how many pieces to read
                move |&PiecesByRangeRequest { from, to }| {
                    let mut pieces_and_indexes =
                        plot.get_sequential_pieces(from, SYNC_PIECES_AT_ONCE).ok()?;

                    let next_piece_index_hash = if let Some(idx) = pieces_and_indexes
                        .iter()
                        .position(|(piece_index, _)| PieceIndexHash::from_index(*piece_index) > to)
                    {
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
            allow_non_globals_in_dht: true,
            listen_on,
            ..Config::with_keypair(sr25519::Keypair::from(
                sr25519::SecretKey::from_bytes(identity.secret_key().to_bytes())
                    .expect("Always valid"),
            ))
        });

        let (node, node_runner) = Handle::current().block_on(create_networking_fut)?;

        node.on_new_listener(Arc::new({
            let node_id = node.id();

            move |multiaddr| {
                info!(
                    "Listening on {}",
                    multiaddr.clone().with(Protocol::P2p(node_id.into()))
                );
            }
        }))
        .detach();

        // Start the farming task
        let farming = enable_farming.then(|| {
            Farming::start(
                plot.clone(),
                commitments.clone(),
                farming_client,
                identity,
                reward_address,
            )
        });

        let mut farm = Self {
            public_key,
            codec,
            plot,
            commitments,
            farming,
            node: node.clone(),
            node_runner,
            background_task_handles: vec![],
        };

        // Start DSN archiving
        if enable_dsn_archiving {
            let archiving_fut = start_archiving(
                farmer_metadata.record_size,
                farmer_metadata.recorded_history_segment_size,
                object_mappings,
                node,
                farm.plotter(),
            );
            let dsn_archiving_handle = tokio::spawn(async move {
                if let Err(error) = archiving_fut.await {
                    error!(%error, "DSN archiving task has ended with error");
                } else {
                    warn!("DSN archiving task has finished");
                }
            });

            farm.background_task_handles.push(dsn_archiving_handle);
        }

        // Start DSN syncing
        if enable_dsn_sync {
            // TODO: operate with number of pieces to fetch, instead of range calculations
            let sync_range_size = PieceIndexHashNumber::MAX / *farmer_metadata.total_pieces * 1024; // 4M per stream
            let dsn_sync_fut = farm.dsn_sync(
                farmer_metadata.max_plot_size,
                farmer_metadata.total_pieces,
                sync_range_size,
            );

            let dsn_sync_handle = tokio::spawn(async move {
                match dsn_sync_fut.await {
                    Ok(()) => {
                        info!("DSN sync done successfully");
                    }
                    Err(error) => {
                        error!(?error, "DSN sync failed");
                    }
                }
            });

            farm.background_task_handles.push(dsn_sync_handle);
        }

        Ok(farm)
    }

    /// Public key associated with this farm
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Access plot instance of the farm
    pub fn plot(&self) -> &Plot {
        &self.plot
    }

    /// Access network node instance of the farm
    pub fn node(&self) -> &Node {
        &self.node
    }

    pub fn piece_getter(&self) -> SinglePlotPieceGetter {
        SinglePlotPieceGetter::new(self.codec.clone(), self.plot.clone())
    }

    /// Plotter for this plot
    pub fn plotter(&self) -> SinglePlotPlotter {
        SinglePlotPlotter::new(
            self.codec.clone(),
            self.plot.clone(),
            self.commitments.clone(),
        )
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        if let Some(farming) = self.farming.as_mut() {
            try_join(farming.wait(), async {
                (&mut self.node_runner).run().await;

                Ok(())
            })
            .await?;
        } else {
            self.node_runner.run().await;
        }

        Ok(())
    }

    pub(crate) fn dsn_sync(
        &self,
        max_plot_size: NPieces,
        total_pieces: NPieces,
        range_size: PieceIndexHashNumber,
    ) -> impl Future<Output = anyhow::Result<()>> {
        let options = SyncOptions {
            range_size,
            public_key: self.public_key,
            max_plot_size,
            total_pieces,
        };

        let single_plot_plotter = self.plotter();

        dsn::sync(self.node.clone(), options, move |pieces, piece_indexes| {
            single_plot_plotter
                .plot_pieces(PiecesToPlot {
                    pieces,
                    piece_indexes,
                })
                .map_err(Into::into)
        })
    }
}
