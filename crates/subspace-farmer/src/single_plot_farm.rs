use crate::commitments::Commitments;
use crate::dsn;
use crate::dsn::{PieceIndexHashNumber, SyncOptions};
use crate::farming::Farming;
use crate::identity::Identity;
use crate::plot::{Plot, PlotError};
use crate::plotting::plot_pieces;
use crate::rpc_client::RpcClient;
use parking_lot::Mutex;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::{PieceIndexHash, PublicKey};
use subspace_networking::libp2p::identity::sr25519;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::{Multiaddr, PeerId};
use subspace_networking::multimess::MultihashCode;
use subspace_networking::{
    libp2p, Config, Node, NodeRunner, PiecesByRangeRequest, PiecesByRangeResponse, PiecesToPlot,
};
use subspace_solving::SubspaceCodec;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tracing::{error, info};

const SYNC_PIECES_AT_ONCE: u64 = 5000;

#[derive(Debug, Clone)]
pub struct SinglePlotPlotter {
    codec: SubspaceCodec,
    plot: Plot,
    commitments: Commitments,
}

impl SinglePlotPlotter {
    fn new(codec: SubspaceCodec, plot: Plot, commitments: Commitments) -> Self {
        Self {
            codec,
            plot,
            commitments,
        }
    }

    /// Plot specified pieces in this farm, potentially replacing some of existing pieces
    pub fn plot_pieces(&self, pieces_to_plot: &PiecesToPlot) {
        let PiecesToPlot {
            piece_indexes,
            mut pieces,
        } = pieces_to_plot.clone();
        if let Err(error) = self.codec.batch_encode(&mut pieces, &piece_indexes) {
            error!(%error, "Failed to encode pieces");
            return;
        }

        let pieces = Arc::new(pieces);

        match self.plot.write_many(Arc::clone(&pieces), piece_indexes) {
            Ok(write_result) => {
                if let Err(error) = self
                    .commitments
                    .remove_pieces(write_result.evicted_pieces())
                {
                    error!(%error, "Failed to remove old commitments for pieces");
                }

                if let Err(error) = self
                    .commitments
                    .create_for_pieces(|| write_result.to_recommitment_iterator())
                {
                    error!(%error, "Failed to create commitments for pieces");
                }
            }
            Err(error) => {
                error!(%error, "Failed to write encoded pieces")
            }
        }
    }
}

pub(crate) struct SinglePlotFarmOptions<C, NewPlot>
where
    C: RpcClient,
    NewPlot: Fn(usize, PublicKey, u64) -> Result<Plot, PlotError> + Clone + Send + 'static,
{
    pub(crate) base_directory: PathBuf,
    pub(crate) plot_index: usize,
    pub(crate) max_plot_pieces: u64,
    pub(crate) max_plot_size: u64,
    pub(crate) total_pieces: u64,
    pub(crate) farming_client: C,
    pub(crate) new_plot: NewPlot,
    pub(crate) listen_on: Vec<Multiaddr>,
    pub(crate) bootstrap_nodes: Vec<Multiaddr>,
    pub(crate) first_listen_on: Arc<Mutex<Option<Vec<Multiaddr>>>>,
    pub(crate) enable_farming: bool,
    pub(crate) reward_address: PublicKey,
    pub(crate) enable_dsn_sync: bool,
}

/// Single plot farm abstraction is a container for everything necessary to plot/farm with a single
/// disk plot.
// TODO: Make fields private
pub struct SinglePlotFarm {
    public_key: PublicKey,
    pub(crate) codec: SubspaceCodec,
    pub plot: Plot,
    pub commitments: Commitments,
    pub(crate) farming: Option<Farming>,
    pub(crate) node: Node,
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
            base_directory,
            plot_index,
            max_plot_pieces,
            max_plot_size,
            total_pieces,
            farming_client,
            new_plot,
            mut listen_on,
            mut bootstrap_nodes,
            first_listen_on,
            enable_farming,
            reward_address,
            enable_dsn_sync,
        }: SinglePlotFarmOptions<C, NewPlot>,
    ) -> anyhow::Result<(Self, NodeRunner)>
    where
        C: RpcClient,
        NewPlot: Fn(usize, PublicKey, u64) -> Result<Plot, PlotError> + Clone + Send + 'static,
    {
        std::fs::create_dir_all(&base_directory)?;

        let identity = Identity::open_or_create(&base_directory)?;
        let public_key = identity.public_key().to_bytes().into();

        // TODO: This doesn't account for the fact that node can
        // have a completely different history to what farmer expects
        info!("Opening plot");
        let plot = new_plot(plot_index, public_key, max_plot_pieces)?;

        info!("Opening commitments");
        let commitments = Commitments::new(base_directory.join("commitments"))?;

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
                    plot.read(piece_index)
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
                        .position(|(piece_index, _)| PieceIndexHash::from(*piece_index) > to)
                    {
                        pieces_and_indexes.truncate(idx);
                        None
                    } else if pieces_and_indexes.len() == 1 {
                        None
                    } else {
                        pieces_and_indexes
                            .pop()
                            .map(|(index, _)| PieceIndexHash::from(index))
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
            node,
            background_task_handles: vec![],
        };

        // Start syncing
        if enable_dsn_sync {
            // TODO: operate with number of pieces to fetch, instead of range calculations
            let sync_range_size = PieceIndexHashNumber::MAX / total_pieces * 1024; // 4M per stream
            let dsn_sync_fut = farm.dsn_sync(max_plot_size, total_pieces, sync_range_size);

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

        Ok((farm, node_runner))
    }

    /// Public key associated with this farm
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get plotter for this plot
    pub fn get_plotter(&self) -> SinglePlotPlotter {
        SinglePlotPlotter::new(
            self.codec.clone(),
            self.plot.clone(),
            self.commitments.clone(),
        )
    }

    pub(crate) fn dsn_sync(
        &self,
        max_plot_size: u64,
        total_pieces: u64,
        range_size: PieceIndexHashNumber,
    ) -> impl Future<Output = anyhow::Result<()>> {
        let commitments = self.commitments.clone();
        let codec = self.codec.clone();
        let node = self.node.clone();

        let options = SyncOptions {
            range_size,
            public_key: self.public_key,
            max_plot_size,
            total_pieces,
        };
        let mut plot_pieces = plot_pieces(codec, &self.plot, commitments);

        dsn::sync(node, options, move |pieces, piece_indexes| {
            if !plot_pieces(PiecesToPlot {
                pieces,
                piece_indexes,
            }) {
                return Err(anyhow::anyhow!("Failed to plot pieces in archiving"));
            }
            Ok(())
        })
    }
}
