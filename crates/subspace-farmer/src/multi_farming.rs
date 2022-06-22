use crate::single_plot_farm::SinglePlotFarm;
use crate::{
    plotting, Archiving, Commitments, Farming, Identity, ObjectMappings, Plot, PlotError, RpcClient,
};
use anyhow::anyhow;
use futures::stream::{FuturesOrdered, FuturesUnordered, StreamExt};
use parking_lot::Mutex;
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::{PieceIndexHash, PublicKey, PIECE_SIZE};
use subspace_networking::libp2p::identity::sr25519;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::{Multiaddr, PeerId};
use subspace_networking::multimess::MultihashCode;
use subspace_networking::{
    libp2p, Config, PiecesByRangeRequest, PiecesByRangeResponse, PiecesToPlot,
};
use subspace_solving::SubspaceCodec;
use tracing::info;

const SYNC_PIECES_AT_ONCE: u64 = 5000;

// TODO: tie `plots`, `commitments`, `farmings`, ``networking_node_runners` together as they always
// will have the same length.
/// Abstraction around having multiple `Plot`s, `Farming`s and `Plotting`s.
///
/// It is needed because of the limit of a single plot size from the consensus
/// (`pallet_subspace::MaxPlotSize`) in order to support any amount of disk space from user.
pub struct MultiFarming {
    pub single_plot_farms: Vec<SinglePlotFarm>,
    archiving: Archiving,
    networking_node_runners: Vec<subspace_networking::NodeRunner>,
}

fn get_plot_sizes(total_plot_size: u64, max_plot_size: u64) -> Vec<u64> {
    // TODO: we need to remember plot size in order to prune unused plots in future if plot size is
    // less than it was specified before.
    // TODO: Piece count should account for database overhead of various additional databases
    // For now assume 92% will go for plot itself
    let total_plot_size = total_plot_size * 92 / 100 / PIECE_SIZE as u64;

    let plot_sizes =
        std::iter::repeat(max_plot_size).take((total_plot_size / max_plot_size) as usize);
    if total_plot_size / max_plot_size == 0 || total_plot_size % max_plot_size > max_plot_size / 2 {
        plot_sizes
            .chain(std::iter::once(total_plot_size % max_plot_size))
            .collect::<Vec<_>>()
    } else {
        plot_sizes.collect()
    }
}

/// Options for `MultiFarming` creation
pub struct Options<C> {
    pub base_directory: PathBuf,
    /// Client used for archiving subscriptions
    pub archiving_client: C,
    /// Independent client used for farming, such that it is not blocked by archiving
    pub farming_client: C,
    pub object_mappings: ObjectMappings,
    pub reward_address: PublicKey,
    pub bootstrap_nodes: Vec<Multiaddr>,
    pub listen_on: Vec<Multiaddr>,
    pub dsn_sync: bool,
}

impl MultiFarming {
    /// Starts multiple farmers with any plot sizes which user gives
    pub async fn new<C: RpcClient>(
        Options {
            base_directory,
            archiving_client,
            farming_client,
            object_mappings,
            reward_address,
            bootstrap_nodes,
            listen_on,
            dsn_sync,
        }: Options<C>,
        total_plot_size: u64,
        max_plot_size: u64,
        new_plot: impl Fn(usize, PublicKey, u64) -> Result<Plot, PlotError> + Clone + Send + 'static,
        start_farmings: bool,
    ) -> anyhow::Result<Self> {
        let plot_sizes = get_plot_sizes(total_plot_size, max_plot_size);

        let mut single_plot_farms = Vec::with_capacity(plot_sizes.len());
        let mut networking_node_runners = Vec::with_capacity(plot_sizes.len());

        let first_listen_on: Arc<Mutex<Option<Vec<Multiaddr>>>> = Arc::default();

        let mut results = plot_sizes
            .into_iter()
            .enumerate()
            .map(|(plot_index, max_plot_pieces)| {
                let base_directory = base_directory.to_owned();
                let farming_client = farming_client.clone();
                let new_plot = new_plot.clone();
                let mut listen_on = listen_on.clone();
                let mut bootstrap_nodes = bootstrap_nodes.clone();
                let first_listen_on = Arc::clone(&first_listen_on);

                tokio::task::spawn_blocking(move || {
                    let base_directory = base_directory.join(format!("plot{plot_index}"));
                    std::fs::create_dir_all(&base_directory)?;

                    let identity = Identity::open_or_create(&base_directory)?;
                    let public_key = identity.public_key().to_bytes().into();

                    // TODO: This doesn't account for the fact that node can
                    // have a completely different history to what farmer expects
                    info!("Opening plot");
                    let plot = new_plot(plot_index, public_key, max_plot_pieces)?;

                    info!("Opening commitments");
                    let plot_commitments = Commitments::new(base_directory.join("commitments"))?;

                    // Start the farming task
                    let farming = start_farmings.then(|| {
                        Farming::start(
                            plot.clone(),
                            plot_commitments.clone(),
                            farming_client.clone(),
                            identity.clone(),
                            reward_address,
                        )
                    });

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
                                        .map(|listen_on| {
                                            listen_on.with(Protocol::P2p(peer_id.into()))
                                        })
                                        .collect(),
                                );
                            }
                        }
                    }

                    Ok::<_, anyhow::Error>((
                        identity,
                        plot,
                        plot_commitments,
                        farming,
                        listen_on,
                        bootstrap_nodes,
                    ))
                })
            })
            .collect::<FuturesOrdered<_>>();

        while let Some(result) = results.next().await {
            let (identity, plot, plot_commitments, farming, listen_on, bootstrap_nodes) =
                result.expect("Plot and farming never fails")?;

            let subspace_codec = SubspaceCodec::new(&plot.public_key());
            let (node, node_runner) = subspace_networking::create(Config {
                bootstrap_nodes,
                // TODO: Do we still need it?
                value_getter: Arc::new({
                    let plot = plot.clone();
                    let subspace_codec = subspace_codec.clone();
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
                                subspace_codec
                                    .decode(&mut piece, piece_index)
                                    .ok()
                                    .map(move |()| piece)
                            })
                            .map(|piece| piece.to_vec())
                    }
                }),
                pieces_by_range_request_handler: Arc::new({
                    let plot = plot.clone();
                    let subspace_codec = subspace_codec.clone();

                    // TODO: also ask for how many pieces to read
                    move |&PiecesByRangeRequest { from, to }| {
                        let mut pieces_and_indexes =
                            plot.get_sequential_pieces(from, SYNC_PIECES_AT_ONCE).ok()?;
                        let next_piece_index_hash = if let Some(idx) = pieces_and_indexes
                            .iter()
                            .position(|(piece_index, _)| PieceIndexHash::from(*piece_index) >= to)
                        {
                            pieces_and_indexes.truncate(idx);
                            None
                        } else {
                            pieces_and_indexes
                                .pop()
                                .map(|(index, _)| Some(PieceIndexHash::from(index)))
                                .unwrap_or_default()
                        };

                        let (piece_indexes, pieces) = pieces_and_indexes
                            .into_iter()
                            .flat_map(|(index, mut piece)| {
                                subspace_codec.decode(&mut piece, index).ok()?;
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
            })
            .await?;

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

            single_plot_farms.push(SinglePlotFarm {
                codec: subspace_codec,
                plot,
                commitments: plot_commitments,
                farming,
                node,
            });
            networking_node_runners.push(node_runner);
        }

        let farmer_metadata = farming_client
            .farmer_metadata()
            .await
            .map_err(|error| anyhow!(error))?;
        let max_plot_size = farmer_metadata.max_plot_size;
        let total_pieces = farmer_metadata.total_pieces;

        // Start syncing
        if dsn_sync {
            tokio::spawn({
                let mut futures = single_plot_farms
                    .iter()
                    .map(|single_plot_farm| single_plot_farm.dsn_sync(max_plot_size, total_pieces))
                    .collect::<FuturesUnordered<_>>();

                async move {
                    while let Some(result) = futures.next().await {
                        result?;
                    }

                    info!("Sync done");

                    Ok::<_, anyhow::Error>(())
                }
            });
        }

        // Start archiving task
        let archiving = Archiving::start(farmer_metadata, object_mappings, archiving_client, {
            let mut on_pieces_to_plots = single_plot_farms
                .iter()
                .map(|single_plot_farm| {
                    plotting::plot_pieces(
                        single_plot_farm.codec.clone(),
                        &single_plot_farm.plot,
                        single_plot_farm.commitments.clone(),
                    )
                })
                .collect::<Vec<_>>();

            move |pieces_to_plot| {
                on_pieces_to_plots
                    .par_iter_mut()
                    .map(|on_pieces_to_plot| {
                        // TODO: It might be desirable to not clone it and instead pick just
                        //  unnecessary pieces and copy pieces once since different plots will
                        //  care about different pieces
                        on_pieces_to_plot(pieces_to_plot.clone())
                    })
                    .reduce(|| true, |result, should_continue| result && should_continue)
            }
        })
        .await?;

        Ok(Self {
            single_plot_farms,
            archiving,
            networking_node_runners,
        })
    }

    /// Waits for farming and plotting completion (or errors)
    pub async fn wait(self) -> anyhow::Result<()> {
        if !self
            .single_plot_farms
            .iter()
            .any(|single_plot_farm| single_plot_farm.farming.is_some())
        {
            return self.archiving.wait().await.map_err(Into::into);
        }

        let mut farming = self
            .single_plot_farms
            .into_iter()
            .filter_map(|single_plot_farm| {
                let farming = single_plot_farm.farming?;
                Some(farming.wait())
            })
            .collect::<FuturesUnordered<_>>();
        let mut node_runners = self
            .networking_node_runners
            .into_iter()
            .map(|node_runner| async move { node_runner.run().await })
            .collect::<FuturesUnordered<_>>();

        tokio::select! {
            res = farming.select_next_some() => {
                res?;
            },
            () = node_runners.select_next_some() => {},
            res = self.archiving.wait() => {
                res?;
            },
        }

        Ok(())
    }
}
