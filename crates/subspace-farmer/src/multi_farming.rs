use crate::dsn::{self, NoSync, PieceIndexHashNumber, SyncOptions};
use crate::{
    plotting, Archiving, Commitments, Farming, Identity, ObjectMappings, Plot, PlotError, RpcClient,
};
use anyhow::anyhow;
use futures::stream::{FuturesOrdered, FuturesUnordered, StreamExt};
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::{PublicKey, PIECE_SIZE};
use subspace_networking::libp2p::identity::sr25519;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::multimess::MultihashCode;
use subspace_networking::{Config, PiecesToPlot};
use subspace_solving::SubspaceCodec;
use tracing::info;

// TODO: tie `plots`, `commitments`, `farmings`, ``networking_node_runners` together as they always
// will have the same length.
/// Abstraction around having multiple `Plot`s, `Farming`s and `Plotting`s.
///
/// It is needed because of the limit of a single plot size from the consensus
/// (`pallet_subspace::MaxPlotSize`) in order to support any amount of disk space from user.
pub struct MultiFarming {
    pub plots: Arc<Vec<Plot>>,
    pub commitments: Vec<Commitments>,
    farmings: Vec<Farming>,
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
            mut bootstrap_nodes,
            listen_on,
        }: Options<C>,
        total_plot_size: u64,
        max_plot_size: u64,
        new_plot: impl Fn(usize, PublicKey, u64) -> Result<Plot, PlotError> + Clone + Send + 'static,
        start_farmings: bool,
    ) -> anyhow::Result<Self> {
        let plot_sizes = get_plot_sizes(total_plot_size, max_plot_size);

        let mut plots = Vec::with_capacity(plot_sizes.len());
        let mut commitments = Vec::with_capacity(plot_sizes.len());
        let mut farmings = Vec::with_capacity(plot_sizes.len());
        let mut networking_node_runners = Vec::with_capacity(plot_sizes.len());
        let mut codecs = Vec::with_capacity(plot_sizes.len());

        let mut results = plot_sizes
            .into_iter()
            .enumerate()
            .map(|(plot_index, max_plot_pieces)| {
                let base_directory = base_directory.to_owned();
                let farming_client = farming_client.clone();
                let new_plot = new_plot.clone();

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

                    Ok::<_, anyhow::Error>((identity, plot, plot_commitments, farming))
                })
            })
            .collect::<FuturesOrdered<_>>()
            .enumerate();

        while let Some((i, result)) = results.next().await {
            let (identity, plot, plot_commitments, farming) =
                result.expect("Plot and farming never fails")?;

            let mut listen_on = listen_on.clone();

            for multiaddr in &mut listen_on {
                if let Some(Protocol::Tcp(starting_port)) = multiaddr.pop() {
                    multiaddr.push(Protocol::Tcp(starting_port + i as u16));
                } else {
                    return Err(anyhow::anyhow!("Unknown protocol {}", multiaddr));
                }
            }

            let subspace_codec = SubspaceCodec::new(&plot.public_key());
            let (node, node_runner) = subspace_networking::create(Config {
                bootstrap_nodes: bootstrap_nodes.clone(),
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
                allow_non_globals_in_dht: true,
                listen_on: listen_on.clone(),
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

            bootstrap_nodes.extend(
                listen_on
                    .into_iter()
                    .map(|listen_on| listen_on.with(Protocol::P2p(node.id().into()))),
            );
            networking_node_runners.push(node_runner);
            plots.push(plot);
            commitments.push(plot_commitments);
            codecs.push(subspace_codec);
            if let Some(farming) = farming {
                farmings.push(farming);
            }
        }

        let farmer_metadata = farming_client
            .farmer_metadata()
            .await
            .map_err(|error| anyhow!(error))?;
        let max_plot_size = farmer_metadata.max_plot_size;
        let total_pieces = farmer_metadata.total_pieces;

        // Start syncing
        // TODO: Unlock once infinite loop (https://github.com/subspace/subspace/issues/598) is fixed
        if false {
            tokio::spawn({
                let plots = plots.clone();
                let commitments = commitments.clone();
                let codecs = codecs.clone();
                async move {
                    let dsn = NoSync;

                    let mut futures = plots
                        .into_iter()
                        .zip(commitments)
                        .zip(codecs)
                        .map(|((plot, commitments), codec)| {
                            let options = SyncOptions {
                                range_size: PieceIndexHashNumber::MAX / 1024,
                                public_key: plot.public_key(),
                                max_plot_size,
                                total_pieces,
                            };
                            let mut plot_pieces = plotting::plot_pieces(codec, &plot, commitments);

                            dsn::sync(dsn, options, move |pieces, piece_indexes| {
                                if !plot_pieces(PiecesToPlot {
                                    pieces,
                                    piece_indexes,
                                }) {
                                    return Err(anyhow::anyhow!(
                                        "Failed to plot pieces in archiving"
                                    ));
                                }
                                Ok(())
                            })
                        })
                        .collect::<FuturesUnordered<_>>();
                    while let Some(result) = futures.next().await {
                        result?;
                    }

                    tracing::info!("Sync done");

                    Ok::<_, anyhow::Error>(())
                }
            });
        }

        // Start archiving task
        let archiving = Archiving::start(farmer_metadata, object_mappings, archiving_client, {
            let mut on_pieces_to_plots = plots
                .iter()
                .zip(&commitments)
                .zip(codecs.clone())
                .map(|((plot, commitments), codec)| {
                    plotting::plot_pieces(codec, plot, commitments.clone())
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
            plots: Arc::new(plots),
            commitments,
            farmings,
            archiving,
            networking_node_runners,
        })
    }

    /// Waits for farming and plotting completion (or errors)
    pub async fn wait(self) -> anyhow::Result<()> {
        if self.farmings.is_empty() {
            return self.archiving.wait().await.map_err(Into::into);
        }

        let mut farming = self
            .farmings
            .into_iter()
            .map(|farming| farming.wait())
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
