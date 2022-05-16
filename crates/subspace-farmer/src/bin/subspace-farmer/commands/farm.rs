use anyhow::{anyhow, Result};
use jsonrpsee::ws_server::WsServerBuilder;
use rand::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::{io, mem};
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::objects::{PieceObject, PieceObjectMapping};
use subspace_core_primitives::{
    ArchivedBlockProgress, FlatPieces, LastArchivedBlock, PublicKey, RootBlock, Sha256Hash,
    PIECE_SIZE,
};
use subspace_farmer::multi_farming::{MultiFarming, Options as MultiFarmingOptions};
use subspace_farmer::ws_rpc_server::{RpcServer, RpcServerImpl};
use subspace_farmer::{
    retrieve_piece_from_plots, NodeRpcClient, ObjectMappings, PieceOffset, Plot, PlotFile,
    RpcClient,
};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::multihash::Multihash;
use subspace_networking::multimess::MultihashCode;
use subspace_networking::Config;
use subspace_rpc_primitives::FarmerMetadata;
use tempfile::TempDir;
use tracing::{debug, info, warn};

use crate::bench_rpc_client::BenchRpcClient;
use crate::{FarmingArgs, WriteToDisk};

pub struct BenchPlotMock {
    piece_count: u64,
    max_piece_count: u64,
}

impl BenchPlotMock {
    pub fn new(max_piece_count: u64) -> Self {
        Self {
            max_piece_count,
            piece_count: 0,
        }
    }
}

impl PlotFile for BenchPlotMock {
    fn piece_count(&mut self) -> io::Result<u64> {
        Ok(self.piece_count)
    }

    fn write(&mut self, pieces: impl AsRef<[u8]>, _offset: PieceOffset) -> io::Result<()> {
        self.piece_count = (self.piece_count + (pieces.as_ref().len() / PIECE_SIZE) as u64)
            .max(self.max_piece_count);
        Ok(())
    }

    fn read(&mut self, _offset: PieceOffset, mut buf: impl AsMut<[u8]>) -> io::Result<()> {
        rand::thread_rng().fill(buf.as_mut());
        Ok(())
    }

    fn sync_all(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn raise_fd_limit() {
    match std::panic::catch_unwind(fdlimit::raise_fd_limit) {
        Ok(Some(new_limit)) => info!(new_limit, "Increase file limit from soft to hard"),
        Ok(None) => debug!("Failed to increase file limit"),
        Err(err) => {
            let err = if let Some(err) = err.downcast_ref::<&str>() {
                *err
            } else if let Some(err) = err.downcast_ref::<String>() {
                err
            } else {
                unreachable!("Should be unreachable as `fdlimit` uses panic macro, which should return either `&str` or `String`.")
            };
            warn!(err, "Failed to increase file limit")
        }
    }
}

/// Start farming by using multiple replica plot in specified path and connecting to WebSocket
/// server at specified address.
pub(crate) async fn farm(
    FarmingArgs {
        bootstrap_nodes,
        custom_path,
        listen_on,
        node_rpc_url,
        mut ws_server_listen_addr,
        reward_address,
        plot_size,
        max_plot_size,
    }: FarmingArgs,
    best_block_number_check_interval: Duration,
) -> Result<(), anyhow::Error> {
    raise_fd_limit();

    let base_directory = crate::utils::get_path(custom_path);

    info!("Connecting to node at {}", node_rpc_url);
    let client = NodeRpcClient::new(&node_rpc_url).await?;

    let metadata = client
        .farmer_metadata()
        .await
        .map_err(|error| anyhow!(error))?;

    let max_plot_size = match max_plot_size.map(|max_plot_size| max_plot_size / PIECE_SIZE as u64) {
        Some(max_plot_size) if max_plot_size > metadata.max_plot_size => {
            warn!("Passed `max_plot_size` is too big. Fallback to the one from consensus.");
            metadata.max_plot_size
        }
        Some(max_plot_size) => max_plot_size,
        None => metadata.max_plot_size,
    };

    let FarmerMetadata {
        record_size,
        recorded_history_segment_size,
        ..
    } = metadata;

    info!("Opening object mapping");
    let object_mappings = tokio::task::spawn_blocking({
        let base_directory = base_directory.clone();

        move || ObjectMappings::open_or_create(&base_directory)
    })
    .await??;

    let multi_farming = MultiFarming::new(
        MultiFarmingOptions {
            base_directory: base_directory.clone(),
            client,
            object_mappings: object_mappings.clone(),
            reward_address,
            best_block_number_check_interval,
        },
        plot_size,
        max_plot_size,
        move |plot_index, public_key, max_piece_count| {
            Plot::open_or_create(
                base_directory.join(format!("plot{plot_index}")),
                public_key,
                max_piece_count,
            )
        },
        true,
    )
    .await?;

    // Start RPC server
    let ws_server = match WsServerBuilder::default()
        .build(ws_server_listen_addr)
        .await
    {
        Ok(ws_server) => ws_server,
        Err(jsonrpsee::core::Error::Transport(ref error)) => {
            warn!(
                address = %ws_server_listen_addr,
                error = %error,
                "Failed to start WebSocket RPC server on, trying random port"
            );
            ws_server_listen_addr.set_port(0);
            WsServerBuilder::default()
                .build(ws_server_listen_addr)
                .await?
        }
        Err(error) => {
            return Err(error.into());
        }
    };
    let ws_server_addr = ws_server.local_addr()?;
    let rpc_server = RpcServerImpl::new(
        record_size,
        recorded_history_segment_size,
        Arc::clone(&multi_farming.plots),
        object_mappings.clone(),
    );
    let _stop_handle = ws_server.start(rpc_server.into_rpc())?;

    info!("WS RPC server listening on {ws_server_addr}");

    let (node, mut node_runner) = subspace_networking::create(Config {
        bootstrap_nodes,
        listen_on,
        value_getter: Arc::new({
            let plots = Arc::clone(&multi_farming.plots);

            move |key| networking_getter(&plots, key)
        }),
        allow_non_globals_in_dht: true,
        // TODO: Persistent identity
        ..Config::with_generated_keypair()
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

    tokio::spawn(async move {
        info!("Starting subspace network node instance");

        node_runner.run().await;
    });

    multi_farming.wait().await
}

const BENCH_FARMER_METADATA: FarmerMetadata = FarmerMetadata {
    record_size: PIECE_SIZE as u32 - 96, // PIECE_SIZE - WITNESS_SIZE
    recorded_history_segment_size: PIECE_SIZE as u32 * 256 / 2, // PIECE_SIZE * MERKLE_NUM_LEAVES / 2
    max_plot_size: 100 * 1024 * 1024 * 1024 / PIECE_SIZE as u64, // 100G
};

pub(crate) async fn bench(
    custom_path: Option<PathBuf>,
    plot_size: u64,
    max_plot_size: Option<u64>,
    best_block_number_check_interval: Duration,
    write_to_disk: WriteToDisk,
    write_pieces_size: u64,
) -> anyhow::Result<()> {
    raise_fd_limit();

    let (archived_segments_sender, archived_segments_receiver) = tokio::sync::mpsc::channel(10);
    let client = BenchRpcClient::new(BENCH_FARMER_METADATA, archived_segments_receiver);

    let base_directory = crate::utils::get_path(custom_path);
    let base_directory = TempDir::new_in(base_directory)?;

    let metadata = client
        .farmer_metadata()
        .await
        .map_err(|error| anyhow!(error))?;

    let max_plot_size = match max_plot_size.map(|max_plot_size| max_plot_size / PIECE_SIZE as u64) {
        Some(max_plot_size) if max_plot_size > metadata.max_plot_size => {
            warn!("Passed `max_plot_size` is too big. Fallback to the one from consensus.");
            metadata.max_plot_size
        }
        Some(max_plot_size) => max_plot_size,
        None => metadata.max_plot_size,
    };

    info!("Opening object mapping");
    let object_mappings = tokio::task::spawn_blocking({
        let base_directory = base_directory.as_ref().to_owned();
        move || ObjectMappings::open_or_create(&base_directory)
    })
    .await??;

    let base_path = base_directory.as_ref().to_owned();
    let plot_factory = move |plot_index, public_key, max_piece_count| {
        let base_path = base_path.join(format!("plot{plot_index}"));
        match write_to_disk {
            WriteToDisk::Nothing => Plot::with_plot_file(
                BenchPlotMock::new(max_piece_count),
                base_path,
                public_key,
                max_piece_count,
            ),
            WriteToDisk::Everything => Plot::open_or_create(base_path, public_key, max_piece_count),
        }
    };

    let multi_farming = MultiFarming::new(
        MultiFarmingOptions {
            base_directory: base_directory.as_ref().to_owned(),
            client: client.clone(),
            object_mappings: object_mappings.clone(),
            reward_address: PublicKey::default(),
            best_block_number_check_interval,
        },
        plot_size,
        max_plot_size,
        plot_factory,
        false,
    )
    .await?;

    tokio::spawn(async move {
        let mut last_archived_block = LastArchivedBlock {
            number: 0,
            archived_progress: ArchivedBlockProgress::Partial(0),
        };

        for segment_index in 0..write_pieces_size / PIECE_SIZE as u64 / 1000 {
            last_archived_block
                .archived_progress
                .set_partial(segment_index as u32 * 1000 * PIECE_SIZE as u32);

            let archived_segment = {
                let root_block = RootBlock::V0 {
                    segment_index,
                    records_root: Sha256Hash::default(),
                    prev_root_block_hash: Sha256Hash::default(),
                    last_archived_block,
                };

                let mut pieces = FlatPieces::new(1000);
                rand::thread_rng().fill(pieces.as_mut());

                let objects = std::iter::repeat_with(|| PieceObject::V0 {
                    hash: rand::random(),
                    offset: rand::random(),
                })
                .take(100)
                .collect();

                ArchivedSegment {
                    root_block,
                    pieces,
                    object_mapping: vec![PieceObjectMapping { objects }],
                }
            };

            if archived_segments_sender
                .send(archived_segment)
                .await
                .is_err()
            {
                break;
            }
        }
    })
    .await?;

    client.stop().await;

    multi_farming.wait().await?;

    Ok(())
}

fn networking_getter(plots: &[Plot], key: &Multihash) -> Option<Vec<u8>> {
    let code = key.code();

    if code != u64::from(MultihashCode::Piece) && code != u64::from(MultihashCode::PieceIndex) {
        return None;
    }

    let piece_index = u64::from_le_bytes(key.digest()[..mem::size_of::<u64>()].try_into().ok()?);

    retrieve_piece_from_plots(plots, piece_index)
        .expect("Decoding of local pieces must never fail")
        .map(|piece| piece.to_vec())
}
