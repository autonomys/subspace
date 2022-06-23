use crate::bench_rpc_client::BenchRpcClient;
use crate::{utils, WriteToDisk};
use anyhow::anyhow;
use futures::channel::mpsc;
use futures::stream::FuturesUnordered;
use futures::{SinkExt, StreamExt};
use rand::prelude::*;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fmt, io};
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::objects::{PieceObject, PieceObjectMapping};
use subspace_core_primitives::{
    ArchivedBlockProgress, FlatPieces, LastArchivedBlock, PublicKey, RootBlock, Sha256Hash,
    PIECE_SIZE,
};
use subspace_farmer::multi_farming::{MultiFarming, Options as MultiFarmingOptions};
use subspace_farmer::{ObjectMappings, PieceOffset, Plot, PlotFile, RpcClient};
use subspace_rpc_primitives::FarmerMetadata;
use tempfile::TempDir;
use tokio::time::Instant;
use tracing::info;

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

struct HumanReadableSize(pub u64);

impl fmt::Display for HumanReadableSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let suffixes = [
            ("M", 1024 * 1024),
            ("G", 1024 * 1024 * 1024),
            ("T", 1024 * 1024 * 1024 * 1024),
        ];

        let (suffix, divisor) = suffixes
            .iter()
            .copied()
            .find(|(_, divisor)| *divisor * 1024 > self.0)
            .unwrap_or(*suffixes.last().unwrap());

        write!(f, "{:.2}{suffix}", self.0 as f64 / divisor as f64)
    }
}

struct HumanReadableDuration(pub Duration);

impl fmt::Display for HumanReadableDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::fmt::Write;

        // If duration is too small we can just print it as it is
        if self.0 < Duration::from_secs(60) {
            return write!(f, "{:?}", self.0);
        }

        let seconds = self.0.as_secs() % 60;
        let minutes = self.0.as_secs() / 60 % 60;
        let hours = self.0.as_secs() / 60 / 60;
        let mut out = String::new();

        if hours > 0 {
            write!(out, "{hours}h ")?;
        }
        if minutes > 0 {
            write!(out, "{minutes}m ")?;
        }
        if seconds > 0 {
            write!(out, "{seconds}s ")?;
        }

        out.trim_end().fmt(f)
    }
}

const BENCH_FARMER_METADATA: FarmerMetadata = FarmerMetadata {
    record_size: PIECE_SIZE as u32 - 96, // PIECE_SIZE - WITNESS_SIZE
    recorded_history_segment_size: PIECE_SIZE as u32 * 256 / 2, // PIECE_SIZE * MERKLE_NUM_LEAVES / 2
    max_plot_size: 100 * 1024 * 1024 * 1024 / PIECE_SIZE as u64, // 100G
    // Doesn't matter, as we don't start sync
    total_pieces: 0,
};

pub(crate) async fn bench(
    base_directory: PathBuf,
    plot_size: u64,
    max_plot_size: Option<u64>,
    write_to_disk: WriteToDisk,
    write_pieces_size: u64,
    do_recommitments: bool,
) -> anyhow::Result<()> {
    utils::raise_fd_limit();

    let (mut archived_segments_sender, archived_segments_receiver) = mpsc::channel(10);
    let client = BenchRpcClient::new(BENCH_FARMER_METADATA, archived_segments_receiver);

    let base_directory = TempDir::new_in(base_directory)?;

    let metadata = client
        .farmer_metadata()
        .await
        .map_err(|error| anyhow!(error))?;

    let max_plot_size = match max_plot_size.map(|max_plot_size| max_plot_size / PIECE_SIZE as u64) {
        Some(max_plot_size) if max_plot_size > metadata.max_plot_size => {
            tracing::warn!(
                "Passed `max_plot_size` is too big. Fallback to the one from consensus."
            );
            metadata.max_plot_size
        }
        Some(max_plot_size) => max_plot_size,
        None => metadata.max_plot_size,
    };

    info!("Opening object mapping");
    let object_mappings = tokio::task::spawn_blocking({
        let path = base_directory.as_ref().join("object-mappings");

        move || ObjectMappings::open_or_create(path)
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
            archiving_client: client.clone(),
            farming_client: client.clone(),
            object_mappings: object_mappings.clone(),
            reward_address: PublicKey::default(),
            bootstrap_nodes: vec![],
            listen_on: vec![],
            dsn_sync: false,
        },
        plot_size,
        max_plot_size,
        plot_factory,
        false,
    )
    .await?;

    let start = Instant::now();

    let mut last_archived_block = LastArchivedBlock {
        number: 0,
        archived_progress: ArchivedBlockProgress::Partial(0),
    };

    for segment_index in 0..write_pieces_size / PIECE_SIZE as u64 / 256 {
        last_archived_block
            .archived_progress
            .set_partial(segment_index as u32 * 256 * PIECE_SIZE as u32);

        let archived_segment = {
            let root_block = RootBlock::V0 {
                segment_index,
                records_root: Sha256Hash::default(),
                prev_root_block_hash: Sha256Hash::default(),
                last_archived_block,
            };

            let mut pieces = FlatPieces::new(256);
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

    let took = start.elapsed();

    let space_allocated = get_size(base_directory)?;
    let actual_space_pledged = multi_farming
        .single_plot_farms
        .iter()
        .map(|single_plot_farm| single_plot_farm.plot.piece_count())
        .sum::<u64>()
        * PIECE_SIZE as u64;
    let overhead = space_allocated - actual_space_pledged;

    println!("Finished benchmarking.\n");
    println!(
        "{} allocated for farming",
        HumanReadableSize(space_allocated)
    );
    println!(
        "{} actual space pledged (which is {:.2}%)",
        HumanReadableSize(actual_space_pledged),
        (actual_space_pledged * 100) as f64 / space_allocated as f64
    );
    println!(
        "{} of overhead (which is {:.2}%)",
        HumanReadableSize(overhead),
        (overhead * 100) as f64 / space_allocated as f64
    );
    println!("{} plotting time", HumanReadableDuration(took));
    println!(
        "{:.2}M/s average plotting throughput",
        actual_space_pledged as f64 / 1000. / 1000. / took.as_secs_f64()
    );

    if do_recommitments {
        let start = Instant::now();

        let mut tasks = multi_farming
            .single_plot_farms
            .iter()
            .map(|single_plot_farm| {
                (
                    single_plot_farm.commitments.clone(),
                    single_plot_farm.plot.clone(),
                )
            })
            .map(|(commitments, plot)| move || commitments.create(rand::random(), plot))
            .map(tokio::task::spawn_blocking)
            .collect::<FuturesUnordered<_>>();
        while let Some(result) = tasks.next().await {
            if let Err(error) = result {
                tracing::error!(%error, "Discovered error while recommitments bench")
            }
        }

        println!(
            "Recommitment took {}",
            HumanReadableDuration(start.elapsed())
        );
    }

    client.stop().await;
    multi_farming.wait().await?;

    Ok(())
}

fn get_size(path: impl AsRef<Path>) -> std::io::Result<u64> {
    let metadata = std::fs::metadata(&path)?;
    let mut size = metadata.len();
    if metadata.is_dir() {
        for entry in std::fs::read_dir(&path)? {
            size += get_size(entry?.path())?;
        }
    }
    Ok(size)
}

#[cfg(test)]
#[tokio::test]
async fn test_dsn_sync() {
    use std::ops::Range;

    use subspace_farmer::{PieceIndexHashNumber, SyncResult};
    use subspace_networking::libp2p::multiaddr::Protocol;
    use subspace_networking::libp2p::{identity, Multiaddr, PeerId};
    use subspace_networking::NodeRunner;

    let seeder_max_plot_size = 20 * 1024 * 1024 / PIECE_SIZE as u64; // 20M
    let syncer_max_plot_size = 2 * 1024 * 1024 / PIECE_SIZE as u64; // 20M
    let request_pieces_size = 20;

    let seeder_base_directory = TempDir::new().unwrap();
    let mut seeder_multiaddr: Multiaddr = "/ip4/127.0.0.1/tcp/40000".parse().unwrap();

    let (mut seeder_archived_segments_sender, seeder_archived_segments_receiver) =
        mpsc::channel(10);
    let seeder_client =
        BenchRpcClient::new(BENCH_FARMER_METADATA, seeder_archived_segments_receiver);

    let object_mappings = tokio::task::spawn_blocking({
        let path = seeder_base_directory.as_ref().join("object-mappings");

        move || ObjectMappings::open_or_create(path)
    })
    .await
    .unwrap()
    .unwrap();

    let base_path = seeder_base_directory.as_ref().to_owned();
    let plot_factory = move |plot_index, public_key, max_piece_count| {
        let base_path = base_path.join(format!("plot{plot_index}"));
        Plot::open_or_create(base_path, public_key, max_piece_count)
    };

    let mut seeder_multi_farming = MultiFarming::new(
        MultiFarmingOptions {
            base_directory: seeder_base_directory.as_ref().to_owned(),
            archiving_client: seeder_client.clone(),
            farming_client: seeder_client.clone(),
            object_mappings: object_mappings.clone(),
            reward_address: PublicKey::default(),
            bootstrap_nodes: vec![],
            listen_on: vec![seeder_multiaddr.clone()],
            dsn_sync: false,
        },
        seeder_max_plot_size,
        seeder_max_plot_size,
        plot_factory,
        false,
    )
    .await
    .unwrap();

    {
        let mut last_archived_block = LastArchivedBlock {
            number: 0,
            archived_progress: ArchivedBlockProgress::Partial(0),
        };

        for segment_index in 0..seeder_max_plot_size / PIECE_SIZE as u64 / 256 {
            last_archived_block
                .archived_progress
                .set_partial(segment_index as u32 * 256 * PIECE_SIZE as u32);

            let archived_segment = {
                let root_block = RootBlock::V0 {
                    segment_index,
                    records_root: Sha256Hash::default(),
                    prev_root_block_hash: Sha256Hash::default(),
                    last_archived_block,
                };

                let mut pieces = FlatPieces::new(256);
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

            if seeder_archived_segments_sender
                .send(archived_segment)
                .await
                .is_err()
            {
                break;
            }
        }
    }
    seeder_multiaddr.push({
        schnorrkel::PublicKey::from_bytes(
            &*seeder_multi_farming.single_plot_farms[0].plot.public_key(),
        )
        .map(identity::sr25519::PublicKey::from)
        .map(identity::PublicKey::Sr25519)
        .map(PeerId::from)
        .map(Into::into)
        .map(Protocol::P2p)
        .unwrap()
    });

    let mut node_runners = seeder_multi_farming
        .single_plot_farms
        .iter_mut()
        .filter_map(|farming| farming.node_runner.take())
        .map(NodeRunner::run)
        .collect::<FuturesUnordered<_>>();
    let (seeder_wait_sender, seeder_wait_receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        while let Some(()) = node_runners.next().await {
            break;
        }
        seeder_multi_farming.wait().await.unwrap();
        seeder_wait_sender.send(()).unwrap();
    });

    for _ in 0..10 {
        let syncer_base_directory = TempDir::new().unwrap();
        let (_sender, syncer_archived_segments_receiver) = mpsc::channel(10);
        let syncer_client =
            BenchRpcClient::new(BENCH_FARMER_METADATA, syncer_archived_segments_receiver);

        info!("Opening object mapping");
        let object_mappings = tokio::task::spawn_blocking({
            let path = syncer_base_directory.as_ref().join("object-mappings");

            move || ObjectMappings::open_or_create(path)
        })
        .await
        .unwrap()
        .unwrap();

        let base_path = syncer_base_directory.as_ref().to_owned();
        let plot_factory = move |plot_index, public_key, max_piece_count| {
            let base_path = base_path.join(format!("plot{plot_index}"));
            Plot::open_or_create(base_path, public_key, max_piece_count)
        };

        let mut syncer_multi_farming = MultiFarming::new(
            MultiFarmingOptions {
                base_directory: syncer_base_directory.as_ref().to_owned(),
                archiving_client: syncer_client.clone(),
                farming_client: syncer_client.clone(),
                object_mappings: object_mappings.clone(),
                reward_address: PublicKey::default(),
                bootstrap_nodes: vec![seeder_multiaddr.clone()],
                listen_on: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                dsn_sync: false,
            },
            syncer_max_plot_size,
            syncer_max_plot_size,
            plot_factory,
            false,
        )
        .await
        .unwrap();

        let mut node_runners = syncer_multi_farming
            .single_plot_farms
            .iter_mut()
            .filter_map(|farming| farming.node_runner.take())
            .map(NodeRunner::run)
            .collect::<FuturesUnordered<_>>();
        let (syncer_wait_sender, syncer_wait_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            while let Some(()) = node_runners.next().await {
                break;
            }
            syncer_wait_sender.send(()).unwrap();
        });

        let expected_total_pieces = seeder_max_plot_size;
        let range_size = PieceIndexHashNumber::MAX / expected_total_pieces * request_pieces_size;
        let mut futures = syncer_multi_farming
            .single_plot_farms
            .iter()
            .map(|farming| {
                farming.dsn_sync(syncer_max_plot_size, expected_total_pieces, range_size)
            })
            .collect::<FuturesUnordered<_>>();

        while let Some(result) = futures.next().await {
            let SyncResult {
                expected_range:
                    Range {
                        start: expected_start,
                        end: expected_end,
                    },
                got_range: Range { start, end },
                total_pieces,
            } = result.unwrap();

            assert!(Range {
                start: expected_start * 9 / 10,
                end: expected_start * 11 / 10,
            }
            .contains(&start));
            assert!(Range {
                start: expected_end * 9 / 10,
                end: expected_end * 11 / 10,
            }
            .contains(&end));
            assert!(Range {
                start: total_pieces * 9 / 10,
                end: total_pieces * 11 / 10,
            }
            .contains(&total_pieces));
        }

        syncer_client.stop().await;
        syncer_multi_farming.wait().await.unwrap();
        syncer_wait_receiver.await.unwrap();
    }

    seeder_client.stop().await;
    seeder_wait_receiver.await.unwrap();
}
