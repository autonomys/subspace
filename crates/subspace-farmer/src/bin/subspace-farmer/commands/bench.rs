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
use subspace_farmer::bench_rpc_client::{BenchRpcClient, BENCH_FARMER_PROTOCOL_INFO};
use subspace_farmer::legacy_multi_plots_farm::{
    LegacyMultiPlotsFarm, Options as MultiFarmingOptions,
};
use subspace_farmer::single_plot_farm::PlotFactoryOptions;
use subspace_farmer::{LegacyObjectMappings, PieceOffset, Plot, PlotFile, RpcClient};
use subspace_rpc_primitives::SlotInfo;
use tempfile::TempDir;
use tokio::time::Instant;
use tracing::{info, warn};

#[derive(Default)]
pub struct BenchPlotMock;

impl PlotFile for BenchPlotMock {
    fn write(&mut self, _pieces: impl AsRef<[u8]>, _offset: PieceOffset) -> io::Result<()> {
        Ok(())
    }

    fn read(&mut self, _offset: PieceOffset, mut buf: impl AsMut<[u8]>) -> io::Result<()> {
        rand::thread_rng().fill(buf.as_mut());
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

pub(crate) async fn bench(
    base_directory: PathBuf,
    plot_size: u64,
    max_plot_size: Option<u64>,
    write_to_disk: WriteToDisk,
    write_pieces_size: u64,
    do_recommitments: bool,
) -> anyhow::Result<()> {
    utils::raise_fd_limit();

    let (mut slot_info_sender, slot_info_receiver) = mpsc::channel(1);
    let (mut archived_segments_sender, archived_segments_receiver) = mpsc::channel(1);
    let (acknowledge_archived_segment_sender, mut acknowledge_archived_segment_receiver) =
        mpsc::channel(1);
    let client = BenchRpcClient::new(
        BENCH_FARMER_PROTOCOL_INFO,
        slot_info_receiver,
        archived_segments_receiver,
        acknowledge_archived_segment_sender,
    );

    let base_directory = TempDir::new_in(base_directory)?;

    let mut farmer_protocol_info = client
        .farmer_protocol_info()
        .await
        .map_err(|error| anyhow!(error))?;

    if let Some(max_plot_size) = max_plot_size {
        if max_plot_size > farmer_protocol_info.max_plot_size {
            warn!("Passed `max_plot_size` is too big. Fallback to the one from consensus.");
        } else {
            farmer_protocol_info.max_plot_size = max_plot_size;
        }
    }

    info!("Opening object mapping");
    let object_mappings = tokio::task::spawn_blocking({
        let path = base_directory.as_ref().join("object-mappings");

        move || LegacyObjectMappings::open_or_create(path)
    })
    .await??;

    let plot_factory = move |options: PlotFactoryOptions<'_>| match write_to_disk {
        WriteToDisk::Nothing => Plot::with_plot_file(
            options.single_plot_farm_id,
            BenchPlotMock::default(),
            options.metadata_directory,
            options.public_key,
            options.max_plot_size,
        ),
        WriteToDisk::Everything => Plot::open_or_create(
            options.single_plot_farm_id,
            options.plot_directory,
            options.metadata_directory,
            options.public_key,
            options.max_plot_size,
        ),
    };

    let multi_farming = LegacyMultiPlotsFarm::new(
        MultiFarmingOptions {
            base_directory: base_directory.as_ref().to_owned(),
            farmer_protocol_info,
            archiving_client: client.clone(),
            farming_client: client.clone(),
            object_mappings: object_mappings.clone(),
            reward_address: PublicKey::default(),
            bootstrap_nodes: vec![],
            listen_on: vec![],
            enable_dsn_archiving: false,
            enable_dsn_sync: false,
            enable_farming: true,
        },
        plot_size,
        plot_factory,
    )
    .await?;

    if do_recommitments {
        slot_info_sender
            .send(SlotInfo {
                slot_number: 0,
                global_challenge: [0; 32],
                salt: [0; 8],
                next_salt: None,
                solution_range: 0,
                voting_solution_range: 0,
            })
            .await
            .unwrap();
    }

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

        if let Err(error) = archived_segments_sender.send(archived_segment).await {
            eprintln!("Failed to send archived segment: {}", error);
            break;
        }

        if acknowledge_archived_segment_receiver.next().await.is_none() {
            eprintln!("Failed to receive archiving acknowledgement");
            break;
        }
    }
    drop(archived_segments_sender);

    let took = start.elapsed();

    let space_allocated = get_size(base_directory)?;
    let actual_space_pledged = multi_farming
        .single_plot_farms()
        .iter()
        .map(|single_plot_farm| single_plot_farm.plot().piece_count())
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
            .single_plot_farms()
            .iter()
            .map(|single_plot_farm| {
                (
                    single_plot_farm.commitments().clone(),
                    single_plot_farm.plot().clone(),
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

    drop(client);
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
