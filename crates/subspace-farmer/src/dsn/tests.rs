use super::{sync, DSNSync, NoSync, PieceIndexHashNumber, SyncOptions};
use crate::bench_rpc_client::{BenchRpcClient, BENCH_FARMER_METADATA};
use crate::legacy_multi_plots_farm::{LegacyMultiPlotsFarm, Options as MultiFarmingOptions};
use crate::{ObjectMappings, Plot};
use futures::{SinkExt, StreamExt};
use num_traits::{WrappingAdd, WrappingSub};
use rand::Rng;
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::{Arc, Mutex};
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{
    ArchivedBlockProgress, FlatPieces, LastArchivedBlock, Piece, PieceIndex, PieceIndexHash,
    RootBlock, Sha256Hash, PIECE_SIZE, U256,
};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::PiecesToPlot;
use tempfile::TempDir;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TestDSN(BTreeMap<PieceIndexHash, (Piece, PieceIndex)>);

#[async_trait::async_trait]
impl DSNSync for TestDSN {
    type Stream = futures::stream::Once<futures::future::Ready<PiecesToPlot>>;
    type Error = std::convert::Infallible;

    async fn get_pieces(
        &mut self,
        Range { start, end }: Range<PieceIndexHash>,
    ) -> Result<Self::Stream, Self::Error> {
        let (pieces, piece_indexes) = self
            .0
            .iter()
            .skip_while(|(k, _)| **k < start)
            .take_while(|(k, _)| **k <= end)
            .fold(
                (Vec::<u8>::new(), Vec::<PieceIndex>::new()),
                |(mut flat_pieces, mut piece_indexes), (_, (piece, index))| {
                    flat_pieces.extend(piece.iter());
                    piece_indexes.push(*index);
                    (flat_pieces, piece_indexes)
                },
            );
        Ok(futures::stream::once(futures::future::ready(
            PiecesToPlot {
                pieces: pieces.try_into().unwrap(),
                piece_indexes,
            },
        )))
    }
}

fn init() {
    let _ = tracing_subscriber::fmt::try_init();
}

#[tokio::test(flavor = "multi_thread")]
async fn simple_test() {
    init();

    let source = (0u8..=255u8)
        .map(|i| {
            let mut piece = Piece::default();
            rand::thread_rng().fill(&mut piece[..]);
            (piece, i as PieceIndex)
        })
        .map(|(piece, index)| (index.into(), (piece, index)))
        .collect::<BTreeMap<_, _>>();
    let result = Arc::new(Mutex::new(BTreeMap::new()));

    sync(
        TestDSN(source.clone()),
        SyncOptions {
            range_size: PieceIndexHashNumber::MAX / 1024,
            public_key: Default::default(),
            max_plot_size: 100 * 1024 * 1024 * 1024 / PIECE_SIZE as u64,
            total_pieces: 256,
        },
        {
            let result = Arc::clone(&result);
            move |pieces, piece_indexes| {
                let mut result = result.lock().unwrap();
                result.extend(
                    pieces
                        .as_pieces()
                        .zip(piece_indexes)
                        .map(|(piece, index)| (index.into(), (piece.try_into().unwrap(), index))),
                );

                Ok(())
            }
        },
    )
    .await
    .unwrap();

    assert_eq!(source, *result.lock().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn no_sync_test() {
    init();

    let result = Arc::new(Mutex::new(
        BTreeMap::<PieceIndexHash, (Piece, PieceIndex)>::new(),
    ));

    sync(
        NoSync,
        SyncOptions {
            range_size: PieceIndexHashNumber::MAX / 1024,
            public_key: Default::default(),
            max_plot_size: 100 * 1024 * 1024 * 1024 / PIECE_SIZE as u64,
            total_pieces: 0,
        },
        {
            let result = Arc::clone(&result);
            move |pieces, piece_indexes| {
                let mut result = result.lock().unwrap();
                result.extend(
                    pieces
                        .as_pieces()
                        .zip(piece_indexes)
                        .map(|(piece, index)| (index.into(), (piece.try_into().unwrap(), index))),
                );
                Ok(())
            }
        },
    )
    .await
    .unwrap();

    assert!(result.lock().unwrap().is_empty())
}

#[tokio::test]
#[ignore]
async fn test_dsn_sync() {
    let seeder_max_plot_size = 20 * 1024 * 1024 / PIECE_SIZE as u64; // 20M
    let syncer_max_plot_size = 2 * 1024 * 1024 / PIECE_SIZE as u64; // 2M
    let request_pieces_size = 20;

    let seeder_base_directory = TempDir::new().unwrap();

    let (mut seeder_archived_segments_sender, seeder_archived_segments_receiver) =
        futures::channel::mpsc::channel(0);
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

    let mut seeder_multi_farming = LegacyMultiPlotsFarm::new(
        MultiFarmingOptions {
            base_directory: seeder_base_directory.as_ref().to_owned(),
            archiving_client: seeder_client.clone(),
            farming_client: seeder_client.clone(),
            object_mappings: object_mappings.clone(),
            reward_address: subspace_core_primitives::PublicKey::default(),
            bootstrap_nodes: vec![],
            listen_on: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            enable_dsn_sync: false,
            enable_dsn_archiving: false,
            enable_farming: false,
        },
        u64::MAX / 100,
        u64::MAX,
        plot_factory,
    )
    .await
    .unwrap();

    let piece_index_hashes = {
        let pieces_per_segment = 256;

        let mut last_archived_block = LastArchivedBlock {
            number: 0,
            archived_progress: ArchivedBlockProgress::Partial(0),
        };
        let number_of_segments = seeder_max_plot_size / pieces_per_segment;

        for segment_index in 0..number_of_segments {
            let archived_segment = {
                let root_block = RootBlock::V0 {
                    segment_index,
                    records_root: Sha256Hash::default(),
                    prev_root_block_hash: Sha256Hash::default(),
                    last_archived_block,
                };

                let pieces = FlatPieces::new(pieces_per_segment as usize);

                ArchivedSegment {
                    root_block,
                    pieces,
                    object_mapping: vec![],
                }
            };

            seeder_archived_segments_sender
                .send(archived_segment)
                .await
                .unwrap();
            last_archived_block.set_complete();
        }

        (0..number_of_segments * pieces_per_segment)
            .map(|index| (U256::from_big_endian(&PieceIndexHash::from(index).0), index))
            .collect::<BTreeMap<_, _>>()
    };

    let (seeder_address_sender, mut seeder_address_receiver) = futures::channel::mpsc::unbounded();
    seeder_multi_farming.single_plot_farms[0]
        .node
        .on_new_listener(Arc::new(move |address| {
            let _ = seeder_address_sender.unbounded_send(address.clone());
        }))
        .detach();
    let mut node_runner = std::mem::take(&mut seeder_multi_farming.networking_node_runners)
        .into_iter()
        .next()
        .unwrap();
    tokio::spawn(async move {
        node_runner.run().await;
    });
    let seeder_multiaddr = seeder_address_receiver
        .next()
        .await
        .unwrap()
        .with(Protocol::P2p(
            seeder_multi_farming.single_plot_farms[0].node.id().into(),
        ));
    drop(seeder_address_receiver);

    let syncer_base_directory = TempDir::new().unwrap();
    let (_sender, syncer_archived_segments_receiver) = futures::channel::mpsc::channel(10);
    let syncer_client =
        BenchRpcClient::new(BENCH_FARMER_METADATA, syncer_archived_segments_receiver);

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

    let mut syncer_multi_farming = LegacyMultiPlotsFarm::new(
        MultiFarmingOptions {
            base_directory: syncer_base_directory.as_ref().to_owned(),
            archiving_client: syncer_client.clone(),
            farming_client: syncer_client.clone(),
            object_mappings: object_mappings.clone(),
            reward_address: subspace_core_primitives::PublicKey::default(),
            bootstrap_nodes: vec![seeder_multiaddr.clone()],
            listen_on: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            enable_dsn_sync: false,
            enable_dsn_archiving: false,
            enable_farming: false,
        },
        syncer_max_plot_size * PIECE_SIZE as u64,
        syncer_max_plot_size,
        plot_factory,
    )
    .await
    .unwrap();
    // HACK: farmer reserves 8% for its own needs, so we need to update piece count here
    let syncer_max_plot_size = syncer_max_plot_size * 92 / 100;

    let mut node_runner = std::mem::take(&mut syncer_multi_farming.networking_node_runners)
        .into_iter()
        .next()
        .unwrap();
    tokio::spawn(async move {
        node_runner.run().await;
    });

    let range_size = PieceIndexHashNumber::MAX / seeder_max_plot_size * request_pieces_size;
    let plot = syncer_multi_farming.single_plot_farms[0].plot.clone();
    syncer_multi_farming.single_plot_farms[0]
        .dsn_sync(syncer_max_plot_size, seeder_max_plot_size, range_size)
        .await
        .unwrap();

    let sync_sector_size = PieceIndexHashNumber::MAX / seeder_max_plot_size * syncer_max_plot_size;
    let public_key = U256::from_big_endian(
        syncer_multi_farming.single_plot_farms[0]
            .public_key()
            .as_ref(),
    );
    let expected_start = public_key.wrapping_sub(&(sync_sector_size / 2));
    let expected_end = public_key.wrapping_add(&(sync_sector_size / 2));
    match plot.get_piece_range().unwrap() {
        Some(range) => {
            let (start, end) = (
                U256::from_big_endian(&range.start().0),
                U256::from_big_endian(&range.end().0),
            );

            let shift_to_middle =
                |n: U256, pub_key| n.wrapping_sub(pub_key).wrapping_add(&U256::MIDDLE);

            let expected_start = shift_to_middle(expected_start, &public_key);
            let expected_end = shift_to_middle(expected_end, &public_key);
            let start = shift_to_middle(start, &public_key);
            let end = shift_to_middle(end, &public_key);
            let piece_index_hashes = piece_index_hashes
                .iter()
                .map(|(&index_hash, index)| (shift_to_middle(index_hash, &public_key), index))
                .filter(|(index_hash, _)| (expected_start..expected_end).contains(index_hash))
                .collect::<BTreeMap<_, _>>();

            assert!((expected_start..expected_end).contains(&start));
            assert!((expected_start..expected_end).contains(&end));

            if piece_index_hashes.len() as u64 > syncer_max_plot_size {
                let expected_piece_count = piece_index_hashes.range(start..=end).count() as u64;
                assert_eq!(
                    plot.piece_count(),
                    expected_piece_count,
                    "Synced wrong number of pieces"
                );
                assert_eq!(
                    plot.piece_count(),
                    syncer_max_plot_size,
                    "Didn't sync all that we need"
                );
            } else {
                let got_range_piece_count = piece_index_hashes.range(start..=end).count();
                let expected_range_piece_count = piece_index_hashes.len();
                assert_eq!(
                    got_range_piece_count, expected_range_piece_count,
                    "Didn't sync all that we need"
                );
                assert_eq!(
                    plot.piece_count(),
                    expected_range_piece_count as u64,
                    "Synced wrong number of pieces"
                );
            }
        }
        None => assert_eq!(
            piece_index_hashes
                .range(expected_start..expected_end)
                .count(),
            0
        ),
    };

    syncer_client.stop().await;

    drop(seeder_archived_segments_sender);
    seeder_client.stop().await;
    seeder_multi_farming.wait().await.unwrap();
}
