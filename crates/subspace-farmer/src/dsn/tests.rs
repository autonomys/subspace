use super::{sync, DSNSync, NoSync, PieceIndexHashNumber, SyncOptions};
use crate::bench_rpc_client::{BenchRpcClient, BENCH_FARMER_PROTOCOL_INFO};
use crate::legacy_multi_plots_farm::{LegacyMultiPlotsFarm, Options as MultiFarmingOptions};
use crate::single_plot_farm::PlotFactoryOptions;
use crate::{ObjectMappings, Plot, RpcClient};
use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use num_traits::{WrappingAdd, WrappingSub};
use parking_lot::Mutex;
use rand::Rng;
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{
    ArchivedBlockProgress, FlatPieces, LastArchivedBlock, Piece, PieceIndex, PieceIndexHash,
    RootBlock, Sha256Hash, PIECE_SIZE, U256,
};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::{Config, PiecesToPlot};
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
        .map(|(piece, index)| (PieceIndexHash::from_index(index), (piece, index)))
        .collect::<BTreeMap<_, _>>();
    let result = Arc::new(Mutex::new(BTreeMap::new()));

    sync(
        TestDSN(source.clone()),
        SyncOptions {
            range_size: PieceIndexHashNumber::MAX / 1024,
            public_key: Default::default(),
            max_plot_size: 100 * 1024 * 1024 * 1024,
            total_pieces: 256,
        },
        {
            let result = Arc::clone(&result);
            move |pieces, piece_indexes| {
                let mut result = result.lock();
                result.extend(pieces.as_pieces().zip(piece_indexes).map(|(piece, index)| {
                    (
                        PieceIndexHash::from_index(index),
                        (piece.try_into().unwrap(), index),
                    )
                }));

                Ok(())
            }
        },
    )
    .await
    .unwrap();

    assert_eq!(source, *result.lock());
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
            max_plot_size: 100 * 1024 * 1024 * 1024,
            total_pieces: 0,
        },
        {
            let result = Arc::clone(&result);
            move |pieces, piece_indexes| {
                let mut result = result.lock();
                result.extend(pieces.as_pieces().zip(piece_indexes).map(|(piece, index)| {
                    (
                        PieceIndexHash::from_index(index),
                        (piece.try_into().unwrap(), index),
                    )
                }));
                Ok(())
            }
        },
    )
    .await
    .unwrap();

    assert!(result.lock().is_empty())
}

#[tokio::test]
#[ignore]
async fn test_dsn_sync() {
    let seeder_max_plot_size = 20 * 1024 * 1024 / PIECE_SIZE as u64; // 20M
    let syncer_max_plot_size = 2 * 1024 * 1024 / PIECE_SIZE as u64; // 2M
    let request_pieces_size = 20;

    let seeder_base_directory = TempDir::new().unwrap();

    let (_seeder_slot_info_sender, seeder_slot_info_receiver) = mpsc::channel(10);
    let (mut seeder_archived_segments_sender, seeder_archived_segments_receiver) = mpsc::channel(0);
    let (seeder_acknowledge_archived_segment_sender, _seeder_acknowledge_archived_segment_receiver) =
        mpsc::channel(1);
    let seeder_client = BenchRpcClient::new(
        BENCH_FARMER_PROTOCOL_INFO,
        seeder_slot_info_receiver,
        seeder_archived_segments_receiver,
        seeder_acknowledge_archived_segment_sender,
    );

    let object_mappings = tokio::task::spawn_blocking({
        let path = seeder_base_directory.as_ref().join("object-mappings");

        move || ObjectMappings::open_or_create(path)
    })
    .await
    .unwrap()
    .unwrap();

    let plot_factory = move |options: PlotFactoryOptions<'_>| {
        Plot::open_or_create(
            options.single_plot_farm_id,
            options.plot_directory,
            options.metadata_directory,
            options.public_key,
            options.max_plot_size,
        )
    };

    // Starting the relay server node.
    let (relay_server_node, mut relay_node_runner) = subspace_networking::create(Config {
        listen_on: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        ..Config::with_generated_keypair()
    })
    .await
    .unwrap();

    tokio::spawn(async move {
        relay_node_runner.run().await;
    });

    let seeder_multi_farming = LegacyMultiPlotsFarm::new(
        MultiFarmingOptions {
            base_directory: seeder_base_directory.as_ref().to_owned(),
            farmer_protocol_info: seeder_client.farmer_protocol_info().await.unwrap(),
            archiving_client: seeder_client.clone(),
            farming_client: seeder_client.clone(),
            object_mappings: object_mappings.clone(),
            reward_address: subspace_core_primitives::PublicKey::default(),
            bootstrap_nodes: vec![],
            enable_dsn_sync: false,
            enable_dsn_archiving: false,
            enable_farming: false,
            relay_server_node,
        },
        u64::MAX / 100,
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
            .map(|index| (U256::from(PieceIndexHash::from_index(index)), index))
            .collect::<BTreeMap<_, _>>()
    };

    let (seeder_address_sender, seeder_address_receiver) = oneshot::channel();
    let on_new_listener_handler = seeder_multi_farming.single_plot_farms()[0]
        .node()
        .on_new_listener(Arc::new({
            let seeder_address_sender = Mutex::new(Some(seeder_address_sender));

            move |address| {
                if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                    if let Some(seeder_address_sender) = seeder_address_sender.lock().take() {
                        seeder_address_sender.send(address.clone()).unwrap();
                    }
                }
            }
        }));

    let peer_id = seeder_multi_farming.single_plot_farms()[0]
        .node()
        .id()
        .into();

    let (seeder_multi_farming_finished_sender, seeder_multi_farming_finished_receiver) =
        oneshot::channel();

    tokio::spawn(async move {
        if let Err(error) = seeder_multi_farming.wait().await {
            eprintln!("Seeder exited with error: {error}");
        }

        let _ = seeder_multi_farming_finished_sender.send(());
    });

    let seeder_multiaddr = seeder_address_receiver
        .await
        .unwrap()
        .with(Protocol::P2p(peer_id));
    drop(on_new_listener_handler);

    let syncer_base_directory = TempDir::new().unwrap();
    let (_syncer_slot_info_sender, syncer_slot_info_receiver) = mpsc::channel(10);
    let (_syncer_archived_segments_sender, syncer_archived_segments_receiver) = mpsc::channel(10);
    let (syncer_acknowledge_archived_segment_sender, _syncer_acknowledge_archived_segment_receiver) =
        mpsc::channel(1);
    let syncer_client = BenchRpcClient::new(
        BENCH_FARMER_PROTOCOL_INFO,
        syncer_slot_info_receiver,
        syncer_archived_segments_receiver,
        syncer_acknowledge_archived_segment_sender,
    );

    let object_mappings = tokio::task::spawn_blocking({
        let path = syncer_base_directory.as_ref().join("object-mappings");

        move || ObjectMappings::open_or_create(path)
    })
    .await
    .unwrap()
    .unwrap();

    let plot_factory = move |options: PlotFactoryOptions<'_>| {
        Plot::open_or_create(
            options.single_plot_farm_id,
            options.plot_directory,
            options.metadata_directory,
            options.public_key,
            options.max_plot_size,
        )
    };

    // Starting the relay server node.
    let (relay_server_node, mut relay_node_runner) = subspace_networking::create(Config {
        listen_on: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        ..Config::with_generated_keypair()
    })
    .await
    .unwrap();

    tokio::spawn(async move {
        relay_node_runner.run().await;
    });

    let syncer_multi_farming = LegacyMultiPlotsFarm::new(
        MultiFarmingOptions {
            base_directory: syncer_base_directory.as_ref().to_owned(),
            farmer_protocol_info: {
                let mut farmer_protocol_info = syncer_client.farmer_protocol_info().await.unwrap();
                farmer_protocol_info.max_plot_size = syncer_max_plot_size;
                farmer_protocol_info
            },
            archiving_client: syncer_client.clone(),
            farming_client: syncer_client.clone(),
            object_mappings: object_mappings.clone(),
            reward_address: subspace_core_primitives::PublicKey::default(),
            bootstrap_nodes: vec![seeder_multiaddr.clone()],
            enable_dsn_sync: false,
            enable_dsn_archiving: false,
            enable_farming: false,
            relay_server_node,
        },
        syncer_max_plot_size * PIECE_SIZE as u64,
        plot_factory,
    )
    .await
    .unwrap();
    // HACK: farmer reserves 8% for its own needs, so we need to update piece count here
    let syncer_max_plot_size = syncer_max_plot_size * 92 / 100;

    let range_size = PieceIndexHashNumber::MAX / seeder_max_plot_size * request_pieces_size;
    let plot = syncer_multi_farming.single_plot_farms()[0].plot().clone();
    let dsn_sync = syncer_multi_farming.single_plot_farms()[0].dsn_sync(
        syncer_max_plot_size,
        seeder_max_plot_size,
        range_size,
    );
    let public_key =
        U256::from_be_bytes((*syncer_multi_farming.single_plot_farms()[0].public_key()).into());

    tokio::spawn(async move {
        if let Err(error) = syncer_multi_farming.wait().await {
            eprintln!("Syncer exited with error: {error}");
        }
    });

    dsn_sync.await.unwrap();

    let sync_sector_size = PieceIndexHashNumber::MAX / seeder_max_plot_size * syncer_max_plot_size;
    let expected_start = public_key.wrapping_sub(&(sync_sector_size / 2));
    let expected_end = public_key.wrapping_add(&(sync_sector_size / 2));

    match plot.get_piece_range().unwrap() {
        Some(range) => {
            let (start, end) = (U256::from(*range.start()), U256::from(*range.end()));

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

    drop(syncer_client);

    drop(seeder_archived_segments_sender);
    drop(seeder_client);
    seeder_multi_farming_finished_receiver.await.unwrap();
}
