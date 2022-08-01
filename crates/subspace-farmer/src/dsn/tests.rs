use super::{sync, DSNSync, NoSync, PieceIndexHashNumber, PiecesToPlot, SyncOptions};
use crate::bench_rpc_client::{BenchRpcClient, BENCH_FARMER_PROTOCOL_INFO};
use crate::legacy_multi_plots_farm::{LegacyMultiPlotsFarm, Options as MultiFarmingOptions};
use crate::single_plot_farm::PlotFactoryOptions;
use crate::{LegacyObjectMappings, Plot};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use num_traits::{WrappingAdd, WrappingSub};
use parking_lot::Mutex;
use rand::Rng;
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{
    bidirectional_distance, ArchivedBlockProgress, FlatPieces, LastArchivedBlock, Piece,
    PieceIndex, PieceIndexHash, RootBlock, Sha256Hash, PIECE_SIZE, U256,
};
use subspace_networking::libp2p::multiaddr::Protocol;
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

#[tokio::test(flavor = "multi_thread")]
async fn test_dsn_sync() {
    init();

    let seeder_max_plot_size = 20 * 1024 * 1024; // 20M
    let seeder_max_piece_count = seeder_max_plot_size / PIECE_SIZE as u64;
    let syncer_max_plot_size = 2 * 1024 * 1024; // 2M
    let pieces_per_request = 20;

    let seeder_base_directory = TempDir::new().unwrap();

    let (_slot_info_sender, slot_info_receiver) = mpsc::channel(0);
    let (mut archived_segments_sender, archived_segments_receiver) = mpsc::channel(0);
    let (acknowledge_archived_segment_sender, mut acknowledge_archived_segment_receiver) =
        mpsc::channel(0);
    let farmer_protocol_info = {
        let mut farmer_protocol_info = BENCH_FARMER_PROTOCOL_INFO;
        farmer_protocol_info.total_pieces = seeder_max_piece_count;
        farmer_protocol_info
    };
    let rpc_client = BenchRpcClient::new(
        farmer_protocol_info,
        slot_info_receiver,
        archived_segments_receiver,
        acknowledge_archived_segment_sender,
    );

    let object_mappings = tokio::task::spawn_blocking({
        let path = seeder_base_directory.as_ref().join("object-mappings");

        move || LegacyObjectMappings::open_or_create(path)
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

    let seeder_multi_farming = LegacyMultiPlotsFarm::new(
        MultiFarmingOptions {
            base_directory: seeder_base_directory.as_ref().to_owned(),
            farmer_protocol_info,
            archiving_client: rpc_client.clone(),
            farming_client: rpc_client.clone(),
            object_mappings: object_mappings.clone(),
            reward_address: subspace_core_primitives::PublicKey::default(),
            listen_on: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap_nodes: vec![],
            enable_dsn_sync: false,
            enable_dsn_archiving: false,
            enable_farming: false,
            relay_server_node: None,
        },
        seeder_max_plot_size,
        plot_factory,
    )
    .await
    .unwrap();

    let seeder_plot = seeder_multi_farming.single_plot_farms()[0].plot().clone();
    let seeder_node = seeder_multi_farming.single_plot_farms()[0].node().clone();
    let seeder_public_key = *seeder_multi_farming.single_plot_farms()[0].public_key();

    tokio::spawn(async move {
        if let Err(error) = seeder_multi_farming.wait().await {
            eprintln!("Seeder exited with error: {error}");
        }
    });

    let (seeder_address_sender, seeder_address_receiver) = oneshot::channel();
    let seeder_address_sender = Arc::new(Mutex::new(Some(seeder_address_sender)));

    let on_new_listener_handler = seeder_node.on_new_listener(Arc::new({
        let seeder_address_sender = Arc::clone(&seeder_address_sender);

        move |address| {
            if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                if let Some(seeder_address_sender) = seeder_address_sender.lock().take() {
                    seeder_address_sender.send(address.clone()).unwrap();
                }
            }
        }
    }));

    for address in seeder_node.listeners() {
        if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
            if let Some(seeder_address_sender) = seeder_address_sender.lock().take() {
                seeder_address_sender.send(address.clone()).unwrap();
            }
        }
    }

    let seeder_multiaddr = seeder_address_receiver
        .await
        .unwrap()
        .with(Protocol::P2p(seeder_node.id().into()));

    drop(on_new_listener_handler);

    let piece_index_hashes = {
        let pieces_per_segment = u64::from(
            farmer_protocol_info.recorded_history_segment_size / farmer_protocol_info.record_size
                * 2,
        );

        let mut last_archived_block = LastArchivedBlock {
            number: 0,
            archived_progress: ArchivedBlockProgress::Partial(0),
        };
        let number_of_segments = seeder_max_piece_count / pieces_per_segment;

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

            archived_segments_sender
                .send(archived_segment)
                .await
                .unwrap();
            acknowledge_archived_segment_receiver.next().await.unwrap();
            last_archived_block.set_complete();
        }

        (0..number_of_segments * pieces_per_segment)
            .map(|index| (U256::from(PieceIndexHash::from_index(index)), index))
            .collect::<BTreeMap<_, _>>()
    };

    // Acknowledgements are sent optimistically, wait for everything to be actually plotted
    for _ in 0..20 {
        if seeder_max_piece_count == seeder_plot.piece_count() {
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut syncer_base_directory = TempDir::new().unwrap();
    let plot_factory = move |options: PlotFactoryOptions<'_>| {
        Plot::open_or_create(
            options.single_plot_farm_id,
            options.plot_directory,
            options.metadata_directory,
            options.public_key,
            options.max_plot_size,
        )
    };

    let syncer_multi_farming = loop {
        {
            let object_mappings = tokio::task::spawn_blocking({
                let path = syncer_base_directory.as_ref().join("object-mappings");

                move || LegacyObjectMappings::open_or_create(path)
            })
            .await
            .unwrap()
            .unwrap();

            let syncer_multi_farming = LegacyMultiPlotsFarm::new(
                MultiFarmingOptions {
                    base_directory: syncer_base_directory.as_ref().to_owned(),
                    farmer_protocol_info,
                    archiving_client: rpc_client.clone(),
                    farming_client: rpc_client.clone(),
                    object_mappings: object_mappings.clone(),
                    reward_address: subspace_core_primitives::PublicKey::default(),
                    bootstrap_nodes: vec![seeder_multiaddr.clone()],
                    listen_on: vec![],
                    enable_dsn_sync: false,
                    enable_dsn_archiving: false,
                    enable_farming: false,
                    relay_server_node: None,
                },
                syncer_max_plot_size,
                plot_factory,
            )
            .await
            .unwrap();

            let syncer_public_key = *syncer_multi_farming.single_plot_farms()[0].public_key();

            // Make sure seeder and syncer are close enough to each other
            if bidirectional_distance(
                &U256::from_be_bytes(seeder_public_key.into()),
                &U256::from_be_bytes(syncer_public_key.into()),
            ) < U256::MAX / U256::from(seeder_max_plot_size / syncer_max_plot_size)
            {
                break syncer_multi_farming;
            }
        }

        // Remove old directory so that everything is deleted and identity re-created
        syncer_base_directory = TempDir::new().unwrap();
    };

    let syncer_max_piece_count = syncer_max_plot_size / PIECE_SIZE as u64;

    let range_size = PieceIndexHashNumber::MAX / seeder_max_piece_count * pieces_per_request;
    let plot = syncer_multi_farming.single_plot_farms()[0].plot().clone();
    let dsn_sync = syncer_multi_farming.single_plot_farms()[0].dsn_sync(
        syncer_max_plot_size,
        seeder_max_piece_count,
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

            if piece_index_hashes.len() as u64 > syncer_max_piece_count {
                let expected_piece_count = piece_index_hashes.range(start..=end).count() as u64;
                assert_eq!(
                    plot.piece_count(),
                    expected_piece_count,
                    "Synced wrong number of pieces"
                );
                assert_eq!(
                    plot.piece_count(),
                    syncer_max_piece_count,
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
}
