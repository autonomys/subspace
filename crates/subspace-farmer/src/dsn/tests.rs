use crate::dsn::{sync, DSNSync, NoSync, OnSync, PieceIndexHashNumber, SyncOptions};
use crate::rpc_client::bench_rpc_client::{BenchRpcClient, BENCH_FARMER_PROTOCOL_INFO};
use crate::single_disk_farm::{SingleDiskFarm, SingleDiskFarmOptions};
use crate::single_plot_farm::PlotFactoryOptions;
use crate::{dsn, Plot};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, Stream, StreamExt};
use num_traits::{WrappingAdd, WrappingSub};
use parking_lot::Mutex;
use rand::Rng;
use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{
    bidirectional_distance, crypto, ArchivedBlockProgress, Blake2b256Hash, FlatPieces,
    LastArchivedBlock, Piece, PieceIndex, PieceIndexHash, RootBlock, PIECE_SIZE, U256,
};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::{
    BootstrappedNetworkingParameters, Config, PeerInfo, PeerInfoRequestHandler, PeerInfoResponse,
    PeerSyncStatus, PiecesByRangeRequest, PiecesByRangeRequestHandler, PiecesByRangeResponse,
    PiecesToPlot,
};
use subspace_rpc_primitives::FarmerProtocolInfo;
use tempfile::TempDir;
use tracing::Span;

struct TestPlotter {
    pub(crate) result: Arc<Mutex<BTreeMap<PieceIndexHash, (Piece, PieceIndex)>>>,
}

#[async_trait::async_trait]
impl OnSync for TestPlotter {
    async fn on_pieces(
        &self,
        pieces: FlatPieces,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<()> {
        let mut result = self.result.lock();
        result.extend(pieces.as_pieces().zip(piece_indices).map(|(piece, index)| {
            (
                PieceIndexHash::from_index(index),
                (piece.try_into().unwrap(), index),
            )
        }));

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TestDSN(BTreeMap<PieceIndexHash, (Piece, PieceIndex)>);

#[async_trait::async_trait]
impl DSNSync for TestDSN {
    type Error = std::convert::Infallible;

    fn notify_sync_start(&self) {}

    fn notify_sync_end(&self) {}

    async fn get_pieces(
        &mut self,
        Range { start, end }: Range<PieceIndexHash>,
    ) -> Result<Box<dyn Stream<Item = PiecesToPlot> + Unpin + Send>, Self::Error> {
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
        Ok(Box::new(futures::stream::once(futures::future::ready(
            PiecesToPlot {
                pieces: pieces.try_into().unwrap(),
                piece_indexes,
            },
        ))))
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
        TestPlotter {
            result: Arc::clone(&result),
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
        TestPlotter {
            result: Arc::clone(&result),
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

    let seeder_plot_directory = TempDir::new().unwrap();
    let seeder_metadata_directory = TempDir::new().unwrap();

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

    let plot_factory = move |options: PlotFactoryOptions<'_>| {
        Plot::open_or_create(
            options.single_plot_farm_id,
            options.plot_directory,
            options.metadata_directory,
            options.public_key,
            options.max_plot_size,
        )
    };

    let seeder_farming = SingleDiskFarm::new(SingleDiskFarmOptions {
        plot_directory: seeder_plot_directory.as_ref().to_owned(),
        metadata_directory: seeder_metadata_directory.as_ref().to_owned(),
        allocated_plotting_space: seeder_max_plot_size,
        farmer_protocol_info,
        disk_concurrency: NonZeroU16::new(u16::MAX).unwrap(),
        plot_factory,
        archiving_client: rpc_client.clone(),
        farming_client: rpc_client.clone(),
        listen_on: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap_nodes: vec![],
        enable_farming: false,
        reward_address: subspace_core_primitives::PublicKey::default(),
        enable_dsn_archiving: false,
        enable_dsn_sync: false,
    })
    .await
    .unwrap();

    let seeder_plot = seeder_farming.single_plot_farms()[0].plot().clone();
    let seeder_node = seeder_farming.single_plot_farms()[0].node().clone();
    let seeder_public_key = *seeder_farming.single_plot_farms()[0].public_key();

    tokio::spawn(async move {
        if let Err(error) = seeder_farming.wait().await {
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
                    records_root: Blake2b256Hash::default(),
                    prev_root_block_hash: Blake2b256Hash::default(),
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

    let mut syncer_plot_directory = TempDir::new().unwrap();
    let mut syncer_metadata_directory = TempDir::new().unwrap();
    let plot_factory = move |options: PlotFactoryOptions<'_>| {
        Plot::open_or_create(
            options.single_plot_farm_id,
            options.plot_directory,
            options.metadata_directory,
            options.public_key,
            options.max_plot_size,
        )
    };

    let syncer_farming = loop {
        {
            let syncer_farming = SingleDiskFarm::new(SingleDiskFarmOptions {
                plot_directory: syncer_plot_directory.as_ref().to_owned(),
                metadata_directory: syncer_metadata_directory.as_ref().to_owned(),
                allocated_plotting_space: syncer_max_plot_size,
                farmer_protocol_info,
                farming_client: rpc_client.clone(),
                archiving_client: rpc_client.clone(),
                plot_factory,
                listen_on: vec![],
                bootstrap_nodes: vec![seeder_multiaddr.clone()],
                disk_concurrency: NonZeroU16::new(u16::MAX).unwrap(),
                enable_farming: false,
                reward_address: subspace_core_primitives::PublicKey::default(),
                enable_dsn_archiving: false,
                enable_dsn_sync: false,
            })
            .await
            .unwrap();

            let syncer_public_key = *syncer_farming.single_plot_farms()[0].public_key();

            // Make sure seeder and syncer are close enough to each other
            if bidirectional_distance(
                &U256::from_be_bytes(seeder_public_key.into()),
                &U256::from_be_bytes(syncer_public_key.into()),
            ) < U256::MAX / U256::from(seeder_max_plot_size / syncer_max_plot_size)
            {
                break syncer_farming;
            }
        }

        // Remove old directory so that everything is deleted and identity re-created
        syncer_plot_directory = TempDir::new().unwrap();
        syncer_metadata_directory = TempDir::new().unwrap();
    };

    let syncer_max_piece_count = syncer_max_plot_size / PIECE_SIZE as u64;

    let range_size = PieceIndexHashNumber::MAX / seeder_max_piece_count * pieces_per_request;
    let plot = syncer_farming.single_plot_farms()[0].plot().clone();
    let dsn_sync = dsn::dsn_sync(
        rpc_client.clone(),
        FarmerProtocolInfo {
            max_plot_size: syncer_max_plot_size,
            total_pieces: seeder_max_piece_count,
            ..farmer_protocol_info
        },
        range_size,
        false, // don't verify pieces
        syncer_farming.single_plot_farms()[0].node().clone(),
        Span::current(),
        syncer_farming.single_plot_farms()[0].plotter(),
        *syncer_farming.single_plot_farms()[0].public_key(),
    );
    let public_key =
        U256::from_be_bytes((*syncer_farming.single_plot_farms()[0].public_key()).into());

    let syncer_node = syncer_farming.single_plot_farms()[0].node().clone();

    tokio::spawn(async move {
        if let Err(error) = syncer_farming.wait().await {
            eprintln!("Syncer exited with error: {error}");
        }
    });

    syncer_node
        .wait_for_connected_peers()
        .await
        .expect("Unexpected Node failure");

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

#[tokio::test]
async fn pieces_by_range_protocol_smoke() {
    let expected_request = PiecesByRangeRequest {
        start: PieceIndexHash::from([1u8; 32]),
        end: PieceIndexHash::from([1u8; 32]),
    };

    let piece_bytes: Vec<u8> = Piece::default().into();
    let flat_pieces = FlatPieces::try_from(piece_bytes).unwrap();
    let pieces = PiecesToPlot {
        piece_indexes: vec![1],
        pieces: flat_pieces,
    };

    let response = PiecesByRangeResponse {
        pieces,
        next_piece_index_hash: None,
    };

    let expected_response = response.clone();

    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        request_response_protocols: vec![PiecesByRangeRequestHandler::create(move |req| {
            assert_eq!(*req, expected_request);

            Some(expected_response.clone())
        })],
        ..Config::with_generated_keypair()
    };
    let (node_1, mut node_runner_1) = subspace_networking::create(config_1).await.unwrap();

    let (node_1_address_sender, node_1_address_receiver) = oneshot::channel();
    let on_new_listener_handler = node_1.on_new_listener(Arc::new({
        let node_1_address_sender = Mutex::new(Some(node_1_address_sender));

        move |address| {
            if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                if let Some(node_1_address_sender) = node_1_address_sender.lock().take() {
                    node_1_address_sender.send(address.clone()).unwrap();
                }
            }
        }
    }));

    tokio::spawn(async move {
        node_runner_1.run().await;
    });

    // Wait for first node to know its address
    let node_1_addr = node_1_address_receiver.await.unwrap();
    drop(on_new_listener_handler);

    let config_2 = Config {
        networking_parameters_registry: BootstrappedNetworkingParameters::new(vec![
            node_1_addr.with(Protocol::P2p(node_1.id().into()))
        ])
        .boxed(),
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        request_response_protocols: vec![PiecesByRangeRequestHandler::create(|_request| None)],
        ..Config::with_generated_keypair()
    };

    let (node_2, mut node_runner_2) = subspace_networking::create(config_2).await.unwrap();
    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    node_2
        .wait_for_connected_peers()
        .await
        .expect("Unexpected Node failure");

    let (mut result_sender, mut result_receiver) = mpsc::unbounded();
    tokio::spawn(async move {
        let resp = node_2
            .send_generic_request(node_1.id(), expected_request)
            .await
            .unwrap();

        result_sender.send(resp).await.unwrap();
    });

    let resp = result_receiver.next().await.unwrap();
    assert_eq!(resp, response);
}

#[tokio::test]
async fn get_pieces_by_range_smoke() {
    let piece_index_from = PieceIndexHash::from(crypto::blake2b_256_hash(b"from"));
    let piece_index_continue = PieceIndexHash::from(crypto::blake2b_256_hash(b"continue"));
    let piece_index_end = PieceIndexHash::from(crypto::blake2b_256_hash(b"end"));

    fn get_pieces_to_plot_mock(seed: u8) -> PiecesToPlot {
        let piece_bytes: Vec<u8> = [seed; 4096].to_vec();
        let flat_pieces = FlatPieces::try_from(piece_bytes).unwrap();

        PiecesToPlot {
            piece_indexes: vec![1],
            pieces: flat_pieces,
        }
    }

    static REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);

    let expected_data = vec![get_pieces_to_plot_mock(0), get_pieces_to_plot_mock(1)];
    let response_data = expected_data.clone();

    let config_1 = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        request_response_protocols: vec![
            PiecesByRangeRequestHandler::create(move |req| {
                let request_index = REQUEST_COUNT.fetch_add(1, Ordering::SeqCst);

                // Only two responses
                if request_index == 2 {
                    return None;
                }

                if request_index == 0 {
                    Some(PiecesByRangeResponse {
                        pieces: response_data[request_index].clone(),
                        next_piece_index_hash: Some(piece_index_continue),
                    })
                } else {
                    // New request starts from from the previous response.
                    assert_eq!(req.start, piece_index_continue);

                    Some(PiecesByRangeResponse {
                        pieces: response_data[request_index].clone(),
                        next_piece_index_hash: None,
                    })
                }
            }),
            PeerInfoRequestHandler::create(|_| {
                Some(PeerInfoResponse {
                    peer_info: PeerInfo {
                        status: PeerSyncStatus::Ready,
                    },
                })
            }),
        ],
        ..Config::with_generated_keypair()
    };
    let (node_1, mut node_runner_1) = subspace_networking::create(config_1).await.unwrap();

    let (node_1_address_sender, node_1_address_receiver) = oneshot::channel();
    let on_new_listener_handler = node_1.on_new_listener(Arc::new({
        let node_1_address_sender = Mutex::new(Some(node_1_address_sender));

        move |address| {
            if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                if let Some(node_1_address_sender) = node_1_address_sender.lock().take() {
                    node_1_address_sender.send(address.clone()).unwrap();
                }
            }
        }
    }));

    tokio::spawn(async move {
        node_runner_1.run().await;
    });

    // Wait for first node to know its address
    let node_1_addr = node_1_address_receiver.await.unwrap();
    drop(on_new_listener_handler);

    let config_2 = Config {
        networking_parameters_registry: BootstrappedNetworkingParameters::new(vec![
            node_1_addr.with(Protocol::P2p(node_1.id().into()))
        ])
        .boxed(),
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_globals_in_dht: true,
        request_response_protocols: vec![
            PiecesByRangeRequestHandler::create(|_request| None),
            PeerInfoRequestHandler::create(|_| {
                Some(PeerInfoResponse {
                    peer_info: PeerInfo {
                        status: PeerSyncStatus::Ready,
                    },
                })
            }),
        ],
        ..Config::with_generated_keypair()
    };

    let (mut node_2, mut node_runner_2) = subspace_networking::create(config_2).await.unwrap();
    tokio::spawn(async move {
        node_runner_2.run().await;
    });

    node_2
        .wait_for_connected_peers()
        .await
        .expect("Unexpected Node failure");

    let mut stream = node_2
        .get_pieces(piece_index_from..piece_index_end)
        .await
        .unwrap();

    let mut result = Vec::new();
    while let Some(piece_plot) = stream.next().await {
        result.push(piece_plot);
    }

    assert_eq!(result, expected_data);
}
