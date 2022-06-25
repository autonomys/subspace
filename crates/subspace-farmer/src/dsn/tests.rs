use super::{sync, DSNSync, NoSync, PieceIndexHashNumber, SyncOptions};
use crate::bench_rpc_client::{BenchRpcClient, BENCH_FARMER_METADATA};
use crate::multi_farming::{MultiFarming, Options as MultiFarmingOptions};
use crate::{ObjectMappings, Plot};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, SinkExt, StreamExt};
use num_traits::{WrappingAdd, WrappingSub};
use rand::Rng;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::ops::Range;
use std::sync::{Arc, Mutex};
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{
    ArchivedBlockProgress, FlatPieces, LastArchivedBlock, Piece, PieceIndex, PieceIndexHash,
    RootBlock, Sha256Hash, PIECE_SIZE, U256,
};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::libp2p::{identity, Multiaddr, PeerId};
use subspace_networking::{NodeRunner, PiecesToPlot};
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
async fn test_dsn_sync() {
    let seeder_max_plot_size = 20 * 1024 * 1024 / PIECE_SIZE as u64; // 20M
    let syncer_max_plot_size = 2 * 1024 * 1024 / PIECE_SIZE as u64; // 20M
    let request_pieces_size = 20;

    let seeder_base_directory = TempDir::new().unwrap();

    let free_port = (10_000..)
        .find(|port| TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, *port)).is_ok())
        .unwrap();
    let mut seeder_multiaddr = format!("/ip4/127.0.0.1/tcp/{free_port}")
        .parse::<Multiaddr>()
        .unwrap();

    let (mut seeder_archived_segments_sender, seeder_archived_segments_receiver) =
        futures::channel::mpsc::channel(10);
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
            reward_address: subspace_core_primitives::PublicKey::default(),
            bootstrap_nodes: vec![],
            listen_on: vec![seeder_multiaddr.clone()],
            dsn_sync: false,
        },
        seeder_max_plot_size * PIECE_SIZE as u64,
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

        for segment_index in 0..seeder_max_plot_size / 256 {
            let archived_segment = {
                let root_block = RootBlock::V0 {
                    segment_index,
                    records_root: Sha256Hash::default(),
                    prev_root_block_hash: Sha256Hash::default(),
                    last_archived_block,
                };

                let mut pieces = FlatPieces::new(256);
                rand::thread_rng().fill(pieces.as_mut());

                ArchivedSegment {
                    root_block,
                    pieces,
                    object_mapping: vec![],
                }
            };

            if seeder_archived_segments_sender
                .send(archived_segment)
                .await
                .is_err()
            {
                break;
            }
            last_archived_block.set_complete();
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

    let node_runners = futures::future::join_all(
        std::mem::take(&mut seeder_multi_farming.networking_node_runners)
            .into_iter()
            .map(NodeRunner::run),
    );
    tokio::spawn(async move {
        node_runners.await;
    });

    for _ in 0..10 {
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

        let mut syncer_multi_farming = MultiFarming::new(
            MultiFarmingOptions {
                base_directory: syncer_base_directory.as_ref().to_owned(),
                archiving_client: syncer_client.clone(),
                farming_client: syncer_client.clone(),
                object_mappings: object_mappings.clone(),
                reward_address: subspace_core_primitives::PublicKey::default(),
                bootstrap_nodes: vec![seeder_multiaddr.clone()],
                listen_on: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                dsn_sync: false,
            },
            syncer_max_plot_size * PIECE_SIZE as u64,
            syncer_max_plot_size,
            plot_factory,
            false,
        )
        .await
        .unwrap();

        let node_runners = futures::future::join_all(
            std::mem::take(&mut syncer_multi_farming.networking_node_runners)
                .into_iter()
                .map(NodeRunner::run),
        );
        tokio::spawn(async move {
            node_runners.await;
        });

        let expected_total_pieces = syncer_max_plot_size;
        let range_size = PieceIndexHashNumber::MAX / expected_total_pieces * request_pieces_size;
        let mut futures = syncer_multi_farming
            .single_plot_farms
            .iter()
            .map(|farming| {
                let plot = farming.plot.clone();
                farming
                    .dsn_sync(syncer_max_plot_size, expected_total_pieces, range_size)
                    .map(move |result| {
                        result.unwrap();
                        plot
                    })
            })
            .collect::<FuturesUnordered<_>>();

        while let Some(plot) = futures.next().await {
            let sync_sector_size =
                PieceIndexHashNumber::MAX / seeder_max_plot_size * syncer_max_plot_size;
            let expected_start =
                U256::from_big_endian(&plot.public_key()).wrapping_sub(&(sync_sector_size / 2));
            let expected_end =
                U256::from_big_endian(&plot.public_key()).wrapping_add(&(sync_sector_size / 2));
            let public_key = U256::from_big_endian(&plot.public_key());
            let Range { start, end } = plot.get_piece_range().unwrap();
            let total_pieces = plot.piece_count();

            let shift_to_middle =
                |n: U256, pub_key| n.wrapping_sub(pub_key).wrapping_add(&U256::MIDDLE);

            let expected_start = shift_to_middle(expected_start, &public_key);
            let expected_end = shift_to_middle(expected_end, &public_key);
            let start = shift_to_middle(U256::from_big_endian(&start.0), &public_key);
            let end = shift_to_middle(U256::from_big_endian(&end.0), &public_key);

            assert!(expected_start <= start && start <= expected_end);
            assert!(expected_start <= end && end <= expected_end);
            assert!(
                expected_total_pieces / 10 * 9 < total_pieces
                    && total_pieces < expected_total_pieces / 10 * 11
            );
        }

        syncer_client.stop().await;
    }

    drop(seeder_archived_segments_sender);
    seeder_client.stop().await;
    seeder_multi_farming.wait().await.unwrap();
}
