use crate::disk_piece_cache::DiskPieceCache;
use crate::farmer_cache::{decode_piece_index_from_record_key, FarmerCache};
use crate::node_client::{Error, NodeClient};
use async_trait::async_trait;
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, Stream, StreamExt};
use parking_lot::Mutex;
use rand::prelude::*;
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{
    HistorySize, LastArchivedBlock, Piece, PieceIndex, SegmentHeader, SegmentIndex,
};
use subspace_farmer_components::{FarmerProtocolInfo, PieceGetter};
use subspace_networking::libp2p::identity;
use subspace_networking::libp2p::kad::RecordKey;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_rpc_primitives::{
    FarmerAppInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};
use tempfile::tempdir;

type TestCacheIndex = u8;

#[derive(Debug, Clone)]
struct MockNodeClient {
    current_segment_index: Arc<AtomicU64>,
    pieces: Arc<Mutex<HashMap<PieceIndex, Piece>>>,
    archived_segment_headers_stream_request_sender:
        mpsc::Sender<oneshot::Sender<mpsc::Receiver<SegmentHeader>>>,
    acknowledge_archived_segment_header_sender: mpsc::Sender<SegmentIndex>,
}

#[async_trait]
impl NodeClient for MockNodeClient {
    async fn farmer_app_info(&self) -> Result<FarmerAppInfo, Error> {
        // Most of these values make no sense, but they are not used by piece cache anyway
        Ok(FarmerAppInfo {
            genesis_hash: [0; 32],
            dsn_bootstrap_nodes: Vec::new(),
            syncing: false,
            farming_timeout: Duration::default(),
            protocol_info: FarmerProtocolInfo {
                history_size: HistorySize::from(SegmentIndex::from(
                    self.current_segment_index.load(Ordering::Acquire),
                )),
                max_pieces_in_sector: 0,
                recent_segments: HistorySize::from(SegmentIndex::ZERO),
                recent_history_fraction: (
                    HistorySize::from(NonZeroU64::new(1).unwrap()),
                    HistorySize::from(NonZeroU64::new(10).unwrap()),
                ),
                min_sector_lifetime: HistorySize::from(NonZeroU64::new(4).unwrap()),
            },
        })
    }

    async fn subscribe_slot_info(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SlotInfo> + Send + 'static>>, Error> {
        unimplemented!()
    }

    async fn submit_solution_response(
        &self,
        _solution_response: SolutionResponse,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    async fn subscribe_reward_signing(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = RewardSigningInfo> + Send + 'static>>, Error> {
        unimplemented!()
    }

    async fn submit_reward_signature(
        &self,
        _reward_signature: RewardSignatureResponse,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    async fn subscribe_archived_segment_headers(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SegmentHeader> + Send + 'static>>, Error> {
        let (tx, rx) = oneshot::channel();
        self.archived_segment_headers_stream_request_sender
            .clone()
            .send(tx)
            .await
            .unwrap();
        // Allow to delay segment headers subscription in tests
        let stream = rx.await.unwrap();
        Ok(Box::pin(stream))
    }

    async fn segment_headers(
        &self,
        _segment_indexes: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<SegmentHeader>>, Error> {
        unimplemented!()
    }

    async fn piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, Error> {
        Ok(Some(
            self.pieces
                .lock()
                .entry(piece_index)
                .or_insert_with(|| {
                    let mut piece = Piece::default();
                    thread_rng().fill(piece.as_mut());
                    piece
                })
                .clone(),
        ))
    }

    async fn acknowledge_archived_segment_header(
        &self,
        segment_index: SegmentIndex,
    ) -> Result<(), Error> {
        self.acknowledge_archived_segment_header_sender
            .clone()
            .send(segment_index)
            .await
            .unwrap();
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct MockPieceGetter {
    pieces: Arc<Mutex<HashMap<PieceIndex, Piece>>>,
}

#[async_trait]
impl PieceGetter for MockPieceGetter {
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(Some(
            self.pieces
                .lock()
                .entry(piece_index)
                .or_insert_with(|| {
                    let mut piece = Piece::default();
                    thread_rng().fill(piece.as_mut());
                    piece
                })
                .clone(),
        ))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn basic() {
    let current_segment_index = Arc::new(AtomicU64::new(0));
    let pieces = Arc::default();
    let (
        archived_segment_headers_stream_request_sender,
        mut archived_segment_headers_stream_request_receiver,
    ) = mpsc::channel(0);
    let (
        acknowledge_archived_segment_header_sender,
        mut acknowledge_archived_segment_header_receiver,
    ) = mpsc::channel(0);

    let node_client = MockNodeClient {
        current_segment_index: Arc::clone(&current_segment_index),
        pieces: Arc::clone(&pieces),
        archived_segment_headers_stream_request_sender,
        acknowledge_archived_segment_header_sender,
    };
    let piece_getter = MockPieceGetter {
        pieces: Arc::clone(&pieces),
    };
    let public_key =
        identity::PublicKey::from(identity::ed25519::PublicKey::try_from_bytes(&[42; 32]).unwrap());
    let path1 = tempdir().unwrap();
    let path2 = tempdir().unwrap();

    {
        let (farmer_cache, farmer_cache_worker) =
            FarmerCache::<TestCacheIndex>::new(node_client.clone(), public_key.to_peer_id(), None);

        let farmer_cache_worker_exited =
            tokio::spawn(farmer_cache_worker.run(piece_getter.clone()));

        let (sender, receiver) = oneshot::channel();
        farmer_cache
            .on_sync_progress(Arc::new({
                let sender = Mutex::new(Some(sender));

                move |progress| {
                    if *progress == 100.0 {
                        if let Some(sender) = sender.lock().take() {
                            sender.send(()).unwrap();
                        }
                    }
                }
            }))
            .detach();
        farmer_cache
            .replace_backing_caches(
                vec![
                    Arc::new(DiskPieceCache::open(path1.as_ref(), 1, None, None).unwrap()),
                    Arc::new(DiskPieceCache::open(path2.as_ref(), 1, None, None).unwrap()),
                ],
                vec![],
            )
            .await;

        // Wait for piece cache to be initialized
        receiver.await.unwrap();

        // These 2 pieces are requested from node during initialization
        {
            let mut requested_pieces = pieces.lock().keys().copied().collect::<Vec<_>>();
            requested_pieces.sort();
            let expected_pieces = vec![PieceIndex::from(26), PieceIndex::from(196)];
            assert_eq!(requested_pieces, expected_pieces);

            for piece_index in requested_pieces {
                farmer_cache
                    .get_piece(piece_index.to_multihash())
                    .await
                    .unwrap();
            }

            // Other piece indices are not requested or cached
            assert!(farmer_cache
                .get_piece(PieceIndex::from(10).to_multihash())
                .await
                .is_none());
        }

        // Update current segment header such that we keep-up after initial sync is triggered
        current_segment_index.store(1, Ordering::Release);

        // Send segment headers receiver such that keep-up sync can start not
        let (mut archived_segment_headers_sender, archived_segment_headers_receiver) =
            mpsc::channel(0);
        archived_segment_headers_stream_request_receiver
            .next()
            .await
            .unwrap()
            .send(archived_segment_headers_receiver)
            .unwrap();

        // Send segment header with the same segment index as "current", so it will have no
        // side-effects, but acknowledgement will indicate that keep-up after initial sync has finished
        {
            let segment_header = SegmentHeader::V0 {
                segment_index: SegmentIndex::ONE,
                segment_commitment: Default::default(),
                prev_segment_header_hash: [0; 32].into(),
                last_archived_block: LastArchivedBlock {
                    number: 0,
                    archived_progress: Default::default(),
                },
            };

            archived_segment_headers_sender
                .send(segment_header)
                .await
                .unwrap();

            // Wait for acknowledgement
            assert_eq!(
                acknowledge_archived_segment_header_receiver
                    .next()
                    .await
                    .unwrap(),
                SegmentIndex::ONE
            );
        }

        // One more piece was requested during keep-up after initial sync
        {
            let mut requested_pieces = pieces.lock().keys().copied().collect::<Vec<_>>();
            requested_pieces.sort();
            let expected_pieces = vec![
                PieceIndex::from(26),
                PieceIndex::from(196),
                PieceIndex::from(276),
            ];
            assert_eq!(requested_pieces, expected_pieces);

            let stored_pieces = vec![PieceIndex::from(196), PieceIndex::from(276)];
            for piece_index in &stored_pieces {
                farmer_cache
                    .get_piece(piece_index.to_multihash())
                    .await
                    .unwrap();
            }

            for piece_index in requested_pieces {
                if !stored_pieces.contains(&piece_index) {
                    // Other piece indices are not stored anymore
                    assert!(farmer_cache
                        .get_piece(PieceIndex::from(10).to_multihash())
                        .await
                        .is_none());
                }
            }
        }

        // Send two more segment headers (one is not enough because for above peer ID there are no pieces for it to
        // store)
        for segment_index in [2, 3] {
            let segment_header = SegmentHeader::V0 {
                segment_index: SegmentIndex::from(segment_index),
                segment_commitment: Default::default(),
                prev_segment_header_hash: [0; 32].into(),
                last_archived_block: LastArchivedBlock {
                    number: 0,
                    archived_progress: Default::default(),
                },
            };

            // Send twice because acknowledgement arrives early, sending twice doesn't have side effects, but ensures
            // things were processed fully
            for _ in 0..=1 {
                archived_segment_headers_sender
                    .send(segment_header)
                    .await
                    .unwrap();

                // Wait for acknowledgement
                assert_eq!(
                    acknowledge_archived_segment_header_receiver
                        .next()
                        .await
                        .unwrap(),
                    SegmentIndex::from(segment_index)
                );
            }

            current_segment_index.store(segment_index, Ordering::Release);
        }

        // One more piece was requested during keep-up after initial sync
        {
            let mut requested_pieces = pieces.lock().keys().copied().collect::<Vec<_>>();
            requested_pieces.sort();
            let expected_pieces = vec![
                PieceIndex::from(26),
                PieceIndex::from(196),
                PieceIndex::from(276),
                PieceIndex::from(823),
                PieceIndex::from(859),
            ];
            assert_eq!(requested_pieces, expected_pieces);

            let stored_pieces = vec![PieceIndex::from(823), PieceIndex::from(859)];
            for piece_index in &stored_pieces {
                farmer_cache
                    .get_piece(piece_index.to_multihash())
                    .await
                    .unwrap();
            }

            for piece_index in requested_pieces {
                if !stored_pieces.contains(&piece_index) {
                    // Other piece indices are not stored anymore
                    assert!(farmer_cache
                        .get_piece(PieceIndex::from(10).to_multihash())
                        .await
                        .is_none());
                }
            }
        }

        drop(farmer_cache);

        farmer_cache_worker_exited.await.unwrap();
    }

    {
        // Clear requested pieces
        pieces.lock().clear();

        let (farmer_cache, farmer_cache_worker) =
            FarmerCache::<TestCacheIndex>::new(node_client.clone(), public_key.to_peer_id(), None);

        let farmer_cache_worker_exited = tokio::spawn(farmer_cache_worker.run(piece_getter));

        let (sender, receiver) = oneshot::channel();
        farmer_cache
            .on_sync_progress(Arc::new({
                let sender = Mutex::new(Some(sender));

                move |progress| {
                    if *progress == 100.0 {
                        if let Some(sender) = sender.lock().take() {
                            sender.send(()).unwrap();
                        }
                    }
                }
            }))
            .detach();
        // Reopen with the same backing caches
        farmer_cache
            .replace_backing_caches(
                vec![
                    Arc::new(DiskPieceCache::open(path1.as_ref(), 1, None, None).unwrap()),
                    Arc::new(DiskPieceCache::open(path2.as_ref(), 1, None, None).unwrap()),
                ],
                vec![],
            )
            .await;
        drop(farmer_cache);

        // Wait for piece cache to be initialized
        receiver.await.unwrap();

        // Same state as before, no pieces should be requested during initialization
        assert_eq!(pieces.lock().len(), 0);

        let (mut archived_segment_headers_sender, archived_segment_headers_receiver) =
            mpsc::channel(0);
        archived_segment_headers_stream_request_receiver
            .next()
            .await
            .unwrap()
            .send(archived_segment_headers_receiver)
            .unwrap();
        // Make worker exit
        archived_segment_headers_sender.close().await.unwrap();

        farmer_cache_worker_exited.await.unwrap();
    }
}

#[test]
fn decode_piece_index_from_record_key_test() {
    let piece_index_0 = PieceIndex::from(0);
    let record_0 = RecordKey::from(piece_index_0.to_multihash());
    let decode_0 = decode_piece_index_from_record_key(&record_0);
    assert_eq!(decode_0, piece_index_0);

    let piece_index_123456 = PieceIndex::from(123456);
    let record_123456 = RecordKey::from(piece_index_123456.to_multihash());
    let decode_123456 = decode_piece_index_from_record_key(&record_123456);
    assert_eq!(decode_123456, piece_index_123456);

    let piece_index_max = PieceIndex::from(u64::MAX);
    let record_max = RecordKey::from(piece_index_max.to_multihash());
    let decode_max = decode_piece_index_from_record_key(&record_max);
    assert_eq!(decode_max, piece_index_max);
}
