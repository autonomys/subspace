use async_trait::async_trait;
use futures::StreamExt;
use lru::LruCache;
use parking_lot::Mutex;
use std::error::Error;
use std::num::NonZeroUsize;
use subspace_archiving::archiver::is_piece_valid;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    Piece, PieceIndex, RecordsRoot, SegmentIndex, PIECES_IN_SEGMENT, RECORD_SIZE,
};
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::piece_provider::PieceValidator;
use subspace_networking::{Node, RootBlockRequest, RootBlockResponse};
use tracing::{debug, error, trace, warn};

const RECORDS_ROOTS_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1_000_000).expect("Not zero; qed");

pub struct RecordsRootPieceValidator {
    dsn_node: Node,
    kzg: Kzg,
    records_root_cache: Mutex<LruCache<SegmentIndex, RecordsRoot>>,
}

impl RecordsRootPieceValidator {
    pub fn new(dsn_node: Node, kzg: Kzg) -> Self {
        Self {
            dsn_node,
            kzg,
            records_root_cache: Mutex::new(LruCache::new(RECORDS_ROOTS_CACHE_SIZE)),
        }
    }

    async fn get_records_root(
        &self,
        segment_index: SegmentIndex,
    ) -> Result<RecordsRoot, Box<dyn Error>> {
        // Get random peers. Some of them could be bootstrap nodes with no support for
        // request-response protocol for records root.
        let get_peers_result = self
            .dsn_node
            .get_closest_peers(PeerId::random().into())
            .await;

        match get_peers_result {
            Ok(mut get_peers_stream) => {
                while let Some(peer_id) = get_peers_stream.next().await {
                    trace!(%peer_id, "get_closest_peers returned an item");

                    let request_result = self
                        .dsn_node
                        .send_generic_request(
                            peer_id,
                            RootBlockRequest {
                                segment_indexes: vec![segment_index],
                            },
                        )
                        .await;

                    match request_result {
                        Ok(RootBlockResponse { root_blocks }) => {
                            trace!(%peer_id, %segment_index, "Root block request succeeded.");

                            if let Some(Some(root_block)) = root_blocks.first() {
                                trace!(%peer_id, %segment_index, "Root block was obtained.");

                                return Ok(root_block.records_root());
                            } else {
                                debug!(%peer_id, %segment_index, "Root block was not received.");
                            }
                        }
                        Err(error) => {
                            debug!(%peer_id, %segment_index, ?error, "Root block request failed.");
                        }
                    };
                }
                Err("No more peers for root blocks.".into())
            }
            Err(err) => {
                warn!(?err, "get_closest_peers returned an error");

                Err(err.into())
            }
        }
    }
}

#[async_trait]
impl PieceValidator for RecordsRootPieceValidator {
    async fn validate_piece(
        &self,
        source_peer_id: PeerId,
        piece_index: PieceIndex,
        piece: Piece,
    ) -> Option<Piece> {
        if source_peer_id != self.dsn_node.id() {
            let segment_index: SegmentIndex = piece_index / PieceIndex::from(PIECES_IN_SEGMENT);

            let maybe_records_root =
                { self.records_root_cache.lock().get(&segment_index).copied() };
            let records_root = match maybe_records_root {
                Some(records_root) => records_root,
                None => {
                    let records_root_result = self.get_records_root(segment_index).await;

                    match records_root_result {
                        Ok(records_root) => {
                            self.records_root_cache
                                .lock()
                                .push(segment_index, records_root);

                            trace!(%segment_index, "Records root was received successfully.");

                            records_root
                        }
                        Err(err) => {
                            debug!(?err, %segment_index, "Records root receiving failed.");

                            return None;
                        }
                    }
                }
            };

            if !is_piece_valid(
                &self.kzg,
                PIECES_IN_SEGMENT,
                &piece,
                records_root,
                u32::try_from(piece_index % PieceIndex::from(PIECES_IN_SEGMENT))
                    .expect("Always fix into u32; qed"),
                RECORD_SIZE,
            ) {
                error!(
                    %piece_index,
                    %source_peer_id,
                    "Received invalid piece from peer"
                );

                // We don't care about result here
                let _ = self.dsn_node.ban_peer(source_peer_id).await;
                return None;
            }
        }

        Some(piece)
    }
}
