use crate::NodeClient;
use async_trait::async_trait;
use lru::LruCache;
use parking_lot::Mutex;
use subspace_archiving::archiver::is_piece_valid;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    Piece, PieceIndex, RecordsRoot, SegmentIndex, PIECES_IN_SEGMENT, RECORD_SIZE,
};
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::piece_provider::PieceValidator;
use subspace_networking::Node;
use tracing::error;

pub struct RecordsRootPieceValidator<NC> {
    dsn_node: Node,
    node_client: NC,
    kzg: Kzg,
    records_root_cache: Mutex<LruCache<SegmentIndex, RecordsRoot>>,
}

impl<NC> RecordsRootPieceValidator<NC> {
    pub fn new(
        dsn_node: Node,
        node_client: NC,
        kzg: Kzg,
        records_root_cache: Mutex<LruCache<SegmentIndex, RecordsRoot>>,
    ) -> Self {
        Self {
            dsn_node,
            node_client,
            kzg,
            records_root_cache,
        }
    }
}

#[async_trait]
impl<NC> PieceValidator for RecordsRootPieceValidator<NC>
where
    NC: NodeClient,
{
    async fn validate_piece(
        &self,
        source_peer_id: PeerId,
        piece_index: PieceIndex,
        piece: Piece,
    ) -> Option<Piece> {
        if source_peer_id != self.dsn_node.id() {
            let segment_index: SegmentIndex = piece_index / PieceIndex::from(PIECES_IN_SEGMENT);

            let maybe_records_root = self.records_root_cache.lock().get(&segment_index).copied();
            let records_root = match maybe_records_root {
                Some(records_root) => records_root,
                None => {
                    let records_roots =
                        match self.node_client.records_roots(vec![segment_index]).await {
                            Ok(records_roots) => records_roots,
                            Err(error) => {
                                error!(
                                    %piece_index,
                                    ?error,
                                    "Failed tor retrieve records root from node"
                                );
                                return None;
                            }
                        };

                    let records_root = match records_roots.into_iter().next().flatten() {
                        Some(records_root) => records_root,
                        None => {
                            error!(
                                %piece_index,
                                %segment_index,
                                "Records root for segment index wasn't found on node"
                            );
                            return None;
                        }
                    };

                    self.records_root_cache
                        .lock()
                        .push(segment_index, records_root);

                    records_root
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
