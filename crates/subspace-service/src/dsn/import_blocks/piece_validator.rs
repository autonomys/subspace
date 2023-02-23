use async_trait::async_trait;
use std::collections::BTreeMap;
use subspace_archiving::archiver::is_piece_valid;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    Piece, PieceIndex, RecordsRoot, RootBlock, SegmentIndex, PIECES_IN_SEGMENT, RECORD_SIZE,
};
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::piece_provider::PieceValidator;
use subspace_networking::Node;
use tracing::error;

pub struct RecordsRootPieceValidator {
    dsn_node: Node,
    kzg: Kzg,
    records_root_cache: BTreeMap<SegmentIndex, RecordsRoot>,
}

impl RecordsRootPieceValidator {
    pub fn new(dsn_node: Node, kzg: Kzg, root_blocks: Vec<RootBlock>) -> Self {
        let records_root_cache = root_blocks
            .iter()
            .map(|rb| (rb.segment_index(), rb.records_root()))
            .collect();

        Self {
            dsn_node,
            kzg,
            records_root_cache,
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

            let maybe_records_root = self.records_root_cache.get(&segment_index);
            let records_root = match maybe_records_root {
                Some(records_root) => *records_root,
                None => {
                    error!(%segment_index, "No records root in the cache.");

                    return None;
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
