use async_trait::async_trait;
use subspace_archiving::archiver::is_piece_valid;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    Piece, PieceIndex, SegmentCommitment, SegmentIndex, PIECES_IN_SEGMENT,
};
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::piece_provider::PieceValidator;
use subspace_networking::Node;
use tracing::error;

pub struct SegmentCommitmentPieceValidator {
    dsn_node: Node,
    kzg: Kzg,
    segment_commitment_cache: Vec<SegmentCommitment>,
}

impl SegmentCommitmentPieceValidator {
    /// Segment headers must be in order from 0 to the last one that exists
    pub fn new(dsn_node: Node, kzg: Kzg, segment_commitment_cache: Vec<SegmentCommitment>) -> Self {
        Self {
            dsn_node,
            kzg,
            segment_commitment_cache,
        }
    }
}

#[async_trait]
impl PieceValidator for SegmentCommitmentPieceValidator {
    async fn validate_piece(
        &self,
        source_peer_id: PeerId,
        piece_index: PieceIndex,
        piece: Piece,
    ) -> Option<Piece> {
        if source_peer_id != self.dsn_node.id() {
            let segment_index: SegmentIndex = piece_index / PieceIndex::from(PIECES_IN_SEGMENT);

            let maybe_segment_commitment =
                self.segment_commitment_cache.get(segment_index as usize);
            let segment_commitment = match maybe_segment_commitment {
                Some(segment_commitment) => *segment_commitment,
                None => {
                    error!(%segment_index, "No segment commitment in the cache.");

                    return None;
                }
            };

            if !is_piece_valid(
                &self.kzg,
                PIECES_IN_SEGMENT as usize,
                &piece,
                &segment_commitment,
                u32::try_from(piece_index % PieceIndex::from(PIECES_IN_SEGMENT))
                    .expect("Always fix into u32; qed"),
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
