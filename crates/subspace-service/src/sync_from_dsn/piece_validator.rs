use async_trait::async_trait;
use sc_client_api::AuxStore;
use sc_consensus_subspace::SegmentHeadersStore;
use subspace_archiving::archiver::is_piece_valid;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{Piece, PieceIndex};
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::piece_provider::PieceValidator;
use subspace_networking::Node;
use tracing::{error, warn};

pub struct SegmentCommitmentPieceValidator<'a, AS> {
    dsn_node: &'a Node,
    kzg: &'a Kzg,
    segment_headers_store: &'a SegmentHeadersStore<AS>,
}

impl<'a, AS> SegmentCommitmentPieceValidator<'a, AS>
where
    AS: AuxStore + Send + Sync + 'static,
{
    /// Segment headers must be in order from 0 to the last one that exists
    pub fn new(
        dsn_node: &'a Node,
        kzg: &'a Kzg,
        segment_headers_store: &'a SegmentHeadersStore<AS>,
    ) -> Self {
        Self {
            dsn_node,
            kzg,
            segment_headers_store,
        }
    }
}

#[async_trait]
impl<'a, AS> PieceValidator for SegmentCommitmentPieceValidator<'a, AS>
where
    AS: AuxStore + Send + Sync + 'static,
{
    async fn validate_piece(
        &self,
        source_peer_id: PeerId,
        piece_index: PieceIndex,
        piece: Piece,
    ) -> Option<Piece> {
        if source_peer_id != self.dsn_node.id() {
            let segment_index = piece_index.segment_index();

            let maybe_segment_header = self.segment_headers_store.get_segment_header(segment_index);
            let segment_commitment = match maybe_segment_header {
                Some(segment_header) => segment_header.segment_commitment(),
                None => {
                    error!(%segment_index, "No segment commitment in the cache.");

                    return None;
                }
            };

            if !is_piece_valid(
                self.kzg,
                &piece,
                &segment_commitment,
                piece_index.position(),
            ) {
                warn!(
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
