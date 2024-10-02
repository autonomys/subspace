use async_trait::async_trait;
use sc_client_api::AuxStore;
use sc_consensus_subspace::archiver::SegmentHeadersStore;
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_kzg::Kzg;
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::piece_provider::PieceValidator;
use subspace_networking::Node;
use subspace_verification::is_piece_valid;
use tracing::{error, warn};

pub(crate) struct SegmentCommitmentPieceValidator<AS> {
    dsn_node: Node,
    kzg: Kzg,
    segment_headers_store: SegmentHeadersStore<AS>,
}

impl<AS> SegmentCommitmentPieceValidator<AS>
where
    AS: AuxStore + Send + Sync + 'static,
{
    /// Segment headers must be in order from 0 to the last one that exists
    pub(crate) fn new(
        dsn_node: Node,
        kzg: Kzg,
        segment_headers_store: SegmentHeadersStore<AS>,
    ) -> Self {
        Self {
            dsn_node,
            kzg,
            segment_headers_store,
        }
    }
}

#[async_trait]
impl<AS> PieceValidator for SegmentCommitmentPieceValidator<AS>
where
    AS: AuxStore + Send + Sync + 'static,
{
    async fn validate_piece(
        &self,
        source_peer_id: PeerId,
        piece_index: PieceIndex,
        piece: Piece,
    ) -> Option<Piece> {
        if source_peer_id == self.dsn_node.id() {
            return Some(piece);
        }

        let segment_index = piece_index.segment_index();

        let maybe_segment_header = self.segment_headers_store.get_segment_header(segment_index);
        let segment_commitment = match maybe_segment_header {
            Some(segment_header) => segment_header.segment_commitment(),
            None => {
                error!(%segment_index, "No segment commitment in the cache.");

                return None;
            }
        };

        let is_valid_fut = tokio::task::spawn_blocking({
            let kzg = self.kzg.clone();

            move || {
                is_piece_valid(&kzg, &piece, &segment_commitment, piece_index.position())
                    .then_some(piece)
            }
        });

        match is_valid_fut.await.unwrap_or_default() {
            Some(piece) => Some(piece),
            None => {
                warn!(
                    %piece_index,
                    %source_peer_id,
                    "Received invalid piece from peer"
                );

                // We don't care about result here
                let _ = self.dsn_node.ban_peer(source_peer_id).await;
                None
            }
        }
    }
}
