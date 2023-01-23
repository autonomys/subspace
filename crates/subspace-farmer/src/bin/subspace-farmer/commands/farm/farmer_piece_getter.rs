use crate::commands::farm::dsn::PieceStorage;
use async_trait::async_trait;
use std::error::Error;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndex, PieceIndexHash};
use subspace_farmer_components::plotting::PieceGetter;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::utils::piece_provider::{PieceProvider, PieceValidator};
use subspace_networking::utils::pieces::announce_single_piece_index_hash_with_backoff;
use subspace_networking::Node;
use tracing::debug;

pub(super) struct FarmerPieceGetter<PV, PS> {
    piece_provider: PieceProvider<PV>,
    piece_storage: Arc<tokio::sync::Mutex<PS>>,
    node: Node,
}

impl<PV, PS> FarmerPieceGetter<PV, PS> {
    pub(super) fn new(
        piece_provider: PieceProvider<PV>,
        piece_storage: Arc<tokio::sync::Mutex<PS>>,
        node: Node,
    ) -> Self {
        Self {
            piece_provider,
            piece_storage,
            node,
        }
    }
}

#[async_trait]
impl<PV, PS> PieceGetter for FarmerPieceGetter<PV, PS>
where
    PV: PieceValidator,
    PS: PieceStorage + Send + 'static,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        let piece_index_hash = PieceIndexHash::from_index(piece_index);
        let key = piece_index_hash.to_multihash().into();

        let maybe_should_store = {
            let piece_storage = self.piece_storage.lock().await;
            if let Some(piece) = piece_storage.get_piece(&key) {
                return Ok(Some(piece));
            }

            piece_storage.should_include_in_storage(&key)
        };

        let maybe_piece = self.piece_provider.get_piece(piece_index).await?;

        if let Some(piece) = &maybe_piece {
            if maybe_should_store {
                let mut piece_storage = self.piece_storage.lock().await;
                if piece_storage.should_include_in_storage(&key)
                    && piece_storage.get_piece(&key).is_none()
                {
                    piece_storage.add_piece(key, piece.clone());
                    if let Err(error) =
                        announce_single_piece_index_hash_with_backoff(piece_index_hash, &self.node)
                            .await
                    {
                        debug!(
                            ?error,
                            ?piece_index_hash,
                            "Announcing retrieved and cached piece index hash failed"
                        );
                    }
                }
            }
        }

        Ok(maybe_piece)
    }
}
