use crate::utils::piece_cache::PieceCache;
use async_trait::async_trait;
use std::error::Error;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndex};
use subspace_farmer_components::plotting::{PieceGetter, PieceGetterRetryPolicy};
use subspace_networking::utils::multihash::ToMultihash;

pub struct FarmerPieceGetter<PG, PC> {
    base_piece_getter: PG,
    piece_cache: Arc<tokio::sync::Mutex<PC>>,
}

impl<PG, PC> FarmerPieceGetter<PG, PC> {
    pub fn new(base_piece_getter: PG, piece_cache: Arc<tokio::sync::Mutex<PC>>) -> Self {
        Self {
            base_piece_getter,
            piece_cache,
        }
    }
}

#[async_trait]
impl<PG, PC> PieceGetter for FarmerPieceGetter<PG, PC>
where
    PG: PieceGetter + Send + Sync,
    PC: PieceCache + Send + 'static,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
        retry_policy: PieceGetterRetryPolicy,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        let piece_index_hash = piece_index.hash();
        let key = piece_index_hash.to_multihash().into();

        {
            let piece_cache = self.piece_cache.lock().await;
            if let Some(piece) = piece_cache.get_piece(&key) {
                return Ok(Some(piece));
            }
        };

        let maybe_piece = self
            .base_piece_getter
            .get_piece(piece_index, retry_policy)
            .await?;

        Ok(maybe_piece)
    }
}
