use async_trait::async_trait;
use std::error::Error;
use subspace_core_primitives::{Piece, PieceIndex};
use subspace_farmer_components::plotting::PieceGetter;

pub struct BenchPieceGetter {
    piece: Piece,
}

#[async_trait]
impl PieceGetter for BenchPieceGetter {
    async fn get_piece(
        &self,
        _piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        Ok(Some(self.piece.clone()))
    }
}

impl BenchPieceGetter {
    pub fn new(piece: Piece) -> Self {
        Self { piece }
    }
}
