use async_trait::async_trait;
use std::error::Error;
use subspace_core_primitives::{Piece, PieceIndex};
use subspace_networking::PieceReceiver;

pub struct BenchPieceReceiver {
    piece: Piece,
}

#[async_trait]
impl PieceReceiver for BenchPieceReceiver {
    async fn get_piece(
        &self,
        _piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        Ok(Some(self.piece.clone()))
    }
}

impl BenchPieceReceiver {
    pub fn new(piece: Piece) -> Self {
        Self { piece }
    }
}
