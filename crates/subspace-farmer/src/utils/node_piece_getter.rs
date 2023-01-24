use async_trait::async_trait;
use std::error::Error;
use subspace_core_primitives::{Piece, PieceIndex};
use subspace_farmer_components::plotting::PieceGetter;
use subspace_networking::utils::piece_provider::{PieceProvider, PieceValidator};

pub struct NodePieceGetter<RV> {
    piece_provider: PieceProvider<RV>,
}

impl<RV> NodePieceGetter<RV> {
    pub fn new(piece_provider: PieceProvider<RV>) -> Self {
        Self { piece_provider }
    }
}

#[async_trait]
impl<PV> PieceGetter for NodePieceGetter<PV>
where
    PV: PieceValidator,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        self.piece_provider.get_piece(piece_index).await
    }
}
