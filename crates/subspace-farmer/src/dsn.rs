use std::ops::Range;

use futures::Stream;
use subspace_core_primitives::PieceIndexHash;

use crate::PiecesToPlot;

#[async_trait::async_trait]
pub trait DSNSync {
    type Stream: Stream<Item = PiecesToPlot>;

    async fn get_pieces(&mut self, range: Range<PieceIndexHash>) -> Self::Stream;
}

/// Marker which disables sync
#[derive(Clone, Copy, Debug)]
pub struct NoSync;

#[async_trait::async_trait]
impl DSNSync for NoSync {
    type Stream = futures::stream::Empty<PiecesToPlot>;

    async fn get_pieces(&mut self, _range: Range<PieceIndexHash>) -> Self::Stream {
        futures::stream::empty()
    }
}
