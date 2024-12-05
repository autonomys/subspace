//! An object piece getter which uses the DSN to fetch pieces.

use async_trait::async_trait;
use futures::stream::StreamExt;
use futures::{FutureExt, Stream};
use std::fmt;
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_data_retrieval::piece_getter::PieceGetter;
use subspace_networking::utils::piece_provider::{PieceProvider, PieceValidator};

/// The maximum number of peer-to-peer walking rounds for L1 archival storage.
const MAX_RANDOM_WALK_ROUNDS: usize = 15;

/// Wrapper type for [`PieceProvider`], so it can implement [`PieceGetter`]
pub struct DsnPieceGetter<PV: PieceValidator>(PieceProvider<PV>);

impl<PV> fmt::Debug for DsnPieceGetter<PV>
where
    PV: PieceValidator,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DsnPieceGetter")
            .field(&format!("{:?}", self.0))
            .finish()
    }
}

// TODO:
// - reconstruct segment if piece is missing
// - move this piece getter impl into a new library part of this crate
#[async_trait]
impl<PV> PieceGetter for DsnPieceGetter<PV>
where
    PV: PieceValidator,
{
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        if let Some((got_piece_index, maybe_piece)) =
            self.0.get_from_cache([piece_index]).await.next().await
        {
            assert_eq!(piece_index, got_piece_index);

            if let Some(piece) = maybe_piece {
                return Ok(Some(piece));
            }
        }

        Ok(self
            .0
            .get_piece_from_archival_storage(piece_index, MAX_RANDOM_WALK_ROUNDS)
            .await)
    }

    async fn get_pieces<'a>(
        &'a self,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    > {
        let stream =
            self.0
                .get_from_cache(piece_indices)
                .await
                .then(move |(index, maybe_piece)| {
                    let fut = async move {
                        if let Some(piece) = maybe_piece {
                            return (index, Ok(Some(piece)));
                        }

                        self.0
                            .get_piece_from_archival_storage(index, MAX_RANDOM_WALK_ROUNDS)
                            .map(|piece| (index, Ok(piece)))
                            .await
                    };
                    Box::pin(fut)
                });

        Ok(Box::new(stream))
    }
}

impl<PV> DsnPieceGetter<PV>
where
    PV: PieceValidator,
{
    /// Creates new DSN piece getter.
    pub fn new(piece_provider: PieceProvider<PV>) -> Self {
        Self(piece_provider)
    }
}
