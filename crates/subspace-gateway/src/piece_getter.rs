//! An object piece getter which uses the DSN to fetch pieces.

use async_trait::async_trait;
use futures::stream::StreamExt;
use std::fmt;
use std::ops::{Deref, DerefMut};
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_data_retrieval::piece_getter::{BoxError, ObjectPieceGetter};
use subspace_networking::utils::piece_provider::{PieceProvider, PieceValidator};
use subspace_networking::Node;

/// The maximum number of peer-to-peer walking rounds for L1 archival storage.
const MAX_RANDOM_WALK_ROUNDS: usize = 15;

/// Wrapper type for PieceProvider, so it can implement ObjectPieceGetter.
pub struct DsnPieceGetter<PV: PieceValidator>(pub PieceProvider<PV>);

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

impl<PV> Deref for DsnPieceGetter<PV>
where
    PV: PieceValidator,
{
    type Target = PieceProvider<PV>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<PV> DerefMut for DsnPieceGetter<PV>
where
    PV: PieceValidator,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// TODO:
// - change ObjectPieceGetter trait to take a list of piece indexes
// - move this piece getter impl into a new library part of this crate
#[async_trait]
impl<PV> ObjectPieceGetter for DsnPieceGetter<PV>
where
    PV: PieceValidator,
{
    async fn get_piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, BoxError> {
        if let Some((got_piece_index, maybe_piece)) =
            self.get_from_cache([piece_index]).await.next().await
        {
            assert_eq!(piece_index, got_piece_index);

            if let Some(piece) = maybe_piece {
                return Ok(Some(piece));
            }
        }

        Ok(self
            .get_piece_from_archival_storage(piece_index, MAX_RANDOM_WALK_ROUNDS)
            .await)
    }
}

impl<PV> DsnPieceGetter<PV>
where
    PV: PieceValidator,
{
    /// Creates new DSN piece getter.
    pub fn new(node: Node, piece_validator: PV) -> Self {
        Self(PieceProvider::new(node, piece_validator))
    }
}
