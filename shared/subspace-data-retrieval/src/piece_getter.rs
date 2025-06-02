//! Getting object pieces from the Subspace Distributed Storage Network, or various caches.

use async_trait::async_trait;
use futures::{Stream, StreamExt, stream};
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use subspace_archiving::archiver::NewArchivedSegment;
use subspace_core_primitives::pieces::{Piece, PieceIndex};

/// Trait representing a way to get pieces
#[async_trait]
pub trait PieceGetter: fmt::Debug {
    /// Get piece by index.
    ///
    /// Returns `Ok(None)` if the piece is not found.
    /// Returns `Err(_)` if trying to get the piece caused an error.
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>>;

    /// Get pieces with provided indices.
    ///
    /// The number of elements in the returned stream is the same as the number of unique
    /// `piece_indices`.
    async fn get_pieces<'a>(
        &'a self,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    >;

    /// Returns a piece getter that falls back to `other` if `self` does not return the piece.
    /// Piece getters may need to be wrapped in `Arc` to be used with this method.
    fn with_fallback<U>(self, other: U) -> FallbackPieceGetter<Self, U>
    where
        Self: Send + Sync + Sized,
        U: PieceGetter + Send + Sync,
    {
        FallbackPieceGetter {
            first: self,
            second: other,
        }
    }
}

/// A piece getter that falls back to another piece getter if the first one does not return the piece.
/// If both piece getters don't return the piece, returns the result of the second piece getter.
#[derive(Debug)]
pub struct FallbackPieceGetter<T, U>
where
    T: PieceGetter + Send + Sync,
    U: PieceGetter + Send + Sync,
{
    first: T,
    second: U,
}

#[async_trait]
impl<T, U> PieceGetter for FallbackPieceGetter<T, U>
where
    T: PieceGetter + Send + Sync,
    U: PieceGetter + Send + Sync,
{
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        if let Ok(Some(piece)) = self.first.get_piece(piece_index).await {
            Ok(Some(piece))
        } else {
            self.second.get_piece(piece_index).await
        }
    }

    async fn get_pieces<'a>(
        &'a self,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    > {
        let first_stream = self.first.get_pieces(piece_indices.clone()).await;

        let fallback_stream = if let Ok(first_stream) = first_stream {
            // For each missing piece, try the second piece getter
            Box::new(Box::pin(first_stream.then(
                |(piece_index, piece_result)| fallback_to(piece_index, piece_result, &self.second),
            )))
                as Box<
                    dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin,
                >
        } else {
            // If no pieces are available, just use the second piece getter
            self.second.get_pieces(piece_indices).await?
        };

        Ok(fallback_stream)
    }
}

/// A heler function which falls back to another piece getter if the first one does not return the
/// piece.
///
/// We can't use an async closure, because async closures eagerly capture lifetimes.
async fn fallback_to<U>(
    piece_index: PieceIndex,
    piece_result: anyhow::Result<Option<Piece>>,
    second: &U,
) -> (PieceIndex, anyhow::Result<Option<Piece>>)
where
    U: PieceGetter,
{
    if let Ok(Some(piece)) = piece_result {
        return (piece_index, Ok(Some(piece)));
    }

    (piece_index, second.get_piece(piece_index).await)
}

// Generic wrapper methods
#[async_trait]
impl<T> PieceGetter for Arc<T>
where
    T: PieceGetter + Send + Sync + ?Sized,
{
    #[inline]
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        self.as_ref().get_piece(piece_index).await
    }

    #[inline]
    async fn get_pieces<'a>(
        &'a self,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    > {
        self.as_ref().get_pieces(piece_indices).await
    }
}

#[async_trait]
impl<T> PieceGetter for Box<T>
where
    T: PieceGetter + Send + Sync + ?Sized,
{
    #[inline]
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        self.as_ref().get_piece(piece_index).await
    }

    #[inline]
    async fn get_pieces<'a>(
        &'a self,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    > {
        self.as_ref().get_pieces(piece_indices).await
    }
}

#[async_trait]
impl<T> PieceGetter for Option<T>
where
    T: PieceGetter + Send + Sync,
{
    #[inline]
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        if let Some(piece_getter) = self.as_ref() {
            piece_getter.get_piece(piece_index).await
        } else {
            Ok(None)
        }
    }

    #[inline]
    async fn get_pieces<'a>(
        &'a self,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    > {
        if let Some(piece_getter) = self.as_ref() {
            piece_getter.get_pieces(piece_indices).await
        } else {
            // The values will all be `Ok(None)`, but we need a stream of them
            get_pieces_individually(|piece_index| self.get_piece(piece_index), piece_indices)
        }
    }
}

// Convenience methods, mainly used in testing
#[async_trait]
impl PieceGetter for NewArchivedSegment {
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        if piece_index.segment_index() == self.segment_header.segment_index() {
            return Ok(Some(
                self.pieces
                    .pieces()
                    .nth(piece_index.position() as usize)
                    .expect("Piece position always exists in a segment; qed"),
            ));
        }

        Ok(None)
    }

    async fn get_pieces<'a>(
        &'a self,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    > {
        get_pieces_individually(|piece_index| self.get_piece(piece_index), piece_indices)
    }
}

// Used for piece caches
#[async_trait]
impl PieceGetter for (PieceIndex, Piece) {
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        if self.0 == piece_index {
            return Ok(Some(self.1.clone()));
        }

        Ok(None)
    }

    async fn get_pieces<'a>(
        &'a self,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    > {
        get_pieces_individually(|piece_index| self.get_piece(piece_index), piece_indices)
    }
}

#[async_trait]
impl PieceGetter for Vec<(PieceIndex, Piece)> {
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        Ok(self.iter().find_map(|(index, piece)| {
            if *index == piece_index {
                Some(piece.clone())
            } else {
                None
            }
        }))
    }

    async fn get_pieces<'a>(
        &'a self,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    > {
        get_pieces_individually(|piece_index| self.get_piece(piece_index), piece_indices)
    }
}

/// A default implementation which gets each piece individually, using the `get_piece` async
/// function.
///
/// This is mainly used for testing and caches. Most production implementations can fetch multiple
/// pieces more efficiently.
#[expect(clippy::type_complexity, reason = "type matches trait signature")]
pub fn get_pieces_individually<'a, PieceIndices, Func, Fut>(
    // TODO: replace with AsyncFn(PieceIndex) -> anyhow::Result<Option<Piece>> once it stabilises
    // https://github.com/rust-lang/rust/issues/62290
    get_piece: Func,
    piece_indices: PieceIndices,
) -> anyhow::Result<
    Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
>
where
    PieceIndices: IntoIterator<Item = PieceIndex, IntoIter: Send> + Send + 'a,
    Func: Fn(PieceIndex) -> Fut + Clone + Send + 'a,
    Fut: Future<Output = anyhow::Result<Option<Piece>>> + Send + Unpin + 'a,
{
    Ok(Box::new(Box::pin(stream::iter(piece_indices).then(
        move |piece_index| {
            let get_piece = get_piece.clone();
            async move { (piece_index, get_piece(piece_index).await) }
        },
    ))))
}
