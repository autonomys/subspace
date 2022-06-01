use crate::PiecesToPlot;
use futures::{Stream, StreamExt};
use num_traits::WrappingAdd;
use std::ops::{ControlFlow, Range};
use std::sync::{Arc, Mutex};
use subspace_core_primitives::{FlatPieces, PieceIndex, PieceIndexHash, PublicKey, Sha256Hash};
use subspace_solving::U256;

#[cfg(test)]
mod tests;

pub type PieceIndexHashNumber = U256;

/// Options for syncing
pub struct SyncOptions {
    /// The size of range which we request
    pub range_size: PieceIndexHashNumber,
    /// Address of our plot
    pub address: PublicKey,
}

#[async_trait::async_trait]
pub trait DSNSync {
    type Stream: Stream<Item = PiecesToPlot>;

    /// Get pieces from the network which fall within the range
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

/// Syncs the closest pieces to the public key from the provided DSN.
///
/// It would sync piece with ranges providing in the `options`. It would go concurently upwards and
/// downwards from address and will either ask all available pieces and end at `options.address -
/// PieceIndexHashNumber::MAX / 2` or if `on_pieces` callback decides to break with any result.
pub async fn sync<DSN, OP>(mut dsn: DSN, options: SyncOptions, on_pieces: OP) -> anyhow::Result<()>
where
    DSN: DSNSync + Send + Sized,
    DSN::Stream: Unpin + Send,
    // On pieces might `break` with some result from the sync or just continue
    OP: FnMut(FlatPieces, Vec<PieceIndex>) -> ControlFlow<anyhow::Result<()>> + Send + 'static,
{
    let SyncOptions {
        range_size,
        address,
    } = options;
    let mut increasing_cursor = PieceIndexHashNumber::from(Sha256Hash::from(address));
    let mut decreasing_cursor = increasing_cursor;
    let mut increasing = true;
    let on_pieces = Arc::new(Mutex::new(on_pieces));
    let stop_at = increasing_cursor.wrapping_add(&(PieceIndexHashNumber::MAX / 2));

    while increasing_cursor < stop_at || decreasing_cursor > stop_at {
        let mut stream: Box<dyn Stream<Item = PiecesToPlot> + Unpin + Send> = if increasing {
            let start = increasing_cursor;
            let (end, is_overflow) = start.overflowing_add(range_size);
            increasing_cursor = end;

            if !is_overflow {
                let stream = dsn
                    .get_pieces(Range {
                        start: start.into(),
                        end: end.into(),
                    })
                    .await;
                Box::new(stream)
            } else {
                let stream = dsn
                    .get_pieces(Range {
                        start: start.into(),
                        end: PieceIndexHashNumber::MAX.into(),
                    })
                    .await
                    .chain(
                        dsn.get_pieces(Range {
                            start: PieceIndexHashNumber::zero().into(),
                            end: end.into(),
                        })
                        .await,
                    );
                Box::new(stream)
            }
        } else {
            let end = decreasing_cursor;
            let (start, is_underflow) = end.overflowing_sub(range_size);
            decreasing_cursor = start;

            if !is_underflow {
                let stream = dsn
                    .get_pieces(Range {
                        start: start.into(),
                        end: end.into(),
                    })
                    .await;
                Box::new(stream)
            } else {
                let stream = dsn
                    .get_pieces(Range {
                        start: start.into(),
                        end: end.into(),
                    })
                    .await
                    .chain(
                        dsn.get_pieces(Range {
                            start: start.into(),
                            end: end.into(),
                        })
                        .await,
                    );
                Box::new(stream)
            }
        };

        while let Some(PiecesToPlot {
            piece_indexes,
            pieces,
        }) = stream.next().await
        {
            // Writing pieces is usually synchronous, therefore might take some time
            if let ControlFlow::Break(result) = tokio::task::spawn_blocking({
                let on_pieces = Arc::clone(&on_pieces);
                move || {
                    let mut on_pieces = on_pieces
                        .lock()
                        .expect("Lock is never poisoned as `on_pieces` never panics");
                    on_pieces(pieces, piece_indexes)
                }
            })
            .await
            .expect("`on_pieces` must never panic")
            {
                return result;
            }
        }

        increasing = !increasing;
    }

    Ok(())
}
