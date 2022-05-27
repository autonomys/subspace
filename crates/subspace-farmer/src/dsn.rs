use crate::PiecesToPlot;
use futures::{Stream, StreamExt};
use std::ops::{ControlFlow, Range};
use std::sync::{Arc, Mutex};
use subspace_core_primitives::{FlatPieces, PieceIndex, PieceIndexHash, PublicKey, Sha256Hash};
use subspace_solving::U256;

#[cfg(test)]
mod tests;

pub type PieceIndexHashNumber = U256;

/// Options for syncing
pub struct SyncOptions {
    /// The size of request in pieces which we should request on average
    pub pieces_per_request: u64,
    /// The size of range which we request initially
    pub initial_range_size: PieceIndexHashNumber,
    /// The size of range at which we should stop syncing
    pub max_range_size: PieceIndexHashNumber,
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

// TODO: Can we know in advance amount of all pieces in the network? That would simplify the whole
// algorithm as it would simply request all pieces within expected range of pieces for which we can
// get rewards from the consensus.
/// Syncs pieces from the provided DSN.
///
/// It would query pieces going upwards and downwards. It will adjust the requested piece range in
/// order to ask the same amount of data over the network.
pub async fn sync<DSN, OP>(mut dsn: DSN, options: SyncOptions, on_pieces: OP) -> anyhow::Result<()>
where
    DSN: DSNSync + Send + Sized,
    DSN::Stream: Unpin + Send,
    // On pieces might `break` with some result from the sync or just continue
    OP: FnMut(FlatPieces, Vec<PieceIndex>) -> ControlFlow<anyhow::Result<()>> + Send + 'static,
{
    let mut range_size = options.initial_range_size;
    let mut increasing_cursor = PieceIndexHashNumber::from(Sha256Hash::from(options.address));
    let mut decreasing_cursor = increasing_cursor;
    let mut increasing = true;
    let on_pieces = Arc::new(Mutex::new(on_pieces));

    loop {
        let range = if increasing {
            let range = Range {
                start: increasing_cursor.into(),
                end: increasing_cursor.overflowing_add(range_size).0.into(),
            };
            increasing_cursor = increasing_cursor.overflowing_add(range_size).0;
            range
        } else {
            let range = Range {
                start: decreasing_cursor.overflowing_sub(range_size).0.into(),
                end: decreasing_cursor.into(),
            };
            decreasing_cursor = decreasing_cursor.overflowing_sub(range_size).0;
            range
        };

        let mut stream = dsn.get_pieces(range).await;
        let mut pieces_fetched = 0;
        while let Some(PiecesToPlot {
            piece_indexes,
            pieces,
        }) = stream.next().await
        {
            pieces_fetched += piece_indexes.len() as u64;

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

        // adjust range in order to request same amount of pieces over the DSN.
        let new_range =
            range_size.saturating_mul(pieces_fetched.into()) / options.pieces_per_request;
        if new_range != PieceIndexHashNumber::zero() {
            range_size = new_range;
        } else {
            range_size *= 2;
        }

        if range_size > options.max_range_size {
            // We synced all the namespace
            return Ok(());
        }
        increasing = !increasing;
    }
}
