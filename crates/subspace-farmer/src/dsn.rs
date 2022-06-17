use crate::PiecesToPlot;
use futures::{Stream, StreamExt};
use num_traits::{WrappingAdd, WrappingSub};
use std::ops::Range;
use std::sync::{Arc, Mutex};
use subspace_core_primitives::{FlatPieces, PieceIndex, PieceIndexHash, PublicKey, Sha256Hash};
use subspace_solving::U256;

#[cfg(test)]
mod tests;

pub type PieceIndexHashNumber = U256;

/// Options for syncing
pub struct SyncOptions {
    /// Max plot size from node (in pieces)
    pub max_plot_size: u64,
    /// Total number of pieces in the network
    pub total_pieces: u64,
    /// The size of range which we request
    pub range_size: PieceIndexHashNumber,
    /// Public key of our plot
    pub public_key: PublicKey,
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
    OP: FnMut(FlatPieces, Vec<PieceIndex>) -> anyhow::Result<()> + Send + 'static,
{
    let SyncOptions {
        max_plot_size,
        total_pieces,
        range_size,
        public_key,
    } = options;
    let public_key = PieceIndexHashNumber::from(Sha256Hash::from(public_key));

    let sync_sector_size = if total_pieces < max_plot_size {
        PieceIndexHashNumber::MAX
    } else {
        PieceIndexHashNumber::MAX / total_pieces * max_plot_size
    };
    let from = public_key.wrapping_sub(&(sync_sector_size / 2));
    let on_pieces = Arc::new(Mutex::new(on_pieces));

    let mut offset = PieceIndexHashNumber::zero();

    while offset < sync_sector_size {
        let start = from.wrapping_add(&offset);
        let end = start.saturating_add(range_size);
        let mut stream = dsn
            .get_pieces(Range {
                start: start.into(),
                end: end.into(),
            })
            .await;

        while let Some(PiecesToPlot {
            piece_indexes,
            pieces,
        }) = stream.next().await
        {
            // Writing pieces is usually synchronous, therefore might take some time
            tokio::task::spawn_blocking({
                let on_pieces = Arc::clone(&on_pieces);
                move || {
                    let mut on_pieces = on_pieces
                        .lock()
                        .expect("Lock is never poisoned as `on_pieces` never panics");
                    on_pieces(pieces, piece_indexes)
                }
            })
            .await
            .expect("`on_pieces` must never panic")?;
        }

        // In case we ended at `MAX` we want to start from 0 next time
        offset = offset.saturating_add(if end == PieceIndexHashNumber::MAX {
            end - start + 1
        } else {
            range_size
        });
    }

    Ok(())
}
