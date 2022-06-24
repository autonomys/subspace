use futures::{Stream, StreamExt};
use num_traits::{WrappingAdd, WrappingSub};
use std::ops::Range;
use subspace_core_primitives::{
    FlatPieces, PieceIndex, PieceIndexHash, PublicKey, Sha256Hash, U256,
};
use subspace_networking::PiecesToPlot;

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
    type Error: std::error::Error + Send + Sync + 'static;

    /// Get pieces from the network which fall within the range
    async fn get_pieces(
        &mut self,
        range: Range<PieceIndexHash>,
    ) -> Result<Self::Stream, Self::Error>;
}

/// Marker which disables sync
#[derive(Clone, Copy, Debug)]
pub struct NoSync;

#[async_trait::async_trait]
impl DSNSync for NoSync {
    type Stream = futures::stream::Empty<PiecesToPlot>;
    type Error = std::convert::Infallible;

    async fn get_pieces(
        &mut self,
        _range: Range<PieceIndexHash>,
    ) -> Result<Self::Stream, Self::Error> {
        Ok(futures::stream::empty())
    }
}

#[async_trait::async_trait]
impl DSNSync for subspace_networking::Node {
    type Stream = futures::channel::mpsc::Receiver<PiecesToPlot>;
    type Error = subspace_networking::GetPiecesByRangeError;

    async fn get_pieces(
        &mut self,
        Range { start, end }: Range<PieceIndexHash>,
    ) -> Result<Self::Stream, Self::Error> {
        self.get_pieces_by_range(start, end).await
    }
}

/// Syncs the closest pieces to the public key from the provided DSN.
pub async fn sync<DSN, OP>(
    mut dsn: DSN,
    options: SyncOptions,
    mut on_pieces: OP,
) -> anyhow::Result<()>
where
    DSN: DSNSync + Send + Sized,
    DSN::Stream: Unpin + Send,
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

    let sync_ranges = std::iter::from_fn({
        let mut i = PieceIndexHashNumber::zero();

        move || {
            let offset_start = i.checked_mul(range_size)?.checked_add(
                // Do not include the same number twice
                if i == PieceIndexHashNumber::zero() {
                    PieceIndexHashNumber::zero()
                } else {
                    PieceIndexHashNumber::one()
                },
            )?;

            let offset_end = (i + 1).saturating_mul(range_size).min(sync_sector_size);

            i += PieceIndexHashNumber::one();

            if offset_start <= sync_sector_size {
                Some((offset_start, offset_end))
            } else {
                None
            }
        }
    })
    .flat_map(|(offset_start, offset_end)| {
        let sub_sector_start = offset_start.wrapping_add(&from);
        let sub_sector_end = offset_end.wrapping_add(&from);

        if sub_sector_start > sub_sector_end {
            [
                Some((PieceIndexHashNumber::zero(), sub_sector_end)),
                Some((sub_sector_start, PieceIndexHashNumber::MAX)),
            ]
        } else {
            [Some((sub_sector_start, sub_sector_end)), None]
        }
    })
    .flatten()
    .map(|(start, end)| Range {
        start: start.into(),
        end: end.into(),
    });

    for range in sync_ranges {
        let mut stream = dsn.get_pieces(range).await?;

        while let Some(PiecesToPlot {
            piece_indexes,
            pieces,
        }) = stream.next().await
        {
            // Writing pieces is usually synchronous, therefore might take some time
            on_pieces = tokio::task::spawn_blocking(move || {
                on_pieces(pieces, piece_indexes).map(|()| on_pieces)
            })
            .await
            .expect("`on_pieces` must never panic")?;
        }
    }

    Ok(())
}
