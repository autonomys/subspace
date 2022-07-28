use async_trait::async_trait;
use futures::{SinkExt, Stream, StreamExt};
use num_traits::{WrappingAdd, WrappingSub};
use std::ops::Range;
use subspace_core_primitives::{
    FlatPieces, PieceIndex, PieceIndexHash, PublicKey, PIECE_SIZE, U256,
};
use subspace_networking::libp2p::core::multihash::{Code, MultihashDigest};
use subspace_networking::{PiecesByRangeRequest, PiecesByRangeResponse, PiecesToPlot};
use tracing::{debug, error, trace, warn};

#[cfg(test)]
mod pieces_by_range_tests;
#[cfg(test)]
mod tests;

const PIECES_CHANNEL_BUFFER_SIZE: usize = 20;

pub type PieceIndexHashNumber = U256;

#[derive(Debug, thiserror::Error)]
pub enum GetPiecesByRangeError {
    /// Cannot find closest pieces by range.
    #[error("Cannot find closest pieces by range")]
    NoClosestPiecesFound,
    /// Cannot get closest peers from DHT.
    #[error("Cannot get closest peers from DHT")]
    CannotGetClosestPeers(#[source] subspace_networking::GetClosestPeersError),
    /// Node runner was dropped, impossible to get pieces by range.
    #[error("Node runner was dropped, impossible to get pieces by range")]
    NodeRunnerDropped(#[source] subspace_networking::SendRequestError),
}

/// Options for syncing
pub struct SyncOptions {
    /// Max plot size from node (in bytes)
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
    type Error = GetPiecesByRangeError;

    async fn get_pieces(
        &mut self,
        Range { start, end }: Range<PieceIndexHash>,
    ) -> Result<Self::Stream, Self::Error> {
        // calculate the middle of the range (big endian)
        let middle = {
            let start = PieceIndexHashNumber::from(start);
            let end = PieceIndexHashNumber::from(end);
            // min + (max - min) / 2
            (start / 2 + end / 2).to_be_bytes()
        };

        // obtain closest peers to the middle of the range
        let key = Code::Identity.digest(&middle);
        let peers = self
            .get_closest_peers(key)
            .await
            .map_err(GetPiecesByRangeError::CannotGetClosestPeers)?;

        // select first peer for the piece-by-range protocol
        let peer_id = *peers
            .first()
            .ok_or(GetPiecesByRangeError::NoClosestPiecesFound)?;

        trace!(%peer_id, ?start, ?end, "Peer found");

        // prepare stream channel
        let (mut tx, rx) =
            futures::channel::mpsc::channel::<PiecesToPlot>(PIECES_CHANNEL_BUFFER_SIZE);

        // populate resulting stream in a separate async task
        let node = self.clone();
        tokio::spawn(async move {
            // indicates the next starting point for a request
            let mut starting_index_hash = start;
            loop {
                trace!(
                    "Sending 'Piece-by-range' request to {} with {:?}",
                    peer_id,
                    starting_index_hash
                );
                // request data by range
                let response = node
                    .send_generic_request(
                        peer_id,
                        PiecesByRangeRequest {
                            start: starting_index_hash,
                            end,
                        },
                    )
                    .await
                    .map_err(GetPiecesByRangeError::NodeRunnerDropped);

                // send the result to the stream and exit on any error
                match response {
                    Ok(PiecesByRangeResponse {
                        pieces,
                        next_piece_index_hash,
                    }) => {
                        // send last response data stream to the result stream
                        if !pieces.piece_indexes.is_empty() && tx.send(pieces).await.is_err() {
                            warn!("Piece-by-range request channel was closed.");
                            break;
                        }

                        // prepare the next starting point for data
                        if let Some(next_piece_index_hash) = next_piece_index_hash {
                            debug_assert_ne!(starting_index_hash, next_piece_index_hash);
                            starting_index_hash = next_piece_index_hash;
                        } else {
                            // exit loop if the last response showed no remaining data
                            break;
                        }
                    }
                    Err(err) => {
                        debug!(%err, "Piece-by-range request failed");
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }
}

/// Defines actions on receiving the pieces during the sync process.
#[async_trait]
pub trait OnSync {
    /// Defines a callback on receiving pieces.
    async fn on_pieces(
        &self,
        pieces: FlatPieces,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<()>;
}

/// Syncs the closest pieces to the public key from the provided DSN.
pub async fn sync<DSN, OP>(mut dsn: DSN, options: SyncOptions, on_sync: OP) -> anyhow::Result<()>
where
    DSN: DSNSync + Send + Sized,
    DSN::Stream: Unpin + Send,
    OP: OnSync,
{
    let SyncOptions {
        max_plot_size,
        total_pieces,
        range_size,
        public_key,
    } = options;
    let public_key = PieceIndexHashNumber::from_be_bytes(public_key.into());

    let sync_sector_size = if total_pieces < max_plot_size / PIECE_SIZE as u64 {
        PieceIndexHashNumber::MAX
    } else {
        PieceIndexHashNumber::MAX / total_pieces * (max_plot_size / PIECE_SIZE as u64)
    };
    let from = public_key.wrapping_sub(&(sync_sector_size / 2));

    let sync_ranges = std::iter::from_fn({
        let mut i = PieceIndexHashNumber::zero();

        move || {
            let offset_start = i.checked_mul(&range_size)?.checked_add(
                // Do not include the same number twice
                &if i == PieceIndexHashNumber::zero() {
                    PieceIndexHashNumber::zero()
                } else {
                    PieceIndexHashNumber::one()
                },
            )?;

            let offset_end = (i + PieceIndexHashNumber::one())
                .saturating_mul(&range_size)
                .min(sync_sector_size);

            i = i + PieceIndexHashNumber::one();

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
                Some((sub_sector_start, PieceIndexHashNumber::MAX)),
                Some((PieceIndexHashNumber::zero(), sub_sector_end)),
            ]
        } else {
            [Some((sub_sector_start, sub_sector_end)), None]
        }
    })
    .flatten();

    for (start, end) in sync_ranges {
        let mut stream = dsn.get_pieces(start.into()..end.into()).await?;

        while let Some(pieces_to_plot) = stream.next().await {
            let PiecesToPlot {
                piece_indexes,
                pieces,
            } = pieces_to_plot;

            // Filter out pieces which are not in our range
            let (piece_indexes, pieces) = piece_indexes
                .into_iter()
                .zip(pieces.as_pieces())
                .filter(|(index, _)| {
                    (start..end).contains(&PieceIndexHashNumber::from(PieceIndexHash::from_index(
                        *index,
                    )))
                })
                .map(|(index, piece)| {
                    (
                        index,
                        piece
                            .try_into()
                            .expect("`as_pieces` always returns a piece"),
                    )
                })
                .unzip();

            if let Err(err) = on_sync.on_pieces(pieces, piece_indexes).await {
                error!(%err, "DSN sync process returned an error");
            }
        }
    }

    Ok(())
}
