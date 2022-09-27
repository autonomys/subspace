//TODO: Restore dsn-sync or remove unused code.
#![allow(dead_code)] // Gather related code here until we enable DSN sync for v2.

use crate::single_plot_farm::SinglePlotPlotter;
use crate::utils::CallOnDrop;
use crate::RpcClient;
use async_trait::async_trait;
use futures::channel::{mpsc, oneshot};
use futures::future::try_join_all;
use futures::{SinkExt, Stream, StreamExt};
use num_traits::{WrappingAdd, WrappingSub, Zero};
use scopeguard::guard;
use std::future::Future;
use std::ops::Range;
use subspace_archiving::archiver::is_piece_valid;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    FlatPieces, PieceIndex, PieceIndexHash, PublicKey, RecordsRoot, PIECE_SIZE, U256,
};
use subspace_networking::libp2p::core::multihash::{Code, MultihashDigest};
use subspace_networking::{
    Node, PeerInfo, PeerInfoRequest, PeerInfoResponse, PeerSyncStatus, PiecesByRangeRequest,
    PiecesByRangeResponse, PiecesToPlot,
};
use subspace_rpc_primitives::{FarmerProtocolInfo, MAX_SEGMENT_INDEXES_PER_REQUEST};
use thiserror::Error;
use tracing::{debug, error, trace, warn, Span};

#[cfg(test)]
mod tests;

const PIECES_CHANNEL_BUFFER_SIZE: usize = 20;
const GET_CLOSEST_PEER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(7);

pub type PieceIndexHashNumber = U256;

mod private {
    use futures::channel::{mpsc, oneshot};
    use futures::Stream;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use subspace_networking::PiecesToPlot;

    pub struct NodePiecesStream {
        rx: Option<mpsc::Receiver<PiecesToPlot>>,
        task_end_rx: Option<oneshot::Receiver<()>>,
    }

    impl NodePiecesStream {
        pub(super) fn new(
            rx: mpsc::Receiver<PiecesToPlot>,
            task_end_rx: oneshot::Receiver<()>,
        ) -> Self {
            Self {
                rx: Some(rx),
                task_end_rx: Some(task_end_rx),
            }
        }
    }

    impl Stream for NodePiecesStream {
        type Item = PiecesToPlot;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Pin::new(self.rx.as_mut().expect("Only removed on drop; qed")).poll_next(cx)
        }
    }

    impl Drop for NodePiecesStream {
        fn drop(&mut self) {
            self.rx.take();
            // Wait for background task to finish before exiting
            let _ = futures::executor::block_on(
                self.task_end_rx
                    .take()
                    .expect("Drop is only called once; qed"),
            );
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GetPiecesByRangeError {
    /// Cannot get closest peers from DHT.
    #[error("Cannot get closest peers from DHT: {0}")]
    CannotGetClosestPeers(#[source] subspace_networking::GetClosestPeersError),
    /// There are no farmers which support our protocol
    #[error("There are no farmers which support our protocol")]
    NoSupportedFarmer,
    /// Node runner was dropped, impossible to get pieces by range.
    #[error("Node runner was dropped, impossible to get pieces by range: {0}")]
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
    type Error: std::error::Error + Send + Sync + 'static;

    /// Notifies about the start of the peer synchronization from the DSN.
    fn notify_sync_start(&self);

    /// Notifies about the end of the peer synchronization from the DSN.
    fn notify_sync_end(&self);

    /// Get pieces from the network which fall within the range
    async fn get_pieces(
        &mut self,
        range: Range<PieceIndexHash>,
    ) -> Result<Box<dyn Stream<Item = PiecesToPlot> + Unpin + Send>, Self::Error>;
}

/// Marker which disables sync
#[derive(Clone, Copy, Debug)]
pub struct NoSync;

#[async_trait::async_trait]
impl DSNSync for NoSync {
    type Error = std::convert::Infallible;

    fn notify_sync_start(&self) {}

    fn notify_sync_end(&self) {}

    async fn get_pieces(
        &mut self,
        _range: Range<PieceIndexHash>,
    ) -> Result<Box<dyn Stream<Item = PiecesToPlot> + Unpin + Send>, Self::Error> {
        Ok(Box::new(futures::stream::empty()))
    }
}

#[async_trait::async_trait]
impl DSNSync for subspace_networking::Node {
    type Error = GetPiecesByRangeError;

    fn notify_sync_start(&self) {
        self.sync_status_handler().toggle_on();
    }

    fn notify_sync_end(&self) {
        self.sync_status_handler().toggle_off();
    }

    async fn get_pieces(
        &mut self,
        Range { start, end }: Range<PieceIndexHash>,
    ) -> Result<Box<dyn Stream<Item = PiecesToPlot> + Unpin + Send>, Self::Error> {
        // calculate the middle of the range (big endian)
        let middle = {
            let start = PieceIndexHashNumber::from(start);
            let end = PieceIndexHashNumber::from(end);
            // min + (max - min) / 2
            (start / 2 + end / 2).to_be_bytes()
        };

        // obtain closest peers to the middle of the range
        let key = Code::Identity.digest(&middle);
        let peer_id = {
            let node = self.clone();

            backoff::future::retry(
                backoff::ExponentialBackoffBuilder::new()
                    .with_max_elapsed_time(Some(GET_CLOSEST_PEER_TIMEOUT))
                    .build(),
                move || {
                    let node = node.clone();
                    async move {
                        let peers = node
                            .get_closest_peers(key)
                            .await
                            .map_err(GetPiecesByRangeError::CannotGetClosestPeers)?;
                        tracing::debug!(?peers, "Received peers");

                        // select first peer for the piece-by-range protocol
                        for id in peers {
                            match node.send_generic_request(id, PeerInfoRequest).await {
                                Ok(PeerInfoResponse { peer_info: PeerInfo { status }}) => if status == PeerSyncStatus::Ready {
                                    return Ok(id)
                                } else {
                                    trace!(%id, ?status, "Peer is not ready for synchronization")
                                },
                                Err(err) => {
                                    debug!(%id, %err, "Peer info request returned an error")
                                }
                            }
                        }

                        Err(backoff::Error::transient(
                            GetPiecesByRangeError::NoSupportedFarmer,
                        ))
                    }
                },
            )
            .await?
        };

        trace!(%peer_id, ?start, ?end, "Peer found");

        // prepare stream channel
        let (task_end_tx, task_end_rx) = oneshot::channel::<()>();
        let (mut tx, rx) = mpsc::channel::<PiecesToPlot>(PIECES_CHANNEL_BUFFER_SIZE);

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
            drop(node);
            let _ = task_end_tx.send(());
        });

        Ok(Box::new(private::NodePiecesStream::new(rx, task_end_rx)))
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
pub async fn sync<DSN, OP>(dsn: DSN, options: SyncOptions, on_sync: OP) -> anyhow::Result<()>
where
    DSN: DSNSync + Send + Sized,
    OP: OnSync,
{
    dsn.notify_sync_start();
    // We redefine dsn variable to call notify_sync_end() at return of the scope or panic
    let mut dsn = guard(dsn, |dsn| dsn.notify_sync_end());

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

/// Pieces verification errors.
#[derive(Error, Debug)]
pub enum PiecesVerificationError {
    /// Invalid pieces data provided
    #[error("Invalid pieces data provided")]
    InvalidRawData,
    /// Invalid farmer protocol info provided
    #[error("Invalid farmer protocol info provided")]
    InvalidFarmerProtocolInfo,
    /// Pieces verification failed.
    #[error("Pieces verification failed.")]
    InvalidPieces,
    /// RPC client failed.
    #[error("RPC client failed. jsonrpsee error: {0}")]
    RpcError(Box<dyn std::error::Error + Send + Sync>),
    /// RPC client returned empty records_root.
    #[error("RPC client returned empty records root.")]
    NoRecordsRootFound,
}

// Defines actions on receiving pieces batch. It verifies the pieces against the blockchain and
// plots them.
struct VerifyingPlotter<RC> {
    // RPC client for verification
    verification_client: RC,
    span: Span,
    single_plot_plotter: SinglePlotPlotter,
    farmer_protocol_info: FarmerProtocolInfo,
    pieces_verification_enabled: bool,
    kzg: Kzg,
}

impl<RC: RpcClient> VerifyingPlotter<RC> {
    // Verifies pieces against the blockchain.
    async fn verify_pieces_at_blockchain(
        &self,
        piece_indexes: &[PieceIndex],
        pieces: &FlatPieces,
    ) -> Result<(), PiecesVerificationError> {
        if piece_indexes.len() != pieces.count() {
            return Err(PiecesVerificationError::InvalidRawData);
        }

        let pieces_in_segment = self.farmer_protocol_info.recorded_history_segment_size
            / self.farmer_protocol_info.record_size.get()
            * 2;
        if pieces_in_segment.is_zero() {
            return Err(PiecesVerificationError::InvalidFarmerProtocolInfo);
        }

        // Calculate segment indexes collection
        let segment_indexes = piece_indexes
            .iter()
            .map(|piece_index| piece_index / u64::from(pieces_in_segment))
            .collect::<Vec<_>>();

        // Split segment indexes collection into allowed max sized chunks
        // and run a future records_roots RPC call for each chunk.
        let roots_futures = segment_indexes
            .chunks(MAX_SEGMENT_INDEXES_PER_REQUEST)
            .map(|segment_indexes_chunk| {
                self.verification_client
                    .records_roots(segment_indexes_chunk.to_vec())
            })
            .collect::<Vec<_>>();

        // Wait for all the RPC calls, flatten the results collection,
        // and check for empty result for any of the records root call.
        let roots = try_join_all(roots_futures)
            .await
            .map_err(|err| PiecesVerificationError::RpcError(err))?
            .into_iter()
            .flatten()
            .zip(piece_indexes.iter())
            .map(|(root, piece_index)| {
                if let Some(root) = root {
                    Ok(root)
                } else {
                    error!(piece_index, "No records root found for piece_index.");

                    Err(PiecesVerificationError::NoRecordsRootFound)
                }
            })
            .collect::<Result<Vec<RecordsRoot>, PiecesVerificationError>>()?;

        // Perform an actual piece validity check
        for ((piece, piece_index), root) in pieces.as_pieces().zip(piece_indexes).zip(roots) {
            let position = u32::try_from(piece_index % u64::from(pieces_in_segment))
                .expect("Position within segment always fits into u32; qed");

            if !is_piece_valid(
                &self.kzg,
                pieces_in_segment,
                piece,
                root,
                position,
                self.farmer_protocol_info.record_size.get(),
            ) {
                error!(?piece_index, "Piece validation failed.");

                return Err(PiecesVerificationError::InvalidPieces);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<RC: RpcClient> OnSync for VerifyingPlotter<RC> {
    #[tracing::instrument(parent = &self.span, skip_all)]
    async fn on_pieces(
        &self,
        pieces: FlatPieces,
        piece_indexes: Vec<PieceIndex>,
    ) -> anyhow::Result<()> {
        if self.pieces_verification_enabled {
            self.verify_pieces_at_blockchain(&piece_indexes, &pieces)
                .await?;
        }

        let plotter = self.single_plot_plotter.clone();
        let (farm_creation_start_sender, farm_creation_start_receiver) =
            std::sync::mpsc::sync_channel(1);
        // Makes sure background blocking task below is finished before this function's future is
        // dropped
        let _plot_pieces_guard = CallOnDrop::new(move || {
            let _ = farm_creation_start_receiver.recv();
        });
        tokio::task::spawn_blocking(move || {
            plotter.plot_pieces(PiecesToPlot {
                pieces,
                piece_indexes,
            })?;

            let _ = farm_creation_start_sender.send(());

            Ok(())
        })
        .await?
    }
}

//TODO: Refactor dsn-sync on code restoring.
#[allow(clippy::too_many_arguments)]
pub fn dsn_sync<RC: RpcClient>(
    verification_client: RC,
    farmer_protocol_info: FarmerProtocolInfo,
    range_size: PieceIndexHashNumber,
    pieces_verification_enabled: bool,
    node: Node,
    span: Span,
    plotter: SinglePlotPlotter,
    public_key: PublicKey,
) -> impl Future<Output = anyhow::Result<()>> {
    let options = SyncOptions {
        range_size,
        public_key,
        max_plot_size: farmer_protocol_info.max_plot_size,
        total_pieces: farmer_protocol_info.total_pieces,
    };

    let kzg = Kzg::new(kzg::test_public_parameters());

    let plotter = VerifyingPlotter {
        single_plot_plotter: plotter,
        span,
        verification_client,
        farmer_protocol_info,
        pieces_verification_enabled,
        kzg,
    };

    sync(node, options, plotter)
}
