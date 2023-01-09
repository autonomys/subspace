use backoff::future::retry;
use backoff::ExponentialBackoff;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{PieceIndex, PieceIndexHash};
use subspace_networking::utils::multihash::MultihashCode;
use subspace_networking::{FixedProviderRecordStorage, Node, ToMultihash};
use tokio::time::error::Elapsed;
use tokio::time::timeout;
use tracing::{debug, error, info, trace};

/// Max time allocated for putting piece from DSN before attempt is considered to fail
const PUT_PIECE_TIMEOUT: Duration = Duration::from_secs(120);
/// Defines initial duration between put_piece calls.
const PUT_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(1);
/// Defines max duration between put_piece calls.
const PUT_PIECE_MAX_INTERVAL: Duration = Duration::from_secs(30);

// Piece-by-sector DSN publishing helper.
#[derive(Clone)]
pub(crate) struct PieceSectorPublisher<FPRS: FixedProviderRecordStorage> {
    dsn_node: Node,
    cancelled: Arc<AtomicBool>,
    fixed_provider_storage: FPRS,
}

impl<FPRS: FixedProviderRecordStorage> PieceSectorPublisher<FPRS> {
    pub(crate) fn new(
        dsn_node: Node,
        cancelled: Arc<AtomicBool>,
        fixed_provider_storage: FPRS,
    ) -> Self {
        Self {
            dsn_node,
            cancelled,
            fixed_provider_storage,
        }
    }

    fn check_cancellation(&self) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        if self.cancelled.load(Ordering::Acquire) {
            debug!("Piece publishing was cancelled.");

            return Err("Piece publishing was cancelled.".into());
        }

        Ok(())
    }

    // Publishes pieces-by-sector to DSN in bulk. Supports cancellation.
    pub(crate) async fn publish_pieces(
        &self,
        piece_indexes: Vec<PieceIndex>,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let mut pieces_publishing_futures = piece_indexes
            .iter()
            .map(|piece_index| self.publish_single_piece_with_backoff(*piece_index))
            .collect::<FuturesUnordered<_>>();

        while pieces_publishing_futures.next().await.is_some() {
            self.check_cancellation()?;
        }

        info!("Piece publishing was successful.");

        Ok(())
    }

    async fn publish_single_piece_with_backoff(
        &self,
        piece_index: PieceIndex,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let backoff = ExponentialBackoff {
            initial_interval: PUT_PIECE_INITIAL_INTERVAL,
            max_interval: PUT_PIECE_MAX_INTERVAL,
            // Try until we get a valid piece
            max_elapsed_time: None,
            ..ExponentialBackoff::default()
        };

        retry(backoff, || async {
            self.check_cancellation()
                .map_err(backoff::Error::Permanent)?;

            let publish_timeout_result: Result<Result<(), _>, Elapsed> =
                timeout(PUT_PIECE_TIMEOUT, self.publish_single_piece(piece_index)).await;

            if let Ok(publish_result) = publish_timeout_result {
                if publish_result.is_ok() {
                    return Ok(());
                }
            }

            error!(%piece_index, "Couldn't publish a piece. Retrying...");

            Err(backoff::Error::transient(
                "Couldn't publish piece to DSN".into(),
            ))
        })
        .await
    }

    async fn publish_single_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        self.check_cancellation()?;

        let key =
            PieceIndexHash::from_index(piece_index).to_multihash_by_code(MultihashCode::Sector);

        self.fixed_provider_storage
            .register_fixed_local_provider(&key.into());

        let result = self.dsn_node.start_announcing(key).await;

        match result {
            Err(error) => {
                debug!(?error, %piece_index, ?key, "Piece publishing for a sector returned an error");

                Err("Piece publishing failed".into())
            }
            Ok(mut stream) => {
                if stream.next().await.is_some() {
                    trace!(%piece_index, ?key, "Piece publishing for a sector succeeded");

                    Ok(())
                } else {
                    debug!(%piece_index, ?key, "Piece publishing for a sector failed");

                    Err("Piece publishing was unsuccessful".into())
                }
            }
        }
    }
}
