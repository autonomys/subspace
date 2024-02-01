use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::debug;

/// Defines the minimum size of the "connection limit semaphore".
const MINIMUM_CONNECTIONS_SEMAPHORE_SIZE: usize = 3;

/// Empiric parameter for connection timeout and retry parameters (total retries and backoff time).
const CONNECTION_TIMEOUT_PARAMETER: usize = 2;

#[derive(Debug)]
pub(crate) struct RateLimiter {
    connections_semaphore: Arc<Semaphore>,
}

impl RateLimiter {
    pub(crate) fn new(out_connections: u32, pending_out_connections: u32) -> Self {
        let permits = Self::calculate_connection_semaphore_size(
            out_connections as usize,
            pending_out_connections as usize,
        );

        debug!(%out_connections, %pending_out_connections, %permits, "Rate limiter was instantiated.");

        Self {
            connections_semaphore: Arc::new(Semaphore::new(permits.get())),
        }
    }

    /// Calculates an empiric formula for the semaphore size based on the connection parameters and
    /// existing constants.
    fn calculate_connection_semaphore_size(
        out_connections: usize,
        pending_out_connections: usize,
    ) -> NonZeroUsize {
        let connections = out_connections.min(pending_out_connections);

        // Number of "in-flight" parallel requests for each query
        let kademlia_parallelism_level = libp2p::kad::ALPHA_VALUE.get();

        let permits_number =
            (connections / (kademlia_parallelism_level * CONNECTION_TIMEOUT_PARAMETER)).max(1);

        let minimum_semaphore_size =
            NonZeroUsize::new(MINIMUM_CONNECTIONS_SEMAPHORE_SIZE).expect("Manual setting");

        NonZeroUsize::new(permits_number)
            .expect("The value is at least 1")
            .max(minimum_semaphore_size)
    }

    pub(crate) async fn acquire_permit(&self) -> OwnedSemaphorePermit {
        self.connections_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("We never close semaphore.")
    }
}
