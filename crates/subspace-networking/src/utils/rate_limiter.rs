pub(crate) mod resizable_semaphore;
#[cfg(test)]
mod tests;

use crate::utils::rate_limiter::resizable_semaphore::{
    ResizableSemaphore, ResizableSemaphorePermit, SemaphoreError,
};
use std::num::NonZeroUsize;
use tracing::{debug, trace};

/// Base limit for number of concurrent tasks initiated towards Kademlia.
///
/// We restrict this so we can manage outgoing requests a bit better by cancelling low-priority
/// requests, but this value will be boosted depending on number of connected peers.
const KADEMLIA_BASE_CONCURRENT_TASKS: NonZeroUsize = NonZeroUsize::new(15).expect("Not zero; qed");
/// Above base limit will be boosted by specified number for every peer connected starting with
/// second peer, such that it scaled with network connectivity, but the exact coefficient might need
/// to be tweaked in the future.
pub(crate) const KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER: usize = 15;
/// Base limit for number of any concurrent tasks except Kademlia.
///
/// We configure total number of streams per connection to 256. Here we assume half of them might be
/// incoming and half outgoing, we also leave a small buffer of streams just in case.
///
/// We restrict this so we don't exceed number of streams for single peer, but this value will be
/// boosted depending on number of connected peers.
const REGULAR_BASE_CONCURRENT_TASKS: NonZeroUsize =
    NonZeroUsize::new(50 - KADEMLIA_BASE_CONCURRENT_TASKS.get()).expect("Not zero; qed");
/// Above base limit will be boosted by specified number for every peer connected starting with
/// second peer, such that it scaled with network connectivity, but the exact coefficient might need
/// to be tweaked in the future.
pub(crate) const REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER: usize = 25;

/// Defines the minimum size of the "connection limit semaphore".
const MINIMUM_CONNECTIONS_SEMAPHORE_SIZE: usize = 3;

/// Empiric parameter for connection timeout and retry parameters (total retries and backoff time).
const CONNECTION_TIMEOUT_PARAMETER: usize = 9;

/// A hint for [`RateLimiter`]. It indicates whether an operation follows the Kademlia requests and
/// assumes that the connection to the peer already exists. It will prevent the [`RateLimiter`] to
/// obtain a semaphore permit from the connection related semaphore.
/// It mostly relates to `get-providers` Kademlia request and not for `get-closest-peers` because
/// in our configuration `get-providers` is guaranteed to return providers from the exact peer and
/// a connection to the peer will last at least `connection timeout` seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimiterHint {
    /// The previous operation was Kademlia request and the connection to the peer is likely already
    /// established. /// The connection permit will NOT be required  for [`RateLimiter`].
    KademliaDependentOperation,
    /// There are no previous Kademlia requests like `get-providers` that opens a connection to the
    /// peer. The connection permit will be required  for [`RateLimiter`].
    IndependentOperation,
}

impl RateLimiterHint {
    fn is_independent_operation(&self) -> bool {
        *self == RateLimiterHint::IndependentOperation
    }
}

#[derive(Debug)]
pub(crate) struct RateLimiterPermit {
    /// Limits Kademlia substreams.
    _substream_limit_permit: ResizableSemaphorePermit,

    /// Limits outgoing connections.
    _connection_limit_permit: Option<ResizableSemaphorePermit>,
}

#[derive(Debug)]
pub(crate) struct RateLimiter {
    kademlia_tasks_semaphore: ResizableSemaphore,
    regular_tasks_semaphore: ResizableSemaphore,
    connections_semaphore: ResizableSemaphore,
}

impl RateLimiter {
    pub(crate) fn new(out_connections: u32, pending_out_connections: u32) -> Self {
        let permits = Self::calculate_connection_semaphore_size(
            out_connections as usize,
            pending_out_connections as usize,
        );

        debug!(%out_connections, %pending_out_connections, %permits, "Rate limiter was instantiated.");

        Self {
            kademlia_tasks_semaphore: ResizableSemaphore::new(KADEMLIA_BASE_CONCURRENT_TASKS),
            regular_tasks_semaphore: ResizableSemaphore::new(REGULAR_BASE_CONCURRENT_TASKS),
            connections_semaphore: ResizableSemaphore::new(
                NonZeroUsize::new(permits).expect("Manual setting."),
            ),
        }
    }

    /// Calculates an empiric formula for the semaphore size based on the connection parameters and
    /// existing constants.
    fn calculate_connection_semaphore_size(
        out_connections: usize,
        pending_out_connections: usize,
    ) -> usize {
        let connections = out_connections.min(pending_out_connections);
        if connections == 0 {
            return 0;
        }
        // Number of "in-flight" parallel requests for each query
        let kademlia_parallelism_level = libp2p::kad::ALPHA_VALUE.get();

        let result = connections / (kademlia_parallelism_level * CONNECTION_TIMEOUT_PARAMETER);

        result.max(MINIMUM_CONNECTIONS_SEMAPHORE_SIZE)
    }

    pub(crate) async fn acquire_regular_permit(&self, hint: RateLimiterHint) -> RateLimiterPermit {
        let connections_permit = if hint.is_independent_operation() {
            Some(self.connections_semaphore.acquire().await)
        } else {
            None
        };

        let substream_permit = self.regular_tasks_semaphore.acquire().await;

        RateLimiterPermit {
            _connection_limit_permit: connections_permit,
            _substream_limit_permit: substream_permit,
        }
    }

    pub(crate) fn expand_regular_semaphore(&self) -> Result<(), SemaphoreError> {
        self.regular_tasks_semaphore
            .expand(REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER)
            .map(|old_capacity| trace!(%old_capacity,  "Expand regular semaphore."))
    }

    pub(crate) fn shrink_regular_semaphore(&self) -> Result<(), SemaphoreError> {
        self.regular_tasks_semaphore
            .shrink(REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER)
            .map(|old_capacity| trace!(%old_capacity,  "Shrink regular semaphore."))
    }

    pub(crate) async fn acquire_kademlia_permit(&self) -> RateLimiterPermit {
        let connections_permit = self.connections_semaphore.acquire().await;
        let substream_permit = self.kademlia_tasks_semaphore.acquire().await;

        RateLimiterPermit {
            _connection_limit_permit: Some(connections_permit),
            _substream_limit_permit: substream_permit,
        }
    }

    pub(crate) fn expand_kademlia_semaphore(&self) -> Result<(), SemaphoreError> {
        self.kademlia_tasks_semaphore
            .expand(KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER)
            .map(|old_capacity| trace!(%old_capacity,  "Expand kademlia semaphore."))
    }

    pub(crate) fn shrink_kademlia_semaphore(&self) -> Result<(), SemaphoreError> {
        self.kademlia_tasks_semaphore
            .shrink(KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER)
            .map(|old_capacity| trace!(%old_capacity,  "Shrink kademlia semaphore."))
    }
}
