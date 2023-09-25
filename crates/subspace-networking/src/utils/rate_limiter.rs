pub(crate) mod resizable_semaphore;
#[cfg(test)]
mod tests;

use crate::utils::rate_limiter::resizable_semaphore::{
    ResizableSemaphore, ResizableSemaphorePermit, SemaphoreError,
};
use std::num::NonZeroUsize;

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

#[derive(Debug)]
pub(crate) struct RateLimiter {
    kademlia_tasks_semaphore: ResizableSemaphore,
    regular_tasks_semaphore: ResizableSemaphore,
}

impl RateLimiter {
    pub(crate) fn new() -> Self {
        Self {
            kademlia_tasks_semaphore: ResizableSemaphore::new(KADEMLIA_BASE_CONCURRENT_TASKS),
            regular_tasks_semaphore: ResizableSemaphore::new(REGULAR_BASE_CONCURRENT_TASKS),
        }
    }

    pub(crate) async fn acquire_regular_permit(&self) -> ResizableSemaphorePermit {
        self.regular_tasks_semaphore.acquire().await
    }

    pub(crate) fn expand_regular_semaphore(&self) -> Result<(), SemaphoreError> {
        self.regular_tasks_semaphore
            .expand(REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER)
    }

    pub(crate) fn shrink_regular_semaphore(&self) -> Result<(), SemaphoreError> {
        self.regular_tasks_semaphore
            .shrink(REGULAR_CONCURRENT_TASKS_BOOST_PER_PEER)
    }

    pub(crate) async fn acquire_kademlia_permit(&self) -> ResizableSemaphorePermit {
        self.kademlia_tasks_semaphore.acquire().await
    }

    pub(crate) fn expand_kademlia_semaphore(&self) -> Result<(), SemaphoreError> {
        self.kademlia_tasks_semaphore
            .expand(KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER)
    }

    pub(crate) fn shrink_kademlia_semaphore(&self) -> Result<(), SemaphoreError> {
        self.kademlia_tasks_semaphore
            .shrink(KADEMLIA_CONCURRENT_TASKS_BOOST_PER_PEER)
    }
}
