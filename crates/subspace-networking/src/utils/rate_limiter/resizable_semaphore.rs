use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Notify;

/// Errors happening during semaphore usage
#[derive(Debug, Error)]
pub(crate) enum SemaphoreError {
    #[error("Invalid shrink: capacity {capacity}, delta {delta}")]
    InvalidShrink {
        /// The current capacity
        capacity: usize,
        /// How much to shrink
        delta: usize,
    },
    #[error("Invalid expand: capacity {capacity}, delta {delta}")]
    InvalidExpand {
        /// The current capacity
        capacity: usize,
        /// How much to expand
        delta: usize,
    },
}

/// The state shared between the semaphore and the outstanding permits.
#[derive(Debug)]
struct SemShared {
    /// The tuple holds (current usage, current max capacity)
    state: Mutex<SemState>,
    /// To signal waiters for permits to be available
    notify: Notify,
}

/// The semaphore state.
#[derive(Debug)]
struct SemState {
    /// The current capacity
    capacity: usize,
    /// The current outstanding permits
    usage: usize,
}

impl SemState {
    // Allocates a permit if available.
    // Returns true if allocated, false otherwise.
    fn alloc_one(&mut self) -> bool {
        if self.usage < self.capacity {
            self.usage += 1;
            true
        } else {
            false
        }
    }

    // Returns a free permit to the free pool.
    // Returns true if any waiters need to be notified.
    fn free_one(&mut self) -> bool {
        let prev_is_full = self.is_full();
        if let Some(dec) = self.usage.checked_sub(1) {
            self.usage = dec;
        } else {
            unreachable!("Dropping semaphore twice is not possible");
        }

        // Notify if we did a full -> available transition.
        prev_is_full && !self.is_full()
    }

    // Expands the max capacity by delta.
    // Returns true if any waiters need to be notified.
    fn expand(&mut self, delta: usize) -> Result<bool, SemaphoreError> {
        let prev_is_full = self.is_full();
        if let Some(capacity) = self.capacity.checked_add(delta) {
            self.capacity = capacity;
            // Notify if we did a full -> available transition.
            Ok(prev_is_full && !self.is_full())
        } else {
            Err(SemaphoreError::InvalidExpand {
                capacity: self.capacity,
                delta,
            })
        }
    }

    // Shrinks the max capacity by delta.
    fn shrink(&mut self, delta: usize) -> Result<(), SemaphoreError> {
        if let Some(capacity) = self.capacity.checked_sub(delta) {
            self.capacity = capacity;
            Ok(())
        } else {
            Err(SemaphoreError::InvalidShrink {
                capacity: self.capacity,
                delta,
            })
        }
    }

    // Returns true if current usage exceeds capacity
    fn is_full(&self) -> bool {
        self.usage >= self.capacity
    }
}

/// Semaphore like implementation that allows both shrinking and expanding
/// the max permits.
#[derive(Clone, Debug)]
pub(crate) struct ResizableSemaphore(Arc<SemShared>);

impl ResizableSemaphore {
    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        let shared = SemShared {
            state: Mutex::new(SemState {
                capacity: capacity.get(),
                usage: 0,
            }),
            notify: Notify::new(),
        };
        Self(Arc::new(shared))
    }

    // Acquires a permit. Waits until a permit is available.
    pub(crate) async fn acquire(&self) -> ResizableSemaphorePermit {
        loop {
            let wait = {
                let mut state = self.0.state.lock();
                if state.alloc_one() {
                    None
                } else {
                    // This needs to be done under the lock to avoid race.
                    Some(self.0.notify.notified())
                }
            };

            match wait {
                Some(notified) => notified.await,
                None => break,
            }
        }
        ResizableSemaphorePermit(self.0.clone())
    }

    // Acquires a permit, doesn't wait for permits to be available.
    // Currently used only for tests.
    #[cfg(test)]
    pub(crate) fn try_acquire(&self) -> Option<ResizableSemaphorePermit> {
        let mut state = self.0.state.lock();
        if state.alloc_one() {
            Some(ResizableSemaphorePermit(self.0.clone()))
        } else {
            None
        }
    }

    // Expands the capacity by the specified amount.
    pub(crate) fn expand(&self, delta: usize) -> Result<(), SemaphoreError> {
        let notify_waiters = self.0.state.lock().expand(delta)?;
        if notify_waiters {
            self.0.notify.notify_waiters();
        }

        Ok(())
    }

    // Shrinks the capacity by the specified amount.
    pub(crate) fn shrink(&self, delta: usize) -> Result<(), SemaphoreError> {
        self.0.state.lock().shrink(delta)
    }
}

/// The semaphore permit.
#[derive(Clone, Debug)]
pub(crate) struct ResizableSemaphorePermit(Arc<SemShared>);

impl Drop for ResizableSemaphorePermit {
    fn drop(&mut self) {
        let notify_waiters = self.0.state.lock().free_one();
        if notify_waiters {
            self.0.notify.notify_waiters();
        }
    }
}
