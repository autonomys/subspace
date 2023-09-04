//! Proof of time verifier

#[cfg(test)]
mod tests;

use async_lock::Mutex as AsyncMutex;
use futures::channel::oneshot;
use lru::LruCache;
use parking_lot::Mutex;
use sp_consensus_slots::Slot;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;
use subspace_core_primitives::{PotCheckpoints, PotProof, PotSeed};
use subspace_proof_of_time::{prove, verify};
use tracing::trace;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct CacheKey {
    seed: PotSeed,
    slot_iterations: NonZeroU32,
}

#[derive(Debug, Clone)]
struct CacheValue {
    checkpoints: Arc<AsyncMutex<Option<PotCheckpoints>>>,
}

/// Verifier data structure that verifies and caches results of PoT verification
#[derive(Debug, Clone)]
pub struct PotVerifier {
    genesis_seed: PotSeed,
    cache: Arc<Mutex<LruCache<CacheKey, CacheValue>>>,
}

impl PotVerifier {
    pub fn new(genesis_seed: PotSeed, cache_size: NonZeroUsize) -> Self {
        Self {
            genesis_seed,
            cache: Arc::new(Mutex::new(LruCache::new(cache_size))),
        }
    }

    /// Inject known good checkpoints into verifier
    pub fn inject_verified_checkpoints(
        &self,
        seed: PotSeed,
        slot_iterations: NonZeroU32,
        checkpoints: PotCheckpoints,
    ) {
        self.cache.lock().push(
            CacheKey {
                seed,
                slot_iterations,
            },
            CacheValue {
                checkpoints: Arc::new(AsyncMutex::new(Some(checkpoints))),
            },
        );
    }

    /// Get genesis seed
    pub fn genesis_seed(&self) -> PotSeed {
        self.genesis_seed
    }

    /// Verify a single proof of time that is `slots` slots away from `seed`.
    ///
    /// NOTE: Potentially much slower than checkpoints, prefer [`Self::verify_checkpoints()`]
    /// whenever possible.
    pub async fn is_proof_valid(
        &self,
        mut seed: PotSeed,
        slot_iterations: NonZeroU32,
        slots: Slot,
        proof: PotProof,
    ) -> bool {
        let mut slots = u64::from(slots);

        loop {
            if slots == 0 {
                return proof.seed() == seed;
            }

            // TODO: This "proxy" is a workaround for https://github.com/rust-lang/rust/issues/57478
            let (result_sender, result_receiver) = oneshot::channel();
            std::thread::spawn({
                let verifier = self.clone();

                move || {
                    futures::executor::block_on({
                        async move {
                            // Result doesn't matter here
                            let _ = result_sender
                                .send(verifier.derive_next_seed(seed, slot_iterations).await);
                        }
                    });
                }
            });

            seed = match result_receiver.await {
                Ok(Some(seed)) => seed,
                _ => {
                    return false;
                }
            };

            slots -= 1;
        }
    }

    /// Derive next seed, proving might be used if necessary
    // TODO: False-positive, lock is not actually held over await point, remove suppression once
    //  fixed upstream
    #[allow(clippy::await_holding_lock)]
    async fn derive_next_seed(
        &self,
        seed: PotSeed,
        slot_iterations: NonZeroU32,
    ) -> Option<PotSeed> {
        let cache_key = CacheKey {
            seed,
            slot_iterations,
        };

        loop {
            let mut cache = self.cache.lock();
            let maybe_cache_value = cache.peek(&cache_key).cloned();
            if let Some(cache_value) = maybe_cache_value {
                drop(cache);
                let correct_checkpoints = cache_value.checkpoints.lock().await;
                if let Some(correct_checkpoints) = correct_checkpoints.as_ref() {
                    return Some(correct_checkpoints.output().seed());
                }

                // There was another verification for these inputs and it wasn't successful,
                // retry
                continue;
            }

            let cache_value = CacheValue {
                checkpoints: Arc::default(),
            };
            let checkpoints = Arc::clone(&cache_value.checkpoints);
            // Take a lock before anyone else
            let mut checkpoints = checkpoints
                .try_lock()
                .expect("No one can access this mutex yet; qed");
            // Store pending verification entry in cache
            cache.push(cache_key, cache_value);
            // Cache lock is no longer necessary, other callers should be able to access cache
            // too
            drop(cache);

            let (result_sender, result_receiver) = oneshot::channel();

            rayon::spawn(move || {
                let result = prove(seed, slot_iterations);

                if let Err(_error) = result_sender.send(result) {
                    trace!("Verification result receiver is gone before result was sent");
                }
            });

            let Ok(Ok(generated_checkpoints)) = result_receiver.await else {
                // Avoid deadlock when taking a lock below
                drop(checkpoints);

                // Proving failed, remove pending entry from cache such that retries can happen
                let maybe_removed_cache_value = self.cache.lock().pop(&cache_key);
                if let Some(removed_cache_value) = maybe_removed_cache_value {
                    // It is possible that we have removed a verified value that we have not
                    // inserted, check for this and restore if that was the case
                    let removed_verified_value =
                        removed_cache_value.checkpoints.lock().await.is_some();
                    if removed_verified_value {
                        self.cache.lock().push(cache_key, removed_cache_value);
                    }
                }
                return None;
            };

            let seed = generated_checkpoints.output().seed();
            checkpoints.replace(generated_checkpoints);
            return Some(seed);
        }
    }

    /// Verify proof of time checkpoints
    // TODO: False-positive, lock is not actually held over await point, remove suppression once
    //  fixed upstream
    #[allow(clippy::await_holding_lock)]
    pub async fn verify_checkpoints(
        &self,
        seed: PotSeed,
        slot_iterations: NonZeroU32,
        checkpoints: &PotCheckpoints,
    ) -> bool {
        let cache_key = CacheKey {
            seed,
            slot_iterations,
        };

        loop {
            let mut cache = self.cache.lock();
            if let Some(cache_value) = cache.peek(&cache_key).cloned() {
                drop(cache);
                let correct_checkpoints = cache_value.checkpoints.lock().await;
                if let Some(correct_checkpoints) = correct_checkpoints.as_ref() {
                    return checkpoints == correct_checkpoints;
                }

                // There was another verification for these inputs and it wasn't successful, retry
                continue;
            }

            let cache_value = CacheValue {
                checkpoints: Arc::default(),
            };
            let correct_checkpoints = Arc::clone(&cache_value.checkpoints);
            // Take a lock before anyone else
            let mut correct_checkpoints = correct_checkpoints
                .try_lock()
                .expect("No one can access this mutex yet; qed");
            // Store pending verification entry in cache
            cache.push(cache_key, cache_value);
            // Cache lock is no longer necessary, other callers should be able to access cache too
            drop(cache);

            let (result_sender, result_receiver) = oneshot::channel();

            let checkpoints = *checkpoints;
            rayon::spawn(move || {
                let result =
                    verify(seed, slot_iterations, checkpoints.as_slice()).unwrap_or_default();

                if let Err(_error) = result_sender.send(result) {
                    trace!("Verification result receiver is gone before result was sent");
                }
            });

            if !result_receiver.await.unwrap_or_default() {
                // Avoid deadlock when taking a lock below
                drop(correct_checkpoints);

                // Verification failed, remove pending entry from cache such that retries can happen
                let maybe_removed_cache_value = self.cache.lock().pop(&cache_key);
                if let Some(removed_cache_value) = maybe_removed_cache_value {
                    // It is possible that we have removed a verified value that we have not
                    // inserted, check for this and restore if that was the case
                    let removed_verified_value =
                        removed_cache_value.checkpoints.lock().await.is_some();
                    if removed_verified_value {
                        self.cache.lock().push(cache_key, removed_cache_value);
                    }
                }
                return false;
            }

            // Store known good checkpoints in cache
            correct_checkpoints.replace(checkpoints);

            return true;
        }
    }
}
