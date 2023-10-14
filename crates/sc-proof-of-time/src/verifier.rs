//! Proof of time verifier

#[cfg(test)]
mod tests;

use async_lock::Mutex as AsyncMutex;
use futures::channel::oneshot;
use lru::LruCache;
use parking_lot::Mutex;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{PotNextSlotInput, PotParametersChange};
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;
use subspace_core_primitives::{PotCheckpoints, PotOutput, PotSeed};
use tokio::runtime::Handle;
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

    /// Try to get checkpoints for provided seed and slot iterations, returns `None` if proving
    /// fails internally.
    pub async fn get_checkpoints(
        &self,
        slot_iterations: NonZeroU32,
        seed: PotSeed,
    ) -> Option<PotCheckpoints> {
        // TODO: This "proxy" is a workaround for https://github.com/rust-lang/rust/issues/57478
        let result_fut = tokio::task::spawn_blocking({
            let verifier = self.clone();

            move || {
                Handle::current().block_on(verifier.calculate_checkpoints(
                    slot_iterations,
                    seed,
                    true,
                ))
            }
        });

        result_fut.await.unwrap_or_default()
    }

    /// Try to get checkpoints quickly without waiting for potentially locked async mutex or proving
    pub fn try_get_checkpoints(
        &self,
        slot_iterations: NonZeroU32,
        seed: PotSeed,
    ) -> Option<PotCheckpoints> {
        let cache_key = CacheKey {
            seed,
            slot_iterations,
        };

        self.cache
            .lock()
            .get(&cache_key)
            .and_then(|value| value.checkpoints.try_lock()?.as_ref().copied())
    }

    /// Verify sequence of proofs of time that covers `slots` slots starting at `slot` with provided
    /// initial `seed`.
    ///
    /// In case `maybe_parameters_change` is present, it will not affect provided `seed` and
    /// `slot_iterations`, meaning if parameters change occurred at `slot`, provided `seed` and
    /// `slot_iterations` must already account for that.
    ///
    /// NOTE: Potentially much slower than checkpoints, prefer [`Self::verify_checkpoints()`]
    /// whenever possible.
    pub async fn is_output_valid(
        &self,
        input: PotNextSlotInput,
        slots: Slot,
        output: PotOutput,
        maybe_parameters_change: Option<PotParametersChange>,
    ) -> bool {
        self.is_output_valid_internal(input, slots, output, maybe_parameters_change, true)
            .await
    }

    /// Does the same verification as [`Self::is_output_valid()`] except it relies on proofs being
    /// pre-validated before and will return `false` in case proving is necessary, this is meant to
    /// be a quick and cheap version of the function.
    pub async fn try_is_output_valid(
        &self,
        input: PotNextSlotInput,
        slots: Slot,
        output: PotOutput,
        maybe_parameters_change: Option<PotParametersChange>,
    ) -> bool {
        self.is_output_valid_internal(input, slots, output, maybe_parameters_change, false)
            .await
    }

    async fn is_output_valid_internal(
        &self,
        mut input: PotNextSlotInput,
        slots: Slot,
        output: PotOutput,
        maybe_parameters_change: Option<PotParametersChange>,
        do_proving_if_necessary: bool,
    ) -> bool {
        let mut slots = u64::from(slots);

        loop {
            let maybe_calculated_checkpoints_fut = tokio::task::spawn_blocking({
                let verifier = self.clone();

                move || {
                    Handle::current().block_on(verifier.calculate_checkpoints(
                        input.slot_iterations,
                        input.seed,
                        do_proving_if_necessary,
                    ))
                }
            });

            let Ok(Some(calculated_checkpoints)) = maybe_calculated_checkpoints_fut.await else {
                return false;
            };
            let calculated_output = calculated_checkpoints.output();

            slots -= 1;

            if slots == 0 {
                return output == calculated_output;
            }

            input = PotNextSlotInput::derive(
                input.slot_iterations,
                input.slot,
                calculated_output,
                &maybe_parameters_change,
            );
        }
    }

    /// Derive next seed, proving might be used if necessary
    // TODO: False-positive, lock is not actually held over await point, remove suppression once
    //  fixed upstream
    #[allow(clippy::await_holding_lock)]
    async fn calculate_checkpoints(
        &self,
        slot_iterations: NonZeroU32,
        seed: PotSeed,
        do_proving_if_necessary: bool,
    ) -> Option<PotCheckpoints> {
        let cache_key = CacheKey {
            seed,
            slot_iterations,
        };

        loop {
            let mut cache = self.cache.lock();
            let maybe_cache_value = cache.get(&cache_key).cloned();
            if let Some(cache_value) = maybe_cache_value {
                drop(cache);
                let correct_checkpoints = cache_value.checkpoints.lock().await;
                if let Some(correct_checkpoints) = *correct_checkpoints {
                    return Some(correct_checkpoints);
                }

                // There was another verification for these inputs and it wasn't successful, retry
                continue;
            }

            if !do_proving_if_necessary {
                // If not found and proving is not allowed then just exit
                return None;
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
            // Cache lock is no longer necessary, other callers should be able to access cache too
            drop(cache);

            let (result_sender, result_receiver) = oneshot::channel();

            rayon::spawn(move || {
                let result = subspace_proof_of_time::prove(seed, slot_iterations);

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

            checkpoints.replace(generated_checkpoints);
            return Some(generated_checkpoints);
        }
    }

    /// Verify proof of time checkpoints
    pub async fn verify_checkpoints(
        &self,
        seed: PotSeed,
        slot_iterations: NonZeroU32,
        checkpoints: &PotCheckpoints,
    ) -> bool {
        // TODO: This "proxy" is a workaround for https://github.com/rust-lang/rust/issues/57478
        let result_fut = tokio::task::spawn_blocking({
            let verifier = self.clone();
            let checkpoints = *checkpoints;

            move || {
                Handle::current().block_on(verifier.verify_checkpoints_internal(
                    seed,
                    slot_iterations,
                    &checkpoints,
                ))
            }
        });

        result_fut.await.unwrap_or_default()
    }

    // TODO: False-positive, lock is not actually held over await point, remove suppression once
    //  fixed upstream
    #[allow(clippy::await_holding_lock)]
    async fn verify_checkpoints_internal(
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
            if let Some(cache_value) = cache.get(&cache_key).cloned() {
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
                    subspace_proof_of_time::verify(seed, slot_iterations, checkpoints.as_slice())
                        .unwrap_or_default();

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
