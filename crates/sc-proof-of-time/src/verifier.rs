//! Proof of time verifier

#[cfg(test)]
mod tests;

use async_lock::Mutex as AsyncMutex;
use futures::channel::oneshot;
use lru::LruCache;
use parking_lot::Mutex;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::PotParametersChange;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;
use subspace_core_primitives::{PotCheckpoints, PotOutput, PotSeed};
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

    /// Try to get checkpoints quickly without waiting for potentially locked async mutex or proving
    pub fn try_get_checkpoints(
        &self,
        seed: PotSeed,
        slot_iterations: NonZeroU32,
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
        slot: Slot,
        seed: PotSeed,
        slot_iterations: NonZeroU32,
        slots: Slot,
        output: PotOutput,
        maybe_parameters_change: Option<PotParametersChange>,
    ) -> bool {
        self.is_output_valid_internal(
            slot,
            seed,
            slot_iterations,
            slots,
            output,
            maybe_parameters_change,
            true,
        )
        .await
    }

    /// Does the same verification as [`Self::is_output_valid()`] except it relies on proofs being
    /// pre-validated before and will return `false` in case proving is necessary, this is meant to
    /// be a quick and cheap version of the function.
    pub async fn try_is_output_valid(
        &self,
        slot: Slot,
        seed: PotSeed,
        slot_iterations: NonZeroU32,
        slots: Slot,
        output: PotOutput,
        maybe_parameters_change: Option<PotParametersChange>,
    ) -> bool {
        self.is_output_valid_internal(
            slot,
            seed,
            slot_iterations,
            slots,
            output,
            maybe_parameters_change,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn is_output_valid_internal(
        &self,
        mut slot: Slot,
        mut seed: PotSeed,
        mut slot_iterations: NonZeroU32,
        slots: Slot,
        output: PotOutput,
        mut maybe_parameters_change: Option<PotParametersChange>,
        do_proving_if_necessary: bool,
    ) -> bool {
        let mut slots = u64::from(slots);

        loop {
            // TODO: This "proxy" is a workaround for https://github.com/rust-lang/rust/issues/57478
            let (result_sender, result_receiver) = oneshot::channel();
            tokio::task::spawn_blocking({
                let verifier = self.clone();

                move || {
                    futures::executor::block_on({
                        async move {
                            // Result doesn't matter here
                            let _ = result_sender.send(
                                verifier
                                    .calculate_output(
                                        seed,
                                        slot_iterations,
                                        do_proving_if_necessary,
                                    )
                                    .await,
                            );
                        }
                    });
                }
            });

            let Ok(Some(calculated_proof)) = result_receiver.await else {
                return false;
            };

            slots -= 1;

            if slots == 0 {
                return output == calculated_proof;
            }

            slot = slot + Slot::from(1);

            if let Some(parameters_change) = maybe_parameters_change
                && parameters_change.slot == slot
            {
                slot_iterations = parameters_change.slot_iterations;
                seed = calculated_proof.seed_with_entropy(&parameters_change.entropy);
                maybe_parameters_change.take();
            } else {
                seed = calculated_proof.seed();
            }
        }
    }

    /// Derive next seed, proving might be used if necessary
    // TODO: False-positive, lock is not actually held over await point, remove suppression once
    //  fixed upstream
    #[allow(clippy::await_holding_lock)]
    async fn calculate_output(
        &self,
        seed: PotSeed,
        slot_iterations: NonZeroU32,
        do_proving_if_necessary: bool,
    ) -> Option<PotOutput> {
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
                if let Some(correct_checkpoints) = correct_checkpoints.as_ref() {
                    return Some(correct_checkpoints.output());
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

            let proof = generated_checkpoints.output();
            checkpoints.replace(generated_checkpoints);
            return Some(proof);
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
        let (result_sender, result_receiver) = oneshot::channel();
        tokio::task::spawn_blocking({
            let verifier = self.clone();
            let checkpoints = *checkpoints;

            move || {
                futures::executor::block_on({
                    async move {
                        // Result doesn't matter here
                        let _ = result_sender.send(
                            verifier
                                .verify_checkpoints_internal(seed, slot_iterations, &checkpoints)
                                .await,
                        );
                    }
                });
            }
        });

        result_receiver.await.unwrap_or_default()
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
