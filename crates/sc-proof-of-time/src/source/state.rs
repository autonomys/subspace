use crate::verifier::PotVerifier;
use atomic::Atomic;
use sp_consensus_slots::Slot;
#[cfg(feature = "pot")]
use sp_consensus_subspace::PotParametersChange;
use std::num::NonZeroU32;
use std::sync::atomic::Ordering;
use subspace_core_primitives::{PotProof, PotSeed};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct NextSlotInput {
    pub(super) slot: Slot,
    pub(super) slot_iterations: NonZeroU32,
    pub(super) seed: PotSeed,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct InnerState {
    next_slot_input: NextSlotInput,
    #[cfg(feature = "pot")]
    parameters_change: Option<PotParametersChange>,
}

impl InnerState {
    pub(super) fn update(
        mut self,
        mut best_slot: Slot,
        mut best_proof: PotProof,
        #[cfg(feature = "pot")] maybe_updated_parameters_change: Option<
            Option<PotParametersChange>,
        >,
        pot_verifier: &PotVerifier,
    ) -> Self {
        #[cfg(feature = "pot")]
        if let Some(updated_parameters_change) = maybe_updated_parameters_change {
            self.parameters_change = updated_parameters_change;
        }

        loop {
            let next_slot = best_slot + Slot::from(1);
            let next_slot_iterations;
            let next_seed;

            #[cfg(feature = "pot")]
            // The change to number of iterations might have happened before `next_slot`
            if let Some(parameters_change) = self.parameters_change
                && parameters_change.slot <= next_slot
            {
                next_slot_iterations = parameters_change.slot_iterations;
                // Only if entropy injection happens on this exact slot we need to mix it in
                if parameters_change.slot == next_slot {
                    next_seed = best_proof.seed_with_entropy(&parameters_change.entropy);
                } else {
                    next_seed = best_proof.seed();
                }
            } else {
                next_slot_iterations = self.next_slot_input.slot_iterations;
                next_seed = best_proof.seed();
            }
            #[cfg(not(feature = "pot"))]
            {
                next_slot_iterations = self.next_slot_input.slot_iterations;
                next_seed = best_proof.seed();
            }

            self.next_slot_input = NextSlotInput {
                slot: next_slot,
                slot_iterations: next_slot_iterations,
                seed: next_seed,
            };

            // Advance further as far as possible using previously verified proofs/checkpoints
            if let Some(checkpoints) = pot_verifier.get_checkpoints(next_seed, next_slot_iterations)
            {
                best_slot = best_slot + Slot::from(1);
                best_proof = checkpoints.output();
            } else {
                break;
            }
        }

        self
    }
}

#[derive(Debug)]
pub(super) struct PotState {
    inner_state: Atomic<InnerState>,
    verifier: PotVerifier,
}

impl PotState {
    pub(super) fn new(
        next_slot_input: NextSlotInput,
        #[cfg(feature = "pot")] parameters_change: Option<PotParametersChange>,
        verifier: PotVerifier,
    ) -> Self {
        let inner = InnerState {
            next_slot_input,
            #[cfg(feature = "pot")]
            parameters_change,
        };

        Self {
            inner_state: Atomic::new(inner),
            verifier,
        }
    }

    pub(super) fn next_slot_input(&self, ordering: Ordering) -> NextSlotInput {
        self.inner_state.load(ordering).next_slot_input
    }

    /// Extend state if it matches provided expected next slot input.
    ///
    /// Returns `Ok(new_next_slot_input)` if state was extended successfully and
    /// `Err(existing_next_slot_input)` in case state was changed in the meantime.
    pub(super) fn try_extend(
        &self,
        expected_previous_next_slot_input: NextSlotInput,
        best_slot: Slot,
        best_proof: PotProof,
        #[cfg(feature = "pot")] maybe_updated_parameters_change: Option<
            Option<PotParametersChange>,
        >,
    ) -> Result<NextSlotInput, NextSlotInput> {
        let old_inner_state = self.inner_state.load(Ordering::Acquire);
        if expected_previous_next_slot_input != old_inner_state.next_slot_input {
            return Err(old_inner_state.next_slot_input);
        }

        let new_inner_state = old_inner_state.update(
            best_slot,
            best_proof,
            #[cfg(feature = "pot")]
            maybe_updated_parameters_change,
            &self.verifier,
        );

        // Use `compare_exchange` to ensure we only update previously known value and not
        // accidentally override something that doesn't match expectations anymore
        self.inner_state
            .compare_exchange(
                old_inner_state,
                new_inner_state,
                Ordering::AcqRel,
                // We don't care about the value read in case of failure
                Ordering::Acquire,
            )
            .map(|_old_inner_state| new_inner_state.next_slot_input)
            .map_err(|existing_inner_state| existing_inner_state.next_slot_input)
    }

    /// Update state, overriding PoT chain if it doesn't match provided values.
    ///
    /// Returns `Some(next_slot_input)` if reorg happened.
    #[cfg(feature = "pot")]
    pub(super) fn update(
        &self,
        best_slot: Slot,
        best_proof: PotProof,
        #[cfg(feature = "pot")] maybe_updated_parameters_change: Option<
            Option<PotParametersChange>,
        >,
    ) -> Option<NextSlotInput> {
        let mut best_state = None;
        // Use `fetch_update` such that we don't accidentally downgrade best slot to smaller value
        let previous_best_state = self
            .inner_state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |inner_state| {
                best_state = Some(inner_state.update(
                    best_slot,
                    best_proof,
                    #[cfg(feature = "pot")]
                    maybe_updated_parameters_change,
                    &self.verifier,
                ));

                best_state
            })
            .expect("Callback always returns `Some`; qed");
        let best_state = best_state.expect("Replaced with `Some` above; qed");

        (previous_best_state.next_slot_input != best_state.next_slot_input)
            .then_some(best_state.next_slot_input)
    }
}
