use crate::verifier::PotVerifier;
use sp_consensus_slots::Slot;
#[cfg(feature = "pot")]
use sp_consensus_subspace::PotParametersChange;
use std::num::NonZeroU32;
use subspace_core_primitives::{PotProof, PotSeed};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct NextSlotInput {
    pub(super) slot: Slot,
    pub(super) slot_iterations: NonZeroU32,
    pub(super) seed: PotSeed,
}

#[derive(Debug, Copy, Clone)]
pub(super) struct PotState {
    pub(super) next_slot_input: NextSlotInput,
    #[cfg(feature = "pot")]
    pub(super) parameters_change: Option<PotParametersChange>,
}

impl PotState {
    /// Extend state if it matches provided expected next slot input.
    ///
    /// Returns `Some` if state was extended.
    pub(super) fn try_extend(
        &mut self,
        expected_next_slot_input: NextSlotInput,
        best_slot: Slot,
        best_proof: PotProof,
        #[cfg(feature = "pot")] maybe_updated_parameters_change: Option<
            Option<PotParametersChange>,
        >,
        pot_verifier: &PotVerifier,
    ) -> Option<NextSlotInput> {
        if expected_next_slot_input != self.next_slot_input {
            return None;
        }

        self.update(
            best_slot,
            best_proof,
            #[cfg(feature = "pot")]
            maybe_updated_parameters_change,
            pot_verifier,
        );

        Some(self.next_slot_input)
    }

    pub(super) fn update(
        &mut self,
        mut best_slot: Slot,
        mut best_proof: PotProof,
        #[cfg(feature = "pot")] maybe_updated_parameters_change: Option<
            Option<PotParametersChange>,
        >,
        pot_verifier: &PotVerifier,
    ) {
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
                    self.parameters_change.take();
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
    }
}
