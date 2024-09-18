use crate::verifier::PotVerifier;
use parking_lot::Mutex;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{PotNextSlotInput, PotParametersChange};
use subspace_core_primitives::PotOutput;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct InnerState {
    next_slot_input: PotNextSlotInput,
    parameters_change: Option<PotParametersChange>,
}

impl InnerState {
    pub(super) fn update(
        mut self,
        mut best_slot: Slot,
        mut best_output: PotOutput,
        maybe_updated_parameters_change: Option<Option<PotParametersChange>>,
        pot_verifier: &PotVerifier,
    ) -> Self {
        if let Some(updated_parameters_change) = maybe_updated_parameters_change {
            self.parameters_change = updated_parameters_change;
        }

        loop {
            self.next_slot_input = PotNextSlotInput::derive(
                self.next_slot_input.slot_iterations,
                best_slot,
                best_output,
                &self.parameters_change,
            );

            // Advance further as far as possible using previously verified proofs/checkpoints
            if let Some(checkpoints) = pot_verifier.try_get_checkpoints(
                self.next_slot_input.slot_iterations,
                self.next_slot_input.seed,
            ) {
                best_slot = self.next_slot_input.slot;
                best_output = checkpoints.output();
            } else {
                break;
            }
        }

        self
    }
}

#[derive(Debug)]
pub(super) enum PotStateUpdateOutcome {
    NoChange,
    Extension {
        from: PotNextSlotInput,
        to: PotNextSlotInput,
    },
    Reorg {
        from: PotNextSlotInput,
        to: PotNextSlotInput,
    },
}

#[derive(Debug)]
pub(super) struct PotState {
    inner_state: Mutex<InnerState>,
    verifier: PotVerifier,
}

impl PotState {
    pub(super) fn new(
        next_slot_input: PotNextSlotInput,
        parameters_change: Option<PotParametersChange>,
        verifier: PotVerifier,
    ) -> Self {
        let inner = InnerState {
            next_slot_input,
            parameters_change,
        };

        Self {
            inner_state: Mutex::new(inner),
            verifier,
        }
    }

    pub(super) fn next_slot_input(&self) -> PotNextSlotInput {
        self.inner_state.lock().next_slot_input
    }

    /// Extend state if it matches provided expected next slot input.
    ///
    /// Returns `Ok(new_next_slot_input)` if state was extended successfully and
    /// `Err(existing_next_slot_input)` in case state was changed in the meantime.
    pub(super) fn try_extend(
        &self,
        expected_existing_next_slot_input: PotNextSlotInput,
        best_slot: Slot,
        best_output: PotOutput,
        maybe_updated_parameters_change: Option<Option<PotParametersChange>>,
    ) -> Result<PotNextSlotInput, PotNextSlotInput> {
        let mut existing_inner_state = self.inner_state.lock();
        if expected_existing_next_slot_input != existing_inner_state.next_slot_input {
            return Err(existing_inner_state.next_slot_input);
        }

        *existing_inner_state = existing_inner_state.update(
            best_slot,
            best_output,
            maybe_updated_parameters_change,
            &self.verifier,
        );

        Ok(existing_inner_state.next_slot_input)
    }

    /// Update state, overriding PoT chain if it doesn't match provided values.
    ///
    /// Returns `Some(next_slot_input)` if reorg happened.
    pub(super) fn update(
        &self,
        best_slot: Slot,
        best_output: PotOutput,
        maybe_updated_parameters_change: Option<Option<PotParametersChange>>,
    ) -> PotStateUpdateOutcome {
        let previous_best_state;
        let new_best_state;
        {
            let mut inner_state = self.inner_state.lock();
            previous_best_state = *inner_state;
            new_best_state = previous_best_state.update(
                best_slot,
                best_output,
                maybe_updated_parameters_change,
                &self.verifier,
            );
            *inner_state = new_best_state;
        }

        if previous_best_state.next_slot_input == new_best_state.next_slot_input {
            return PotStateUpdateOutcome::NoChange;
        }

        if previous_best_state.next_slot_input.slot < new_best_state.next_slot_input.slot {
            let mut slot_iterations = previous_best_state.next_slot_input.slot_iterations;
            let mut seed = previous_best_state.next_slot_input.seed;

            for slot in u64::from(previous_best_state.next_slot_input.slot)
                ..u64::from(new_best_state.next_slot_input.slot)
            {
                let slot = Slot::from(slot);

                let Some(checkpoints) = self.verifier.try_get_checkpoints(slot_iterations, seed)
                else {
                    break;
                };

                let pot_input = PotNextSlotInput::derive(
                    slot_iterations,
                    slot,
                    checkpoints.output(),
                    &maybe_updated_parameters_change.flatten(),
                );

                // TODO: Consider carrying of the whole `PotNextSlotInput` rather than individual
                //  variables
                let next_slot = slot + Slot::from(1);
                slot_iterations = pot_input.slot_iterations;
                seed = pot_input.seed;

                if next_slot == new_best_state.next_slot_input.slot
                    && slot_iterations == new_best_state.next_slot_input.slot_iterations
                    && seed == new_best_state.next_slot_input.seed
                {
                    return PotStateUpdateOutcome::Extension {
                        from: previous_best_state.next_slot_input,
                        to: new_best_state.next_slot_input,
                    };
                }
            }
        }

        PotStateUpdateOutcome::Reorg {
            from: previous_best_state.next_slot_input,
            to: new_best_state.next_slot_input,
        }
    }
}
