use codec::{Decode, Encode};
use sp_domain_tracker::StateRootUpdate;
use sp_runtime::{ConsensusEngineId, DigestItem};

const DOMAIN_ENGINE_ID: ConsensusEngineId = *b"DMN_";

pub trait AsPredigest {
    /// Returns state root update digest
    fn as_system_domain_state_root_update<Number: Decode, StateRoot: Decode>(
        &self,
    ) -> Option<StateRootUpdate<Number, StateRoot>>;

    /// Creates a new digest from state root update for system domain.
    fn system_domain_state_root_update<Number: Encode, StateRoot: Encode>(
        update: StateRootUpdate<Number, StateRoot>,
    ) -> Self;
}

impl AsPredigest for DigestItem {
    fn as_system_domain_state_root_update<Number: Decode, StateRoot: Decode>(
        &self,
    ) -> Option<StateRootUpdate<Number, StateRoot>> {
        self.pre_runtime_try_to(&DOMAIN_ENGINE_ID)
    }

    fn system_domain_state_root_update<Number: Encode, StateRoot: Encode>(
        update: StateRootUpdate<Number, StateRoot>,
    ) -> Self {
        DigestItem::PreRuntime(DOMAIN_ENGINE_ID, update.encode())
    }
}
