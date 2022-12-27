#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use sp_domain_tracker::StateRootUpdate;
use sp_runtime::{ConsensusEngineId, DigestItem};

const DOMAIN_ENGINE_ID: ConsensusEngineId = *b"DMN_";

const DOMAIN_REGISTRY_ENGINE_ID: ConsensusEngineId = *b"RGTR";

/// Trait to provide simpler abstractions to create predigests for runtime.
pub trait AsPredigest {
    /// Returns state root update digest
    fn as_system_domain_state_root_update<Number: Decode, StateRoot: Decode>(
        &self,
    ) -> Option<StateRootUpdate<Number, StateRoot>>;

    /// Creates a new digest from state root update for system domain.
    fn system_domain_state_root_update<Number: Encode, StateRoot: Encode>(
        update: StateRootUpdate<Number, StateRoot>,
    ) -> Self;

    /// Returna a pair of (primary_block_number, primary_block_hash).
    fn as_primary_block_info<Number: Decode, Hash: Decode>(&self) -> Option<(Number, Hash)>;

    /// Creates a new digest of primary block info for system domain.
    fn primary_block_info<Number: Encode, Hash: Encode>(info: (Number, Hash)) -> Self;
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

    /// Returna a pair of (primary_block_number, primary_block_hash).
    fn as_primary_block_info<Number: Decode, Hash: Decode>(&self) -> Option<(Number, Hash)> {
        self.pre_runtime_try_to(&DOMAIN_REGISTRY_ENGINE_ID)
    }

    fn primary_block_info<Number: Encode, Hash: Encode>(info: (Number, Hash)) -> Self {
        DigestItem::PreRuntime(DOMAIN_REGISTRY_ENGINE_ID, info.encode())
    }
}
