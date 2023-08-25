//! Subspace proof of time implementation.

#![feature(const_option)]

pub mod gossip;
mod state_manager;
mod time_keeper;

use crate::state_manager::{init_pot_state, PotProtocolState};
use core::num::{NonZeroU32, NonZeroU8};
use std::sync::Arc;
use subspace_core_primitives::{BlockNumber, PotKey, SlotNumber};
use subspace_proof_of_time::ProofOfTime;

pub use state_manager::{
    PotConsensusState, PotGetBlockProofsError, PotStateSummary, PotVerifyBlockProofsError,
};
pub use time_keeper::TimeKeeper;

// TODO: change the fields that can't be zero to NonZero types.
#[derive(Debug, Clone)]
pub struct PotConfig {
    /// PoT key used initially when PoT chain starts.
    // TODO: Also add seed field here
    pub initial_key: PotKey,

    /// Frequency of entropy injection from consensus.
    pub randomness_update_interval_blocks: BlockNumber,

    /// Starting point for entropy injection from consensus.
    pub injection_depth_blocks: BlockNumber,

    /// Number of slots it takes for updated global randomness to
    /// take effect.
    pub global_randomness_reveal_lag_slots: SlotNumber,

    /// Number of slots it takes for injected randomness to
    /// take effect.
    pub pot_injection_lag_slots: SlotNumber,

    /// If the received proof is more than max_future_slots into the
    /// future from the current tip's slot, reject it.
    pub max_future_slots: SlotNumber,

    /// Total iterations per proof.
    pub pot_iterations: NonZeroU32,

    /// Number of checkpoints per proof.
    pub num_checkpoints: NonZeroU8,
}

/// Components initialized during the new_partial() phase of set up.
#[derive(Debug)]
pub struct PotComponents {
    /// PoT key used initially when PoT chain starts.
    // TODO: Remove this from here, shouldn't be necessary eventually
    pub(crate) initial_key: PotKey,

    /// If the role is time keeper or node client.
    is_time_keeper: bool,

    /// Proof of time implementation.
    proof_of_time: ProofOfTime,

    /// Protocol state.
    protocol_state: Arc<dyn PotProtocolState>,

    /// Consensus state.
    consensus_state: Arc<dyn PotConsensusState>,
}

impl PotComponents {
    /// Sets up the partial components.
    pub fn new(is_time_keeper: bool, config: PotConfig) -> Self {
        let proof_of_time = ProofOfTime::new(config.pot_iterations, config.num_checkpoints)
            // TODO: Proper error handling or proof
            .expect("Failed to initialize proof of time");
        let initial_key = config.initial_key;
        let (protocol_state, consensus_state) = init_pot_state(config, proof_of_time);

        Self {
            initial_key,
            is_time_keeper,
            proof_of_time,
            protocol_state,
            consensus_state,
        }
    }

    /// Checks if the role is time keeper or node client.
    pub fn is_time_keeper(&self) -> bool {
        self.is_time_keeper
    }

    /// Returns the consensus interface.
    pub fn consensus_state(&self) -> Arc<dyn PotConsensusState> {
        self.consensus_state.clone()
    }
}
