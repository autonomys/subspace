//! Subspace proof of time implementation.

#![feature(const_option)]

mod clock_master;
mod gossip;
mod node_client;
mod state_manager;
mod utils;

use crate::state_manager::{init_pot_state, PotProtocolState};
use core::num::{NonZeroU32, NonZeroU8};
use std::sync::Arc;
use subspace_core_primitives::{BlockNumber, SlotNumber};
use subspace_proof_of_time::ProofOfTime;

pub use clock_master::ClockMaster;
pub use gossip::pot_gossip_peers_set_config;
pub use node_client::PotClient;
pub use state_manager::{
    PotConsensusState, PotGetBlockProofsError, PotStateSummary, PotVerifyBlockProofsError,
};

// TODO: change the fields that can't be zero to NonZero types.
#[derive(Debug, Clone)]
pub struct PotConfig {
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

impl Default for PotConfig {
    fn default() -> Self {
        // TODO: fill proper values. These are set to use less
        // CPU and take less than 1 sec to produce per proof
        // during the initial testing.
        Self {
            randomness_update_interval_blocks: 18,
            injection_depth_blocks: 90,
            global_randomness_reveal_lag_slots: 6,
            pot_injection_lag_slots: 6,
            max_future_slots: 10,
            pot_iterations: NonZeroU32::new(4 * 1_000).expect("Not zero; qed"),
            num_checkpoints: NonZeroU8::new(4).expect("Not zero; qed"),
        }
    }
}

/// Components initialized during the new_partial() phase of set up.
pub struct PotComponents {
    /// If the role is clock master or node client.
    is_clock_master: bool,

    /// Proof of time implementation.
    proof_of_time: ProofOfTime,

    /// Protocol state.
    protocol_state: Arc<dyn PotProtocolState>,

    /// Consensus state.
    consensus_state: Arc<dyn PotConsensusState>,
}

impl PotComponents {
    /// Sets up the partial components.
    pub fn new(is_clock_master: bool) -> Self {
        let config = PotConfig::default();
        let proof_of_time = ProofOfTime::new(config.pot_iterations, config.num_checkpoints)
            // TODO: Proper error handling or proof
            .expect("Failed to initialize proof of time");
        let (protocol_state, consensus_state) = init_pot_state(config);

        Self {
            is_clock_master,
            proof_of_time,
            protocol_state,
            consensus_state,
        }
    }

    /// Checks if the role is clock master or node client.
    pub fn is_clock_master(&self) -> bool {
        self.is_clock_master
    }

    /// Returns the consensus interface.
    pub fn consensus_state(&self) -> Arc<dyn PotConsensusState> {
        self.consensus_state.clone()
    }
}
