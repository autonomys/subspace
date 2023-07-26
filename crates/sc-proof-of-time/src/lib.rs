//! Subspace proof of time implementation.

mod clock_master;
mod gossip;
mod state_manager;
mod utils;

use crate::state_manager::PotProtocolState;
use core::num::{NonZeroU32, NonZeroU8};
use std::sync::Arc;
use subspace_core_primitives::{BlockNumber, SlotNumber};
use subspace_proof_of_time::ProofOfTime;

pub use clock_master::{BootstrapParams, ClockMaster};
pub use gossip::{pot_gossip_peers_set_config, PotGossip};

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
        // TODO: fill proper values. These are set to produce
        // approximately 1 proof/sec during testing.
        Self {
            randomness_update_interval_blocks: 18,
            injection_depth_blocks: 90,
            global_randomness_reveal_lag_slots: 6,
            pot_injection_lag_slots: 6,
            max_future_slots: 10,
            pot_iterations: NonZeroU32::new(16 * 200_000).expect("pot_iterations cannot be zero"),
            num_checkpoints: NonZeroU8::new(16).expect("num_checkpoints cannot be zero"),
        }
    }
}

/// Components initialized during the new_partial() phase of set up.
pub struct PotComponents {
    /// Proof of time implementation.
    proof_of_time: ProofOfTime,

    /// Protocol state.
    protocol_state: Arc<dyn PotProtocolState>,
}
