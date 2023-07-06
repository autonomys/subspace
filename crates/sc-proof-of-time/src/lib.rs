//! Subspace proof of time implementation.

mod clock_master;
mod pot_state;

use subspace_core_primitives::{BlockHash, BlockNumber, PotKey, SlotNumber};

pub use clock_master::{pot_gossip_peers_set_config, ClockMaster};
pub use pot_state::{clock_master_state, ClockMasterState};

pub(crate) const LOG_TARGET: &str = "subspace-proof-of-time";

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

    /// Number of checkpoints per proof.
    pub num_checkpoints: u8,

    /// Number of EAS iterations per checkpoints.
    /// Total iterations per proof = num_checkpoints * checkpoint_iterations.
    pub checkpoint_iterations: u32,
}

impl Default for PotConfig {
    fn default() -> Self {
        // TODO: fill proper values
        Self {
            randomness_update_interval_blocks: 18,
            injection_depth_blocks: 90,
            global_randomness_reveal_lag_slots: 6,
            pot_injection_lag_slots: 6,
            max_future_slots: 10,
            num_checkpoints: 16,
            checkpoint_iterations: 200_000,
        }
    }
}

/// Inputs to build the initial proof.
#[derive(Debug, Clone)]
pub struct InitialPotProofInputs {
    /// Genesis block hash.
    pub genesis_hash: BlockHash,

    /// Slot number for the genesis block.
    pub genesis_slot: SlotNumber,

    /// The initial key to be used.
    pub key: PotKey,
}

impl InitialPotProofInputs {
    pub fn new(genesis_hash: BlockHash, genesis_slot: SlotNumber) -> Self {
        Self {
            genesis_hash,
            genesis_slot,
            key: PotKey::initial_key(),
        }
    }
}
