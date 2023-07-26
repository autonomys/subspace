//! Subspace proof of time implementation.

mod clock_master;
mod pot_client;
mod pot_state;
mod utils;

use crate::pot_state::{init_pot_state, PotState};
use crate::utils::GOSSIP_PROTOCOL;
use sc_network::config::NonDefaultSetConfig;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;
use subspace_core_primitives::{BlockHash, BlockNumber, PotKey, PotProof, SlotNumber};
use subspace_proof_of_time::ProofOfTime;

pub use clock_master::ClockMaster;
pub use pot_client::PotClient;
pub use utils::PotGossip;

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

/// Components initialized during the new_partial() phase of set up.
pub struct PotPartial<Block> {
    /// Proof of time implementation.
    proof_of_time: Arc<ProofOfTime>,

    /// Protocol interface.
    pot_state: Arc<dyn PotState>,

    /// Consensus interface.
    pot_consensus: Arc<dyn PotConsensus<Block>>,
}

impl<Block: BlockT> PotPartial<Block> {
    /// Sets up the partial components.
    pub fn new() -> Self {
        let config = PotConfig::default();
        let proof_of_time = Arc::new(ProofOfTime::new(
            config.num_checkpoints,
            config.checkpoint_iterations,
        ));
        let (pot_state, pot_consensus) = init_pot_state(config, proof_of_time.clone(), vec![]);

        Self {
            proof_of_time,
            pot_state,
            pot_consensus,
        }
    }

    /// Returns the consensus interface.
    pub fn pot_consensus(&self) -> Arc<dyn PotConsensus<Block>> {
        self.pot_consensus.clone()
    }
}

impl<Block: BlockT> Default for PotPartial<Block> {
    fn default() -> Self {
        Self::new()
    }
}

/// Inputs for bootstrapping.
#[derive(Debug, Clone)]
pub struct BootstrapParams {
    /// Genesis block hash.
    pub genesis_hash: BlockHash,

    /// The initial key to be used.
    pub key: PotKey,

    /// Initial slot number.
    pub slot: SlotNumber,
}

impl BootstrapParams {
    pub fn new(genesis_hash: BlockHash, slot: SlotNumber) -> Self {
        Self {
            genesis_hash,
            key: PotKey::initial_key(),
            slot,
        }
    }
}

/// The role of subspace-node
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PotRole {
    /// Clock master role of producing proofs + initial bootstrapping.
    ClockMasterBootStrap,

    /// Clock master role of producing proofs.
    ClockMaster,

    /// Listens to proofs from clock masters.
    Client,
}

impl PotRole {
    /// Checks if the role is clock master.
    pub fn is_clock_master(&self) -> bool {
        *self == Self::ClockMasterBootStrap || *self == Self::ClockMaster
    }

    /// Checks if the role is clock master bootstrap.
    pub fn is_clock_master_bootstrap(&self) -> bool {
        *self == Self::ClockMasterBootStrap
    }
}

/// PoT interface to consensus.
pub trait PotConsensus<Block: BlockT>: Send + Sync {
    /// Called by consensus when trying to claim the slot.
    /// Returns the proofs in the slot range
    /// [parent.last_proof.slot + 1, slot_number - global_randomness_reveal_lag_slots].
    fn get_block_proofs(
        &self,
        slot_number: SlotNumber,
        block_number: NumberFor<Block>,
        parent_block_proofs: &[PotProof],
    ) -> Result<Vec<PotProof>, PotConsensusError>;

    /// Called during block import validation.
    /// Verifies the sequence of proofs in the block being validated.
    fn verify_block_proofs(
        &self,
        slot_number: SlotNumber,
        block_number: NumberFor<Block>,
        block_proofs: &[PotProof],
        parent_block_proofs: &[PotProof],
    ) -> Result<(), PotConsensusError>;
}

#[derive(Debug, thiserror::Error)]
pub enum PotConsensusError {
    #[error("Parent block proofs empty: {cur_tip}/{slot_number}/{block_number}")]
    ParentProofsEmpty {
        cur_tip: String,
        slot_number: SlotNumber,
        block_number: String,
    },

    #[error("Invalid slot range: {cur_tip}/{start_slot}/{end_slot}/{block_number}")]
    InvalidRange {
        cur_tip: String,
        start_slot: SlotNumber,
        end_slot: SlotNumber,
        block_number: String,
    },

    #[error("Proof unavailable to send: {cur_tip}/{start_slot}/{end_slot}/{block_number}/{slot}")]
    ProofUnavailable {
        cur_tip: String,
        start_slot: SlotNumber,
        end_slot: SlotNumber,
        block_number: String,
        slot: SlotNumber,
    },

    #[error("Unexpected proof count: {cur_tip}/{block_number}/{slot}/{expected}/{actual}")]
    UnexpectedProofCount {
        cur_tip: String,
        block_number: String,
        slot: SlotNumber,
        expected: usize,
        actual: usize,
    },

    #[error("Received proof locally missing: {cur_tip}/{block_number}/{slot}")]
    ReceivedSlotMissing {
        cur_tip: String,
        block_number: String,
        slot: SlotNumber,
    },

    #[error("Received proof did not match local proof: {cur_tip}/{block_number}/{slot}")]
    ReceivedProofMismatch {
        cur_tip: String,
        block_number: String,
        slot: SlotNumber,
    },

    #[error("Received block with no proofs: {cur_tip}/{slot_number}/{block_number}")]
    ReceivedProofsEmpty {
        cur_tip: String,
        slot_number: SlotNumber,
        block_number: String,
    },

    #[error(
        "Received proofs with unexpected slot number: {cur_tip}/{block_number}/{expected}/{actual}"
    )]
    ReceivedUnexpectedSlotNumber {
        cur_tip: String,
        block_number: String,
        expected: SlotNumber,
        actual: SlotNumber,
    },
}

/// Returns the network configuration for PoT gossip.
pub fn pot_gossip_peers_set_config() -> NonDefaultSetConfig {
    let mut cfg = NonDefaultSetConfig::new(GOSSIP_PROTOCOL.into(), 5 * 1024 * 1024);
    cfg.allow_non_reserved(25, 25);
    cfg
}
