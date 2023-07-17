//! Subspace proof of time implementation.

mod clock_master;
mod pot_client;
mod pot_state;
mod utils;

use crate::utils::GOSSIP_PROTOCOL;
use sc_network::config::NonDefaultSetConfig;
use sc_service::TaskManager;
use sc_utils::mpsc::tracing_unbounded;
use sp_consensus::SyncOracle;
use sp_runtime::traits::Block as BlockT;
use subspace_core_primitives::{BlockHash, BlockNumber, PotKey, SlotNumber};

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

/// Returns the network configuration for PoT gossip.
pub fn pot_gossip_peers_set_config() -> NonDefaultSetConfig {
    let mut cfg = NonDefaultSetConfig::new(GOSSIP_PROTOCOL.into(), 5 * 1024 * 1024);
    cfg.allow_non_reserved(25, 25);
    cfg
}

/// Starts the PoT components.
#[allow(clippy::type_complexity)]
pub fn start_pot<Block, SO>(
    clock_master_components: Option<(
        ClockMaster<Block, SO>,
        Box<dyn Fn() -> Option<InitialPotProofInputs> + Send>,
    )>,
    pot_client: PotClient<Block>,
    task_manager: &TaskManager,
) where
    Block: BlockT,
    SO: SyncOracle + Send + Sync + Clone + 'static,
{
    let receiver = clock_master_components.map(|(clock_master, init_fn)| {
        // Producer thread -> clock master.
        let (sender_clock_master, receiver_clock_master) =
            tracing_unbounded("clock-master-local-proofs-channel", 100);
        // Producer thread -> PoT client.
        let (sender_pot_client, receiver_pot_client) =
            tracing_unbounded("pot-client-local-proofs-channel", 100);
        task_manager.spawn_essential_handle().spawn_blocking(
            "subspace-proof-of-time-clock-master",
            Some("subspace-proof-of-time-clock-master"),
            async move {
                clock_master
                    .run(
                        init_fn,
                        sender_clock_master,
                        receiver_clock_master,
                        sender_pot_client,
                    )
                    .await;
            },
        );
        receiver_pot_client
    });

    task_manager.spawn_essential_handle().spawn_blocking(
        "subspace-proof-of-time-client",
        Some("subspace-proof-of-time-client"),
        async move {
            pot_client.run(receiver).await;
        },
    );
}
