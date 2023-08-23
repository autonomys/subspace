//! Subspace proof of time implementation.

#![feature(const_option)]

pub mod gossip;
mod slots;
pub mod source;
mod state_manager;
mod time_keeper;

use crate::slots::SlotInfoProducer;
use crate::source::PotSlotStream;
use crate::state_manager::{init_pot_state, PotProtocolState};
use core::num::NonZeroU32;
use futures::StreamExt;
use sc_consensus_slots::SlotWorker;
use sp_consensus::{SelectChain, SyncOracle};
use sp_consensus_slots::{Slot, SlotDuration};
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use subspace_core_primitives::{BlockNumber, PotKey, PotSeed, SlotNumber};
use tracing::debug;

pub use state_manager::{
    PotConsensusState, PotGetBlockProofsError, PotStateSummary, PotVerifyBlockProofsError,
};
pub use time_keeper::TimeKeeper;

/// Start a new slot worker.
///
/// Every time a new slot is triggered, `worker.on_slot` is called and the future it returns is
/// polled until completion, unless we are major syncing.
pub async fn start_slot_worker<Block, Client, Worker, SO, CIDP, Proof>(
    slot_duration: SlotDuration,
    client: Client,
    mut worker: Worker,
    sync_oracle: SO,
    create_inherent_data_providers: CIDP,
    mut slot_stream: PotSlotStream,
) where
    Block: BlockT,
    Client: SelectChain<Block>,
    Worker: SlotWorker<Block, Proof>,
    SO: SyncOracle + Send,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + 'static,
{
    let slot_info_producer = SlotInfoProducer::new(
        slot_duration.as_duration(),
        create_inherent_data_providers,
        client,
    );

    let mut maybe_last_slot = None;

    while let Some(slot) = slot_stream.next().await {
        if sync_oracle.is_major_syncing() {
            debug!(%slot, "Skipping proposal slot due to sync");
            continue;
        }

        if let Some(last_slot) = maybe_last_slot {
            if last_slot >= slot {
                // Already processed
                continue;
            }
        }
        maybe_last_slot.replace(slot);

        if let Some(slot_info) = slot_info_producer.produce_slot_info(Slot::from(slot)).await {
            let _ = worker.on_slot(slot_info).await;

            // TODO: Remove this hack, it restricts slot production with extremely low number of
            //  iterations
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

// TODO: change the fields that can't be zero to NonZero types.
// TODO: CLean up unused fields
#[derive(Debug, Clone)]
pub struct PotConfig {
    /// PoT seed used initially when PoT chain starts.
    pub initial_seed: PotSeed,

    /// PoT key used initially when PoT chain starts.
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
}

/// Components initialized during the new_partial() phase of set up.
#[derive(Debug)]
pub struct PotComponents {
    /// PoT seed used initially when PoT chain starts.
    // TODO: Remove this from here, shouldn't be necessary eventually
    pub(crate) initial_seed: PotSeed,

    /// PoT key used initially when PoT chain starts.
    // TODO: Remove this from here, shouldn't be necessary eventually
    pub initial_key: PotKey,

    /// PoT iterations for each slot.
    // TODO: Remove this from here, shouldn't be necessary eventually
    pub(crate) iterations: NonZeroU32,

    /// If the role is time keeper or node client.
    is_time_keeper: bool,

    /// Protocol state.
    protocol_state: Arc<dyn PotProtocolState>,

    /// Consensus state.
    consensus_state: Arc<dyn PotConsensusState>,
}

impl PotComponents {
    /// Sets up the partial components.
    pub fn new(is_time_keeper: bool, config: PotConfig) -> Self {
        let initial_seed = config.initial_seed;
        let initial_key = config.initial_key;
        let iterations = config.pot_iterations;
        let (protocol_state, consensus_state) = init_pot_state(config);

        Self {
            initial_seed,
            initial_key,
            iterations,
            is_time_keeper,
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
