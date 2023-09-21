//! Subspace proof of time implementation.

#![feature(const_option, extract_if, let_chains)]

mod slots;
pub mod source;
pub mod verifier;

use crate::slots::SlotInfoProducer;
use crate::source::{PotSlotInfo, PotSlotInfoStream};
use futures::StreamExt;
use sc_consensus_slots::{SimpleSlotWorker, SimpleSlotWorkerToSlotWorker, SlotWorker};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::{SelectChain, SyncOracle};
use sp_consensus_slots::{Slot, SlotDuration};
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi as SubspaceRuntimeApi};
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::Block as BlockT;
#[cfg(feature = "pot")]
use std::sync::Arc;
use subspace_core_primitives::PotCheckpoints;
#[cfg(feature = "pot")]
use tracing::error;
use tracing::{debug, trace};

pub trait PotSlotWorker<Block>
where
    Block: BlockT,
{
    /// Called when new proof of time is available for slot.
    ///
    /// NOTE: Can be called more than once in case of reorgs to override old slots.
    fn on_proof(&mut self, slot: Slot, checkpoints: PotCheckpoints);
}

/// Start a new slot worker.
///
/// Every time a new slot is triggered, `worker.on_slot` is called and the future it returns is
/// polled until completion, unless we are major syncing.
pub async fn start_slot_worker<Block, Client, SC, Worker, SO, CIDP>(
    slot_duration: SlotDuration,
    #[cfg(feature = "pot")] client: Arc<Client>,
    select_chain: SC,
    worker: Worker,
    sync_oracle: SO,
    create_inherent_data_providers: CIDP,
    mut slot_info_stream: PotSlotInfoStream,
) where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: SubspaceRuntimeApi<Block, FarmerPublicKey>,
    SC: SelectChain<Block>,
    Worker: PotSlotWorker<Block> + SimpleSlotWorker<Block> + Send + Sync,
    SO: SyncOracle + Send,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + 'static,
{
    #[cfg(feature = "pot")]
    let best_hash = client.info().best_hash;
    #[cfg(feature = "pot")]
    let runtime_api = client.runtime_api();
    #[cfg(feature = "pot")]
    let block_authoring_delay = match runtime_api.chain_constants(best_hash) {
        Ok(chain_constants) => chain_constants.block_authoring_delay(),
        Err(error) => {
            error!(%error, "Failed to retrieve chain constants from runtime API");
            return;
        }
    };
    #[cfg(not(feature = "pot"))]
    let block_authoring_delay = Slot::from(6);

    let slot_info_producer = SlotInfoProducer::new(
        slot_duration.as_duration(),
        create_inherent_data_providers,
        select_chain,
    );

    let mut worker = SimpleSlotWorkerToSlotWorker(worker);

    let mut maybe_last_claimed_slot = None;

    while let Some(PotSlotInfo { slot, checkpoints }) = slot_info_stream.next().await {
        worker.0.on_proof(slot, checkpoints);

        if sync_oracle.is_major_syncing() {
            debug!(%slot, "Skipping proposal slot due to sync");
            continue;
        }

        // Slots that we claim must be `block_authoring_delay` behind the best slot we know of
        let Some(slot_to_claim) = slot.checked_sub(*block_authoring_delay).map(Slot::from) else {
            trace!("Skipping very early slot during chain start");
            continue;
        };

        if let Some(last_claimed_slot) = maybe_last_claimed_slot {
            if last_claimed_slot >= slot_to_claim {
                // Already processed
                continue;
            }
        }
        maybe_last_claimed_slot.replace(slot_to_claim);

        if let Some(slot_info) = slot_info_producer.produce_slot_info(slot_to_claim).await {
            let _ = worker.on_slot(slot_info).await;
        }
    }
}
