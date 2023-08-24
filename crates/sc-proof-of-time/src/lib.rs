//! Subspace proof of time implementation.

#![feature(const_option)]

// TODO: Adjust or remove unused modules in the future
// pub mod gossip;
mod slots;
pub mod source;
// mod state_manager;
// mod time_keeper;

use crate::slots::SlotInfoProducer;
use crate::source::{PotSlotInfo, PotSlotInfoStream};
use futures::StreamExt;
use sc_consensus_slots::{SimpleSlotWorker, SimpleSlotWorkerToSlotWorker, SlotWorker};
use sp_consensus::{SelectChain, SyncOracle};
use sp_consensus_slots::{Slot, SlotDuration};
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::Block as BlockT;
use subspace_core_primitives::{PotCheckpoints, SlotNumber};
use tracing::debug;

pub trait PotSlotWorker<Block>
where
    Block: BlockT,
{
    // TODO: It should be possible to remove this once Substrate's `SlotInfo` supports extra payload
    //  in it directly
    fn on_proof(&mut self, slot: SlotNumber, checkpoints: PotCheckpoints);
}

/// Start a new slot worker.
///
/// Every time a new slot is triggered, `worker.on_slot` is called and the future it returns is
/// polled until completion, unless we are major syncing.
pub async fn start_slot_worker<Block, Client, Worker, SO, CIDP>(
    slot_duration: SlotDuration,
    client: Client,
    worker: Worker,
    sync_oracle: SO,
    create_inherent_data_providers: CIDP,
    mut slot_info_stream: PotSlotInfoStream,
) where
    Block: BlockT,
    Client: SelectChain<Block>,
    Worker: PotSlotWorker<Block> + SimpleSlotWorker<Block> + Send + Sync,
    SO: SyncOracle + Send,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + 'static,
{
    let slot_info_producer = SlotInfoProducer::new(
        slot_duration.as_duration(),
        create_inherent_data_providers,
        client,
    );

    let mut worker = SimpleSlotWorkerToSlotWorker(worker);

    let mut maybe_last_slot = None;

    while let Some(PotSlotInfo { slot, checkpoints }) = slot_info_stream.next().await {
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
            worker.0.on_proof(slot, checkpoints);
            let _ = worker.on_slot(slot_info).await;

            // TODO: Remove this hack, it restricts slot production with extremely low number of
            //  iterations
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}
