//! Subspace proof of time implementation.

#![feature(let_chains)]

mod slots;
pub mod source;
pub mod verifier;

use crate::slots::SlotInfoProducer;
use crate::source::{PotSlotInfo, PotSlotInfoStream};
use sc_consensus_slots::{SimpleSlotWorker, SimpleSlotWorkerToSlotWorker, SlotWorker};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::{SelectChain, SyncOracle};
use sp_consensus_slots::{Slot, SlotDuration};
use sp_consensus_subspace::SubspaceApi;
use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use subspace_core_primitives::pot::PotCheckpoints;
use subspace_core_primitives::PublicKey;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, error, info, trace};

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
    client: Arc<Client>,
    select_chain: SC,
    worker: Worker,
    sync_oracle: SO,
    create_inherent_data_providers: CIDP,
    mut slot_info_stream: PotSlotInfoStream,
) where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: SubspaceApi<Block, PublicKey>,
    SC: SelectChain<Block>,
    Worker: PotSlotWorker<Block> + SimpleSlotWorker<Block> + Send + Sync,
    SO: SyncOracle + Send,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + 'static,
{
    let best_hash = client.info().best_hash;
    let runtime_api = client.runtime_api();
    let block_authoring_delay = match runtime_api.chain_constants(best_hash) {
        Ok(chain_constants) => chain_constants.block_authoring_delay(),
        Err(error) => {
            error!(%error, "Failed to retrieve chain constants from runtime API");
            return;
        }
    };

    let slot_info_producer = SlotInfoProducer::new(
        slot_duration.as_duration(),
        create_inherent_data_providers,
        select_chain,
    );

    let mut worker = SimpleSlotWorkerToSlotWorker(worker);

    let mut maybe_last_proven_slot = None;

    loop {
        let PotSlotInfo { slot, checkpoints } = match slot_info_stream.recv().await {
            Ok(slot_info) => slot_info,
            Err(err) => match err {
                RecvError::Closed => {
                    info!("No Slot info senders available. Exiting slot worker.");
                    return;
                }
                RecvError::Lagged(skipped_notifications) => {
                    debug!(
                        "Slot worker is lagging. Skipped {} slot notification(s)",
                        skipped_notifications
                    );
                    continue;
                }
            },
        };
        if let Some(last_proven_slot) = maybe_last_proven_slot {
            if last_proven_slot >= slot {
                // Already processed
                continue;
            }
        }
        maybe_last_proven_slot.replace(slot);

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

        if let Some(slot_info) = slot_info_producer.produce_slot_info(slot_to_claim).await {
            let _ = worker.on_slot(slot_info).await;
        }
    }
}
