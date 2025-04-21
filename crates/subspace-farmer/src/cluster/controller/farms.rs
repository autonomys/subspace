//! This module exposed implementation of farms maintenance.
//!
//! The goal is to observe farms in a cluster and keep controller's data structures
//! about which pieces are plotted in which sectors of which farm up to date. Implementation
//! automatically handles dynamic farm addition and removal, etc.

use crate::cluster::controller::stream_map::StreamMap;
use crate::cluster::controller::ClusterControllerFarmerIdentifyBroadcast;
use crate::cluster::farmer::{
    ClusterFarm, ClusterFarmerFarmDetails, ClusterFarmerFarmDetailsRequest, ClusterFarmerId,
    ClusterFarmerIdentifyBroadcast,
};
use crate::cluster::nats_client::NatsClient;
use crate::farm::plotted_pieces::PlottedPieces;
use crate::farm::{Farm, FarmId, SectorPlottingDetails, SectorUpdate};
use anyhow::anyhow;
use async_lock::RwLock as AsyncRwLock;
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, StreamExt};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::mem;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subspace_core_primitives::sectors::SectorIndex;
use tokio::sync::broadcast;
use tokio::task;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, trace, warn};

/// Number of farms in a cluster is currently limited to 2^16
pub type FarmIndex = u16;

enum FarmAddRemoveResult {
    Add {
        close_receiver: broadcast::Receiver<()>,
        farm: ClusterFarm,
    },
    Remove {
        farm_index: FarmIndex,
    },
}

struct FarmerAddResult<I> {
    close_receiver: broadcast::Receiver<()>,
    added_farms: I,
}

#[derive(Debug)]
struct KnownFarmer {
    farmer_id: ClusterFarmerId,
    last_identification: Instant,
    known_farms: HashMap<FarmIndex, FarmId>,
    close_sender: Option<broadcast::Sender<()>>,
}

impl KnownFarmer {
    fn notify_cleanup(&mut self) -> bool {
        let Some(close_sender) = self.close_sender.take() else {
            return false;
        };
        let _ = close_sender.send(());
        true
    }
}

#[derive(Debug)]
struct KnownFarmers {
    identification_broadcast_interval: Duration,
    known_farmers: Vec<KnownFarmer>,
}

impl KnownFarmers {
    fn new(identification_broadcast_interval: Duration) -> Self {
        Self {
            identification_broadcast_interval,
            known_farmers: Vec::new(),
        }
    }

    /// Return `false` if the farmer is unknown and initialization is required
    fn refresh(&mut self, farmer_id: ClusterFarmerId) -> bool {
        self.known_farmers.iter_mut().any(|known_farmer| {
            if known_farmer.farmer_id == farmer_id {
                trace!(%farmer_id, "Updating last identification for farmer");
                known_farmer.last_identification = Instant::now();
                true
            } else {
                false
            }
        })
    }

    fn add(
        &mut self,
        farmer_id: ClusterFarmerId,
        farms: Vec<ClusterFarmerFarmDetails>,
    ) -> FarmerAddResult<impl Iterator<Item = (FarmIndex, ClusterFarmerFarmDetails)>> {
        let farm_indices = self.pick_farm_indices(farms.len());
        let farm_ids_to_add = farms
            .iter()
            .map(|farm_details| farm_details.farm_id)
            .collect::<HashSet<FarmId>>();

        if let Some(old_farmer) = self.known_farmers.iter_mut().find(|known_farmer| {
            known_farmer
                .known_farms
                .values()
                .any(|farm_id| farm_ids_to_add.contains(farm_id))
        }) {
            warn!(old_farmer_id = %old_farmer.farmer_id, "Some farms are already known, notify for cleanup them first");
            old_farmer.notify_cleanup();
        }

        let (close_sender, close_receiver) = broadcast::channel(1);
        self.known_farmers.push(KnownFarmer {
            farmer_id,
            last_identification: Instant::now(),
            known_farms: farm_indices
                .iter()
                .copied()
                .zip(farms.iter().map(|farm_details| farm_details.farm_id))
                .collect(),
            close_sender: Some(close_sender),
        });

        FarmerAddResult {
            close_receiver,
            added_farms: farm_indices.into_iter().zip(farms),
        }
    }

    fn pick_farm_indices(&self, len: usize) -> Vec<u16> {
        let used_indices = self
            .known_farmers
            .iter()
            .flat_map(|known_farmer| known_farmer.known_farms.keys())
            .collect::<HashSet<_>>();

        let mut available_indices = Vec::with_capacity(len);

        for farm_index in FarmIndex::MIN..=FarmIndex::MAX {
            if !used_indices.contains(&farm_index) {
                if available_indices.len() < len {
                    available_indices.push(farm_index);
                } else {
                    return available_indices;
                }
            }
        }

        warn!(max_supported_farm_index = %FarmIndex::MAX, "Too many farms");
        available_indices
    }

    fn remove_expired(&mut self) -> impl Iterator<Item = (ClusterFarmerId, &FarmIndex, &FarmId)> {
        self.known_farmers
            .iter_mut()
            .filter_map(|known_farmer| {
                if known_farmer.last_identification.elapsed()
                    > self.identification_broadcast_interval * 2
                    && known_farmer.notify_cleanup()
                {
                    Some(
                        known_farmer
                            .known_farms
                            .iter()
                            .map(|(farm_index, farm_id)| {
                                (known_farmer.farmer_id, farm_index, farm_id)
                            }),
                    )
                } else {
                    None
                }
            })
            .flatten()
    }

    fn remove_farm(&mut self, farm_index: FarmIndex) {
        self.known_farmers.retain_mut(|known_farmer| {
            if known_farmer.known_farms.contains_key(&farm_index) {
                known_farmer.known_farms.remove(&farm_index);
                !known_farmer.known_farms.is_empty()
            } else {
                true
            }
        });
    }
}

/// Utility function for maintaining farms by controller in a cluster environment
pub async fn maintain_farms(
    instance: &str,
    nats_client: &NatsClient,
    plotted_pieces: &Arc<AsyncRwLock<PlottedPieces<FarmIndex>>>,
    identification_broadcast_interval: Duration,
) -> anyhow::Result<()> {
    let mut known_farmers = KnownFarmers::new(identification_broadcast_interval);

    let mut farmers_to_add = StreamMap::default();
    // Stream map for adding/removing farms
    let mut farms_to_add_remove = StreamMap::default();
    let mut farms = FuturesUnordered::new();

    let farmer_identify_subscription = pin!(nats_client
        .subscribe_to_broadcasts::<ClusterFarmerIdentifyBroadcast>(None, None)
        .await
        .map_err(|error| anyhow!("Failed to subscribe to farmer identify broadcast: {error}"))?);

    // Request farmer to identify themselves
    if let Err(error) = nats_client
        .broadcast(&ClusterControllerFarmerIdentifyBroadcast, instance)
        .await
    {
        warn!(%error, "Failed to send farmer identification broadcast");
    }

    let mut farmer_identify_subscription = farmer_identify_subscription.fuse();
    let mut farm_pruning_interval = tokio::time::interval_at(
        (Instant::now() + identification_broadcast_interval * 2).into(),
        identification_broadcast_interval * 2,
    );
    farm_pruning_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        select! {
            (farm_index, result) = farms.select_next_some() => {
                farms_to_add_remove.push(farm_index, Box::pin(async move {
                    let plotted_pieces = Arc::clone(plotted_pieces);

                    let delete_farm_fut = task::spawn_blocking(move || {
                        plotted_pieces.write_blocking().delete_farm(farm_index);
                    });
                    if let Err(error) = delete_farm_fut.await {
                        error!(
                            %farm_index,
                            %error,
                            "Failed to delete farm that exited"
                        );
                    }

                    FarmAddRemoveResult::Remove { farm_index }
                }));

                match result {
                    Ok(()) => {
                        info!(%farm_index, "Farm exited successfully");
                    }
                    Err(error) => {
                        error!(%farm_index, %error, "Farm exited with error");
                    }
                }
            }
            maybe_identify_message = farmer_identify_subscription.next() => {
                let Some(identify_message) = maybe_identify_message else {
                    return Err(anyhow!("Farmer identify stream ended"));
                };
                let ClusterFarmerIdentifyBroadcast {
                    farmer_id,
                } = identify_message;

                if known_farmers.refresh(farmer_id) {
                    trace!(
                        %farmer_id,
                        "Received identification for already known farmer"
                    );
                } else if farmers_to_add.add_if_not_in_progress(farmer_id, Box::pin(collect_farmer_farms(farmer_id, nats_client))) {
                    debug!(
                        %farmer_id,
                        "Received identification for new farmer, collecting farms"
                    );
                } else {
                    debug!(
                        %farmer_id,
                        "Received identification for new farmer, which is already in progress"
                    );
                }
            }
            (farmer_id, maybe_farms) = farmers_to_add.select_next_some() => {
                let Ok(farms) = maybe_farms.inspect_err(|error| {
                    warn!(
                        %farmer_id,
                        %error,
                        "Failed to collect farms to add, may retry later"
                    );
                }) else {
                    continue;
                };

                let farm_add_result = known_farmers.add(farmer_id, farms);
                let FarmerAddResult {
                    close_receiver,
                    added_farms,
                } = farm_add_result;
                for (farm_index, farm_details) in added_farms {
                    let ClusterFarmerFarmDetails {
                        farm_id,
                        total_sectors_count,
                    } = farm_details;

                    let plotted_pieces = Arc::clone(plotted_pieces);
                    let close_receiver = close_receiver.resubscribe();
                    farms_to_add_remove.push(
                        farm_index,
                        Box::pin(async move {
                            match initialize_farm(
                                farm_index,
                                farm_id,
                                total_sectors_count,
                                plotted_pieces,
                                nats_client,
                            )
                            .await
                            {
                                Ok(farm) => {
                                    info!(
                                        %farmer_id,
                                        %farm_index,
                                        %farm_id,
                                        "Farm initialized successfully"
                                    );

                                    FarmAddRemoveResult::Add {
                                        close_receiver,
                                        farm,
                                    }
                                }
                                Err(error) => {
                                    warn!(
                                        %farmer_id,
                                        %farm_index,
                                        %farm_id,
                                        %error,
                                        "Failed to initialize farm"
                                    );
                                    // We should remove the farm if it failed to initialize
                                    FarmAddRemoveResult::Remove { farm_index }
                                }
                            }
                        }),
                    );
                }
            }
            _ = farm_pruning_interval.tick().fuse() => {
                for (farmer_id, farm_index, farm_id) in known_farmers.remove_expired() {
                    warn!(
                        %farmer_id,
                        %farm_index,
                        %farm_id,
                        "Farm expired, notify for cleanup"
                    );
                }
            }
            (farm_index, result) = farms_to_add_remove.select_next_some() => {
                match result {
                    FarmAddRemoveResult::Add {
                        mut close_receiver,
                        farm,
                    } => {
                        farms.push(async move {
                            select! {
                                result = farm.run().fuse() => {
                                    (farm_index, result)
                                }
                                _ = close_receiver.recv().fuse() => {
                                    // Nothing to do
                                    (farm_index, Ok(()))
                                }
                            }
                        });
                    }
                    FarmAddRemoveResult::Remove { farm_index } => {
                        known_farmers.remove_farm(farm_index);
                    }
                }
            }
        }
    }
}

/// Collect `ClusterFarmerFarmDetails` from the farmer by sending a stream request
async fn collect_farmer_farms(
    farmer_id: ClusterFarmerId,
    nats_client: &NatsClient,
) -> anyhow::Result<Vec<ClusterFarmerFarmDetails>> {
    trace!(%farmer_id, "Requesting farmer farm details");
    Ok(nats_client
        .stream_request(
            &ClusterFarmerFarmDetailsRequest,
            Some(&farmer_id.to_string()),
        )
        .await
        .inspect_err(|error| {
            warn!(
                %error,
                %farmer_id,
                "Failed to request farmer farm details"
            )
        })?
        .collect()
        .await)
}

async fn initialize_farm(
    farm_index: FarmIndex,
    farm_id: FarmId,
    total_sectors_count: SectorIndex,
    plotted_pieces: Arc<AsyncRwLock<PlottedPieces<FarmIndex>>>,
    nats_client: &NatsClient,
) -> anyhow::Result<ClusterFarm> {
    let farm = ClusterFarm::new(farm_id, total_sectors_count, nats_client.clone())
        .await
        .map_err(|error| anyhow!("Failed instantiate cluster farm {farm_id}: {error}"))?;

    // Buffer sectors that are plotted while already plotted sectors are being iterated over
    let plotted_sectors_buffer = Arc::new(Mutex::new(Vec::new()));
    let sector_update_handler = farm.on_sector_update(Arc::new({
        let plotted_sectors_buffer = Arc::clone(&plotted_sectors_buffer);

        move |(_sector_index, sector_update)| {
            if let SectorUpdate::Plotting(SectorPlottingDetails::Finished {
                plotted_sector,
                old_plotted_sector,
                ..
            }) = sector_update
            {
                plotted_sectors_buffer
                    .lock()
                    .push((plotted_sector.clone(), old_plotted_sector.clone()));
            }
        }
    }));

    // Add plotted sectors of the farm to global plotted pieces
    let plotted_sectors = farm.plotted_sectors();
    let mut plotted_sectors = plotted_sectors
        .get()
        .await
        .map_err(|error| anyhow!("Failed to get plotted sectors for farm {farm_id}: {error}"))?;

    {
        plotted_pieces
            .write()
            .await
            .add_farm(farm_index, farm.piece_reader());

        while let Some(plotted_sector_result) = plotted_sectors.next().await {
            let plotted_sector = plotted_sector_result.map_err(|error| {
                anyhow!("Failed to get plotted sector for farm {farm_id}: {error}")
            })?;

            let mut plotted_pieces_guard = plotted_pieces.write().await;
            plotted_pieces_guard.add_sector(farm_index, &plotted_sector);

            // Drop the guard immediately to make sure other tasks are able to access the plotted pieces
            drop(plotted_pieces_guard);

            task::yield_now().await;
        }
    }

    // Add sectors that were plotted while above iteration was happening to plotted sectors
    // too
    drop(sector_update_handler);
    let plotted_sectors_buffer = mem::take(&mut *plotted_sectors_buffer.lock());
    let add_buffered_sectors_fut = task::spawn_blocking(move || {
        let mut plotted_pieces = plotted_pieces.write_blocking();

        for (plotted_sector, old_plotted_sector) in plotted_sectors_buffer {
            if let Some(old_plotted_sector) = old_plotted_sector {
                plotted_pieces.delete_sector(farm_index, &old_plotted_sector);
            }
            // Call delete first to avoid adding duplicates
            plotted_pieces.delete_sector(farm_index, &plotted_sector);
            plotted_pieces.add_sector(farm_index, &plotted_sector);
        }
    });

    add_buffered_sectors_fut
        .await
        .map_err(|error| anyhow!("Failed to add buffered sectors for farm {farm_id}: {error}"))?;

    Ok(farm)
}
