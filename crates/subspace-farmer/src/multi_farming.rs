use std::{path::Path, sync::Arc, time::Duration};

use anyhow::anyhow;
use futures::stream::{FuturesUnordered, StreamExt};
use log::{debug, error, info};
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{
    objects::{GlobalObject, PieceObject, PieceObjectMapping},
    PublicKey, Sha256Hash,
};
use subspace_rpc_primitives::FarmerMetadata;
use subspace_solving::SubspaceCodec;
use tokio::{sync::broadcast, task::JoinHandle};

use crate::{
    archiving::{ArchivedBlock, Archiving},
    Commitments, FarmerData, Farming, Identity, ObjectMappings, Plot, Plotting, RpcClient, WsRpc,
};

/// Abstraction around having multiple plots, farmings and plottings
pub struct MultiFarming {
    pub plots: Arc<Vec<Plot>>,
    farmings: Vec<Farming>,
    plottings: Vec<Plotting>,
    archiving: Archiving,
    update_object_mapping_handle: Option<JoinHandle<()>>,
}

impl MultiFarming {
    /// Starts multiple farmers with any plot sizes which user gives
    pub async fn new(
        base_directory: impl AsRef<Path>,
        client: WsRpc,
        object_mappings: ObjectMappings,
        plot_sizes: Vec<u64>,
        reward_address: PublicKey,
        best_block_number_check_interval: Duration,
    ) -> anyhow::Result<Self> {
        let mut plots = Vec::with_capacity(plot_sizes.len());
        let mut farmings = Vec::with_capacity(plot_sizes.len());
        let mut plottings = Vec::with_capacity(plot_sizes.len());

        let archiving = {
            let plot = tokio::task::spawn_blocking({
                let base_directory = base_directory.as_ref().join("plot0");

                move || -> anyhow::Result<Plot> {
                    let identity = Identity::open_or_create(&base_directory)?;
                    let public_key = identity.public_key().to_bytes().into();
                    std::fs::create_dir_all(&base_directory)?;
                    Ok(Plot::open_or_create(&base_directory, public_key, u64::MAX)?)
                }
            })
            .await
            .unwrap()?;
            Archiving::start(
                client.clone(),
                plot.get_last_root_block()?,
                best_block_number_check_interval,
                plot.is_empty(),
            )
            .await?
        };

        for (plot_index, max_plot_pieces) in plot_sizes.into_iter().enumerate() {
            let base_directory = base_directory.as_ref().join(format!("plot{plot_index}"));
            std::fs::create_dir_all(&base_directory)?;
            let (plot, plotting, farming) = farm_single_plot(
                base_directory,
                reward_address,
                client.clone(),
                max_plot_pieces,
                archiving.subscribe(),
            )
            .await?;
            plots.push(plot);
            farmings.push(farming);
            plottings.push(plotting);
        }

        let update_object_mapping_handle = tokio::spawn({
            let mut archived_blocks_receiver = archiving.subscribe();
            let FarmerMetadata {
                record_size,
                recorded_history_segment_size,
                ..
            } = client
                .farmer_metadata()
                .await
                .map_err(|err| anyhow!("Getting metadata failed: {err}"))?;

            // TODO: This assumes fixed size segments, which might not be the case
            let merkle_num_leaves = u64::from(recorded_history_segment_size / record_size * 2);
            async move {
                loop {
                    let segments = match archived_blocks_receiver.recv().await {
                        Ok(ArchivedBlock { segments, .. }) => segments,
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            debug!("Skipped {n} blocks");
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    };

                    for segment in segments {
                        let ArchivedSegment {
                            object_mapping,
                            root_block,
                            ..
                        } = segment;
                        let piece_index_offset = merkle_num_leaves * root_block.segment_index();
                        let object_mapping =
                            create_global_object_mapping(piece_index_offset, object_mapping);
                        if let Err(error) = tokio::task::spawn_blocking({
                            let object_mappings = object_mappings.clone();
                            move || object_mappings.store(&object_mapping)
                        })
                        .await
                        {
                            error!("Failed to store object mappings for pieces: {}", error);
                        }
                    }
                }
            }
        });

        Ok(Self {
            plots: Arc::new(plots),
            farmings,
            plottings,
            archiving,
            update_object_mapping_handle: Some(update_object_mapping_handle),
        })
    }

    /// Waits for farming and plotting completion (or errors)
    pub async fn wait(mut self) -> anyhow::Result<()> {
        let mut farming_plotting = self
            .farmings
            .into_iter()
            .zip(self.plottings)
            .into_iter()
            .map(|(farming, plotting)| async move {
                tokio::select! {
                    res = plotting.wait() => if let Err(error) = res {
                        return Err(anyhow!(error))
                    },
                    res = farming.wait() => if let Err(error) = res {
                        return Err(anyhow!(error))
                    },
                }
                Ok(())
            })
            .collect::<FuturesUnordered<_>>();

        tokio::select! {
             res = farming_plotting.next() => {
                if let Some(res) = res {
                    res?;
                }
             }
             res = self.archiving.wait() => {
                res?;
             }
        }

        self.update_object_mapping_handle.take().unwrap().await?;

        Ok(())
    }
}

/// Starts farming for a single plot in specified base directory.
pub(crate) async fn farm_single_plot(
    base_directory: impl AsRef<Path>,
    reward_address: PublicKey,
    client: WsRpc,
    max_plot_pieces: u64,
    archived_blocks_receiver: broadcast::Receiver<ArchivedBlock>,
) -> anyhow::Result<(Plot, Plotting, Farming)> {
    let identity = Identity::open_or_create(&base_directory)?;
    let public_key = identity.public_key().to_bytes().into();

    // TODO: This doesn't account for the fact that node can
    // have a completely different history to what farmer expects
    info!("Opening plot");
    let plot = tokio::task::spawn_blocking({
        let base_directory = base_directory.as_ref().to_owned();

        move || Plot::open_or_create(&base_directory, public_key, max_plot_pieces)
    })
    .await
    .unwrap()?;

    info!("Opening commitments");
    let commitments_fut = tokio::task::spawn_blocking({
        let path = base_directory.as_ref().join("commitments");

        move || Commitments::new(path)
    });
    let commitments = commitments_fut.await.unwrap()?;

    let subspace_codec = SubspaceCodec::new(identity.public_key());

    // start the farming task
    let farming_instance = Farming::start(
        plot.clone(),
        commitments.clone(),
        client.clone(),
        identity,
        reward_address,
    );

    let farmer_data = FarmerData::new(
        plot.clone(),
        commitments,
        client
            .farmer_metadata()
            .await
            .map_err(|error| anyhow!(error))?,
    );

    // start the background plotting
    let plotting_instance = Plotting::start(farmer_data, subspace_codec, archived_blocks_receiver);

    Ok((plot, plotting_instance, farming_instance))
}

fn create_global_object_mapping(
    piece_index_offset: u64,
    object_mapping: Vec<PieceObjectMapping>,
) -> Vec<(Sha256Hash, GlobalObject)> {
    object_mapping
        .iter()
        .enumerate()
        .flat_map(move |(position, object_mapping)| {
            object_mapping.objects.iter().map(move |piece_object| {
                let PieceObject::V0 { hash, offset } = piece_object;
                (
                    *hash,
                    GlobalObject::V0 {
                        piece_index: piece_index_offset + position as u64,
                        offset: *offset,
                    },
                )
            })
        })
        .collect()
}
