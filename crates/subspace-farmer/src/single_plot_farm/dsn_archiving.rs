use crate::object_mappings::ObjectMappings;
use crate::single_disk_farm::SingleDiskSemaphore;
use crate::single_plot_farm::{SinglePlotFarmId, SinglePlotPlotter};
use crate::utils::JoinOnDrop;
use futures::StreamExt;
use parity_scale_codec::Decode;
use std::{io, thread};
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::objects::{GlobalObject, PieceObject, PieceObjectMapping};
use subspace_core_primitives::Blake2b256Hash;
use subspace_networking::{Node, PiecesToPlot, SubscribeError};
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::{error, info, warn, Span};

#[derive(Debug, Error)]
pub(super) enum StartDsnArchivingError {
    /// Failed to subscribe for archived segments
    #[error("Failed to subscribe for archived segments from DSN: {0}")]
    DsnSubscribe(#[from] SubscribeError),
    /// Failed to spawn archiving thread
    #[error("Failed to spawn archiving thread: {0}")]
    ArchivingThread(io::Error),
}

// TODO: No verification whatsoever for now, must be added soon
/// `on_pieces_to_plot` must return `true` unless archiving is no longer necessary
pub(super) async fn start_archiving(
    single_plot_farm_id: SinglePlotFarmId,
    record_size: u32,
    recorded_history_segment_size: u32,
    object_mappings: ObjectMappings,
    node: Node,
    plotter: SinglePlotPlotter,
    single_disk_semaphore: SingleDiskSemaphore,
) -> Result<(), StartDsnArchivingError> {
    let pieces_in_segment = u64::from(recorded_history_segment_size / record_size * 2);

    let (archived_segments_sync_sender, archived_segments_sync_receiver) =
        std::sync::mpsc::sync_channel::<(ArchivedSegment, oneshot::Sender<()>)>(5);

    let span = Span::current();
    // Piece encoding are CPU-intensive operations.
    let _join_handle = thread::Builder::new()
        .name(format!("dsn-archiving-{single_plot_farm_id}"))
        .spawn({
            move || {
                let _guard = span.enter();

                let mut last_archived_segment_index = None;
                while let Ok((archived_segment, acknowledgement_sender)) =
                    archived_segments_sync_receiver.recv()
                {
                    let ArchivedSegment {
                        root_block,
                        pieces,
                        object_mapping,
                    } = archived_segment;
                    let segment_index = root_block.segment_index();
                    if last_archived_segment_index == Some(segment_index) {
                        continue;
                    }
                    last_archived_segment_index.replace(segment_index);

                    let piece_index_offset = pieces_in_segment * segment_index;

                    let pieces_to_plot = PiecesToPlot {
                        piece_indexes: (piece_index_offset..).take(pieces.count()).collect(),
                        pieces,
                    };

                    {
                        let _guard = single_disk_semaphore.acquire();
                        if let Err(error) = plotter.plot_pieces(pieces_to_plot) {
                            error!(%error, "Failed to plot pieces from DSN");
                            break;
                        }

                        let object_mapping =
                            create_global_object_mapping(piece_index_offset, object_mapping);

                        if let Err(error) = object_mappings.store(&object_mapping) {
                            error!(%error, "Failed to store object mappings for pieces");
                        }
                    }

                    info!(segment_index, "Plotted segment");

                    if let Err(()) = acknowledgement_sender.send(()) {
                        error!("Failed to send archived segment acknowledgement");
                    }
                }
            }
        })
        .map(JoinOnDrop::new)
        .map_err(StartDsnArchivingError::ArchivingThread)?;

    info!("Subscribing to pubsub archiving...");
    let mut archived_segments = node
        .subscribe(subspace_networking::PUB_SUB_ARCHIVING_TOPIC.clone())
        .await?
        .filter_map(|bytes| async move {
            match ArchivedSegment::decode(&mut bytes.as_ref()) {
                Ok(archived_segment) => Some(archived_segment),
                Err(error) => {
                    tracing::error!(%error, "Failed to decode archived segment");
                    None
                }
            }
        })
        .boxed();

    // Listen for new blocks produced on the network
    while let Some(archived_segment) = archived_segments.next().await {
        let (acknowledge_sender, acknowledge_receiver) = oneshot::channel();
        if let Err(error) =
            archived_segments_sync_sender.try_send((archived_segment, acknowledge_sender))
        {
            warn!(%error, "Failed to send archived segment for plotting");
        }
        let _ = acknowledge_receiver.await;
    }

    Ok(())
}

fn create_global_object_mapping(
    piece_index_offset: u64,
    object_mapping: Vec<PieceObjectMapping>,
) -> Vec<(Blake2b256Hash, GlobalObject)> {
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
