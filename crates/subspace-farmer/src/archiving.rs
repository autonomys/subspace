use crate::object_mappings::ObjectMappings;
use crate::rpc_client::RpcClient;
use crate::utils::{AbortingJoinHandle, JoinOnDrop};
use futures::StreamExt;
use std::{io, thread};
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::objects::{GlobalObject, PieceObject, PieceObjectMapping};
use subspace_core_primitives::Blake2b256Hash;
use subspace_networking::PiecesToPlot;
use subspace_rpc_primitives::FarmerProtocolInfo;
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::{debug, error, info};

#[derive(Debug, Error)]
pub enum ArchivingError {
    #[error("Plot is empty on restart, can't continue")]
    ContinueError,
    #[error("Failed to get block {0} from the chain, probably need to erase existing plot")]
    GetBlockError(u32),
    #[error("jsonrpsee error: {0}")]
    RpcError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Error joining task: {0}")]
    JoinTask(tokio::task::JoinError),
    #[error("Archiver instantiation error: {0}")]
    Archiver(subspace_archiving::archiver::ArchiverInstantiationError),
    #[error("Failed to subscribe to new segments: {0}")]
    Subscribe(#[from] subspace_networking::SubscribeError),
    /// Failed to spawn archiving thread
    #[error("Failed to spawn archiving thread: {0}")]
    ArchivingThread(io::Error),
}

/// Abstraction around archiving blocks and updating global object map
pub struct Archiving {
    archiving_task: Option<AbortingJoinHandle<()>>,
    /// Background archiving thread, must be kept around to stop gracefully on drop, including
    /// waiting for async archiving task above
    _archiving_thread: JoinOnDrop,
}

impl Archiving {
    // TODO: Blocks that are coming form substrate node are fully trusted right now, which we probably
    //  don't want eventually
    /// `on_pieces_to_plot` must return `true` unless archiving is no longer necessary
    pub async fn start<Client, OPTP>(
        farmer_protocol_info: FarmerProtocolInfo,
        object_mappings: Vec<ObjectMappings>,
        client: Client,
        mut on_pieces_to_plot: OPTP,
    ) -> Result<Archiving, ArchivingError>
    where
        Client: RpcClient + Clone + Send + Sync + 'static,
        OPTP: FnMut(PiecesToPlot) -> bool + Send + 'static,
    {
        let FarmerProtocolInfo {
            record_size,
            recorded_history_segment_size,
            ..
        } = farmer_protocol_info;

        let merkle_num_leaves = u64::from(recorded_history_segment_size / record_size * 2);

        let (archived_segments_sync_sender, archived_segments_sync_receiver) =
            std::sync::mpsc::channel::<(ArchivedSegment, oneshot::Sender<()>)>();

        // Erasure coding in archiver and piece encoding are CPU-intensive operations.
        let archiving_thread = thread::Builder::new()
            .name("archiving".to_string())
            .spawn({
                move || {
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

                        let piece_index_offset = merkle_num_leaves * segment_index;

                        let pieces_to_plot = PiecesToPlot {
                            piece_indexes: (piece_index_offset..).take(pieces.count()).collect(),
                            pieces,
                        };
                        if !on_pieces_to_plot(pieces_to_plot) {
                            // No need to continue
                            break;
                        }

                        let object_mapping =
                            create_global_object_mapping(piece_index_offset, object_mapping);

                        for object_mappings in &object_mappings {
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
            .map_err(ArchivingError::ArchivingThread)?;

        info!("Subscribing to archived segments");
        let mut archived_segments = client
            .subscribe_archived_segments()
            .await
            .map_err(ArchivingError::RpcError)?;

        let archiving_handle = tokio::spawn(async move {
            // Listen for new blocks produced on the network
            while let Some(archived_segment) = archived_segments.next().await {
                let segment_index = archived_segment.root_block.segment_index();
                let (acknowledge_sender, acknowledge_receiver) = oneshot::channel();
                // Acknowledge immediately to allow node to continue sync quickly,
                // but this will miss some segments in case farmer crashed in the
                // meantime. Ideally we'd acknowledge after, but it makes node wait
                // for it and the whole process very sequential.
                if let Err(error) = client.acknowledge_archived_segment(segment_index).await {
                    error!(%error, "Failed to send archived segment acknowledgement");
                }
                if let Err(error) =
                    archived_segments_sync_sender.send((archived_segment, acknowledge_sender))
                {
                    error!(%error, "Failed to send archived segment for plotting");
                }
                let _ = acknowledge_receiver.await;
            }

            debug!("Subscription has forcefully closed from node side!");
        });

        Ok(Self {
            archiving_task: Some(AbortingJoinHandle::new(archiving_handle)),
            _archiving_thread: archiving_thread,
        })
    }

    /// Waits for the background archiving to finish
    pub async fn wait(mut self) -> Result<(), ArchivingError> {
        self.archiving_task
            .take()
            .unwrap()
            .await
            .map_err(ArchivingError::JoinTask)
    }
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
