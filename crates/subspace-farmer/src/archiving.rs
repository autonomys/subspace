use crate::rpc::{self, RpcClient};
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use subspace_archiving::archiver::{ArchivedSegment, Archiver};
use subspace_core_primitives::{BlockNumber, RootBlock};
use subspace_rpc_primitives::{EncodedBlockWithObjectMapping, FarmerMetadata};
use tokio::task::JoinError;
use tokio::{sync::oneshot, task::JoinHandle};

const BEST_BLOCK_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

// Abstraction around background block querying and archiving
pub struct Archiving {
    stop_sender: Option<oneshot::Sender<()>>,
    new_blocks_handle: Option<JoinHandle<()>>,
    archiving_handle: Option<JoinHandle<()>>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Plot is empty on restart, can't continue")]
    ContinueError,
    #[error("Failed to get block {0} from the chain, probably need to erase existing plot")]
    GetBlockError(u32),
    #[error("jsonrpsee error: {0}")]
    RpcError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Archiver instantiation error: {0}")]
    Archiver(subspace_archiving::archiver::ArchiverInstantiationError),
}

impl Archiving {
    // Start block archiving in the background
    pub async fn start(
        client: impl RpcClient + Clone + Send + Sync + 'static,
        maybe_last_root_block: Option<RootBlock>,
        best_block_number_check_interval: Duration,
        plot_is_empty: bool,
        archived_blocks_sender: std::sync::mpsc::SyncSender<(BlockNumber, Vec<ArchivedSegment>)>,
    ) -> Result<Self, Error> {
        let FarmerMetadata {
            record_size,
            recorded_history_segment_size,
            ..
        } = client.farmer_metadata().await.map_err(Error::RpcError)?;

        let archiver = if let Some(last_root_block) = maybe_last_root_block {
            // Continuing from existing initial state
            if plot_is_empty {
                return Err(Error::ContinueError);
            }

            let last_archived_block_number = last_root_block.last_archived_block().number;
            info!("Last archived block {}", last_archived_block_number);

            let maybe_last_archived_block = client
                .block_by_number(last_archived_block_number)
                .await
                .map_err(Error::RpcError)?;

            match maybe_last_archived_block {
                Some(EncodedBlockWithObjectMapping {
                    block,
                    object_mapping,
                }) => Archiver::with_initial_state(
                    record_size as usize,
                    recorded_history_segment_size as usize,
                    last_root_block,
                    &block,
                    object_mapping,
                )
                .map_err(Error::Archiver)?,
                None => {
                    return Err(Error::GetBlockError(last_archived_block_number));
                }
            }
        } else {
            // Starting from genesis
            if !plot_is_empty {
                // Restart before first block was archived, erase the plot
                // TODO: Erase plot
            }

            Archiver::new(record_size as usize, recorded_history_segment_size as usize)
                .map_err(Error::Archiver)?
        };

        let (new_block_to_archive_sender, new_block_to_archive_receiver) =
            std::sync::mpsc::sync_channel::<Arc<AtomicU32>>(0);
        let (stop_sender, stop_receiver) = oneshot::channel::<()>();

        let new_blocks_handle = spawn_listening_to_blocks(
            client.clone(),
            maybe_last_root_block,
            new_block_to_archive_sender,
            stop_receiver,
            best_block_number_check_interval,
        )
        .await
        .map_err(Error::RpcError)?;

        let archiving_handle = spawn_archiving(
            client,
            archiver,
            new_block_to_archive_receiver,
            archived_blocks_sender,
        );
        Ok(Self {
            stop_sender: Some(stop_sender),
            new_blocks_handle: Some(new_blocks_handle),
            archiving_handle: Some(archiving_handle),
        })
    }

    /// Waits for the background block archiving to finish
    pub async fn wait(mut self) -> Result<(), JoinError> {
        self.new_blocks_handle.take().unwrap().await?;
        self.archiving_handle.take().unwrap().await
    }
}

impl Drop for Archiving {
    fn drop(&mut self) {
        let _ = self.stop_sender.take().unwrap().send(());
    }
}

async fn spawn_listening_to_blocks(
    client: impl RpcClient + Clone + Send + Sync + 'static,
    maybe_last_root_block: Option<RootBlock>,
    new_block_to_archive_sender: std::sync::mpsc::SyncSender<Arc<AtomicU32>>,
    mut stop_receiver: oneshot::Receiver<()>,
    best_block_number_check_interval: Duration,
) -> Result<JoinHandle<()>, rpc::Error> {
    let confirmation_depth_k = client.farmer_metadata().await?.confirmation_depth_k;

    info!("Subscribing to new heads");
    let mut new_head = client.subscribe_new_head().await?;

    let block_to_archive = Arc::new(AtomicU32::default());

    if maybe_last_root_block.is_none() {
        // If not continuation, archive genesis block
        new_block_to_archive_sender
            .send(Arc::clone(&block_to_archive))
            .expect("Failed to send genesis block archiving message");
    }

    let (mut best_block_number_sender, mut best_block_number_receiver) = mpsc::channel(1);

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(best_block_number_check_interval).await;

            // In case connection dies, we need to disconnect from the node
            let best_block_number_result =
                tokio::time::timeout(BEST_BLOCK_REQUEST_TIMEOUT, client.best_block_number()).await;

            let is_error = !matches!(best_block_number_result, Ok(Ok(_)));
            // Result doesn't matter here
            let _ = best_block_number_sender
                .send(best_block_number_result)
                .await;

            if is_error {
                break;
            }
        }
    });

    let mut last_best_block_number_error = false;

    // Listen for new blocks produced on the network
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_receiver => {
                    info!("Plotting stopped!");
                    break;
                }
                result = new_head.recv() => {
                    match result {
                        Some(head) => {
                            let block_number = u32::from_str_radix(&head.number[2..], 16).unwrap();
                            debug!("Last block number: {:#?}", block_number);

                            if let Some(block_number) = block_number.checked_sub(confirmation_depth_k) {
                                // We send block that should be archived over channel that doesn't have
                                // a buffer, atomic integer is used to make sure archiving process
                                // always read up to date value
                                block_to_archive.store(block_number, Ordering::Relaxed);
                                let _ = new_block_to_archive_sender.try_send(Arc::clone(&block_to_archive));
                            }
                        },
                        None => {
                            debug!("Subscription has forcefully closed from node side!");
                            break;
                        }
                    }
                }
                maybe_result = best_block_number_receiver.next() => {
                    match maybe_result {
                        Some(Ok(Ok(best_block_number))) => {
                            debug!("Best block number: {:#?}", best_block_number);
                            last_best_block_number_error = false;

                            if let Some(block_number) = best_block_number.checked_sub(confirmation_depth_k) {
                                // We send block that should be archived over channel that doesn't have
                                // a buffer, atomic integer is used to make sure archiving process
                                // always read up to date value
                                block_to_archive.fetch_max(block_number, Ordering::Relaxed);
                                let _ = new_block_to_archive_sender.try_send(Arc::clone(&block_to_archive));
                            }
                        }
                        Some(Ok(Err(error))) => {
                            if last_best_block_number_error {
                                error!("Request to get new best block failed second time: {error}");
                                break;
                            } else {
                                warn!("Request to get new best block failed: {error}");
                                last_best_block_number_error = true;
                            }
                        }
                        Some(Err(_error)) => {
                            if last_best_block_number_error {
                                error!("Request to get new best block timed out second time");
                                break;
                            } else {
                                warn!("Request to get new best block timed out");
                                last_best_block_number_error = true;
                            }
                        }
                        None => {
                            debug!("Best block number channel closed!");
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(handle)
}

fn spawn_archiving(
    client: impl RpcClient + Clone + Send + Sync + 'static,
    mut archiver: Archiver,
    new_block_to_archive_receiver: std::sync::mpsc::Receiver<Arc<AtomicU32>>,
    archived_blocks_sender: std::sync::mpsc::SyncSender<(BlockNumber, Vec<ArchivedSegment>)>,
) -> JoinHandle<()> {
    // Process blocks since last fully archived block (or genesis) up to the current head minus K
    let mut blocks_to_archive_from = archiver
        .last_archived_block_number()
        .map(|n| n + 1)
        .unwrap_or_default();

    // Erasure coding in archiver and piece encoding are CPU-intensive operations.
    tokio::task::spawn_blocking({
        #[allow(clippy::mut_range_bound)]
        move || {
            let runtime_handle = tokio::runtime::Handle::current();

            'outer: for blocks_to_archive_to in new_block_to_archive_receiver.into_iter() {
                let blocks_to_archive_to = blocks_to_archive_to.load(Ordering::Relaxed);
                if blocks_to_archive_to >= blocks_to_archive_from {
                    debug!(
                        "Archiving blocks {}..={}",
                        blocks_to_archive_from, blocks_to_archive_to,
                    );
                }

                for block_to_archive in blocks_to_archive_from..=blocks_to_archive_to {
                    let EncodedBlockWithObjectMapping {
                        block,
                        object_mapping,
                    } = match runtime_handle.block_on(client.block_by_number(block_to_archive)) {
                        Ok(Some(block)) => block,
                        Ok(None) => {
                            error!(
                                "Failed to get block #{} from RPC: Block not found",
                                block_to_archive,
                            );

                            blocks_to_archive_from = block_to_archive;
                            continue 'outer;
                        }
                        Err(error) => {
                            error!(
                                "Failed to get block #{} from RPC: {}",
                                block_to_archive, error,
                            );

                            blocks_to_archive_from = block_to_archive;
                            continue 'outer;
                        }
                    };

                    if archived_blocks_sender
                        .send((block_to_archive, archiver.add_block(block, object_mapping)))
                        .is_err()
                    {
                        break 'outer;
                    }
                }

                blocks_to_archive_from = blocks_to_archive_to + 1;
            }
        }
    })
}
