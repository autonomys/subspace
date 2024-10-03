pub(crate) mod import_blocks;
pub(crate) mod piece_validator;
pub(crate) mod segment_header_downloader;
pub(crate) mod snap_sync;
pub(crate) mod snap_sync_engine;

use crate::sync_from_dsn::import_blocks::import_blocks_from_dsn;
use crate::sync_from_dsn::segment_header_downloader::SegmentHeaderDownloader;
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::{select, FutureExt, StreamExt};
use sc_client_api::{AuxStore, BlockBackend, BlockchainEvents};
use sc_consensus::import_queue::ImportQueueService;
use sc_consensus_subspace::archiver::SegmentHeadersStore;
use sc_network::service::traits::NetworkService;
use sc_network::NetworkBlock;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus_subspace::SubspaceApi;
use sp_runtime::traits::{Block as BlockT, CheckedSub, NumberFor};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_core_primitives::segments::SegmentIndex;
use subspace_core_primitives::PublicKey;
use subspace_erasure_coding::ErasureCoding;
use subspace_networking::utils::piece_provider::{PieceProvider, PieceValidator};
use subspace_networking::Node;
use tracing::{debug, info, warn};

/// How much time to wait for new block to be imported before timing out and starting sync from DSN
const NO_IMPORTED_BLOCKS_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Frequency with which to check whether node is online or not
const CHECK_ONLINE_STATUS_INTERVAL: Duration = Duration::from_secs(1);
/// Frequency with which to check whether node is almost synced to the tip of the observed chain
const CHECK_ALMOST_SYNCED_INTERVAL: Duration = Duration::from_secs(1);
/// Period of time during which node should be offline for DSN sync to kick-in
const MIN_OFFLINE_PERIOD: Duration = Duration::from_secs(60);

/// Trait representing a way to get pieces for DSN sync purposes
#[async_trait]
pub trait DsnSyncPieceGetter: fmt::Debug {
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>>;
}

#[async_trait]
impl<T> DsnSyncPieceGetter for Arc<T>
where
    T: DsnSyncPieceGetter + Send + Sync + ?Sized,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        self.as_ref().get_piece(piece_index).await
    }
}

#[async_trait]
impl<PV> DsnSyncPieceGetter for PieceProvider<PV>
where
    PV: PieceValidator,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        Ok(self.get_piece_from_cache(piece_index).await)
    }
}

#[derive(Debug)]
enum NotificationReason {
    NoImportedBlocks,
    // TODO: Restore or remove connected peer later
    #[allow(dead_code)]
    WentOnlineSubspace,
    WentOnlineSubstrate,
}

/// Create node observer that will track node state and send notifications to worker to start sync
/// from DSN.
#[allow(clippy::too_many_arguments)]
pub(super) fn create_observer_and_worker<Block, AS, NB, Client, PG>(
    segment_headers_store: SegmentHeadersStore<AS>,
    network_service: Arc<dyn NetworkService>,
    node: Node,
    client: Arc<Client>,
    mut import_queue_service: Box<dyn ImportQueueService<Block>>,
    network_block: NB,
    sync_target_block_number: Arc<AtomicU32>,
    pause_sync: Arc<AtomicBool>,
    piece_getter: PG,
    erasure_coding: ErasureCoding,
) -> (
    impl Future<Output = ()> + Send + 'static,
    impl Future<Output = Result<(), sc_service::Error>> + Send + 'static,
)
where
    Block: BlockT,
    AS: AuxStore + Send + Sync + 'static,
    NB: NetworkBlock<Block::Hash, NumberFor<Block>> + Send + 'static,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + BlockchainEvents<Block>
        + ProvideRuntimeApi<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, PublicKey>,
    PG: DsnSyncPieceGetter + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel(0);
    let observer_fut = {
        let node = node.clone();
        let client = Arc::clone(&client);

        async move { create_observer(network_service.as_ref(), &node, client.as_ref(), tx).await }
    };
    let worker_fut = async move {
        create_worker(
            segment_headers_store,
            &node,
            client.as_ref(),
            import_queue_service.as_mut(),
            network_block,
            sync_target_block_number,
            pause_sync,
            rx,
            &piece_getter,
            &erasure_coding,
        )
        .await
    };
    (observer_fut, worker_fut)
}

async fn create_observer<Block, Client>(
    network_service: &dyn NetworkService,
    _node: &Node,
    client: &Client,
    notifications_sender: mpsc::Sender<NotificationReason>,
) where
    Block: BlockT,
    Client: BlockchainEvents<Block> + Send + Sync + 'static,
{
    // // Separate reactive observer for Subspace networking that is not a future
    // let _handler_id = node.on_num_established_peer_connections_change({
    //     // Assuming node is offline by default
    //     let last_online = Atomic::new(None::<Instant>);
    //     let notifications_sender = notifications_sender.clone();
    //
    //     Arc::new(move |&new_connections| {
    //         let is_online = new_connections > 0;
    //         let was_online = last_online
    //             .load(Ordering::AcqRel)
    //             .map(|last_online| last_online.elapsed() < MIN_OFFLINE_PERIOD)
    //             .unwrap_or_default();
    //
    //         if is_online && !was_online {
    //             // Doesn't matter if sending failed here
    //             let _ = notifications_sender
    //                 .clone()
    //                 .try_send(NotificationReason::WentOnlineSubspace);
    //         }
    //
    //         if is_online {
    //             last_online.store(Some(Instant::now()), Ordering::Release);
    //         }
    //     })
    // });
    select! {
        _ = create_imported_blocks_observer(client, notifications_sender.clone()).fuse() => {
            // Runs indefinitely
        }
        _ = create_substrate_network_observer(network_service, notifications_sender).fuse() => {
            // Runs indefinitely
        }
    }
}

async fn create_imported_blocks_observer<Block, Client>(
    client: &Client,
    mut notifications_sender: mpsc::Sender<NotificationReason>,
) where
    Block: BlockT,
    Client: BlockchainEvents<Block> + Send + Sync + 'static,
{
    let mut import_notification_stream = client.every_import_notification_stream();
    loop {
        match tokio::time::timeout(
            NO_IMPORTED_BLOCKS_TIMEOUT,
            import_notification_stream.next(),
        )
        .await
        {
            Ok(Some(_notification)) => {
                // Do nothing
            }
            Ok(None) => {
                // No more notifications
                return;
            }
            Err(_timeout) => {
                if let Err(error) =
                    notifications_sender.try_send(NotificationReason::NoImportedBlocks)
                {
                    if error.is_disconnected() {
                        // Receiving side was closed
                        return;
                    }
                }
            }
        }
    }
}

async fn create_substrate_network_observer(
    network_service: &dyn NetworkService,
    mut notifications_sender: mpsc::Sender<NotificationReason>,
) {
    // Assuming node is offline by default
    let mut last_online = None::<Instant>;

    loop {
        tokio::time::sleep(CHECK_ONLINE_STATUS_INTERVAL).await;

        let is_online = network_service.sync_num_connected() > 0;

        let was_online = last_online
            .map(|last_online| last_online.elapsed() < MIN_OFFLINE_PERIOD)
            .unwrap_or_default();
        if is_online && !was_online {
            if let Err(error) =
                notifications_sender.try_send(NotificationReason::WentOnlineSubstrate)
            {
                if error.is_disconnected() {
                    // Receiving side was closed
                    return;
                }
            }
        }

        if is_online {
            last_online.replace(Instant::now());
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn create_worker<Block, AS, IQS, NB, Client, PG>(
    segment_headers_store: SegmentHeadersStore<AS>,
    node: &Node,
    client: &Client,
    import_queue_service: &mut IQS,
    network_block: NB,
    sync_target_block_number: Arc<AtomicU32>,
    pause_sync: Arc<AtomicBool>,
    mut notifications: mpsc::Receiver<NotificationReason>,
    piece_getter: &PG,
    erasure_coding: &ErasureCoding,
) -> Result<(), sc_service::Error>
where
    Block: BlockT,
    AS: AuxStore + Send + Sync + 'static,
    IQS: ImportQueueService<Block> + ?Sized,
    NB: NetworkBlock<Block::Hash, NumberFor<Block>>,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + ProvideRuntimeApi<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, PublicKey>,
    PG: DsnSyncPieceGetter,
{
    let info = client.info();
    let chain_constants = client
        .runtime_api()
        .chain_constants(info.best_hash)
        .map_err(|error| error.to_string())?;

    // Corresponds to contents of block one, everyone has it, so we consider it being processed
    // right away
    let mut last_processed_segment_index = SegmentIndex::ZERO;
    // TODO: We'll be able to just take finalized block once we are able to decouple pruning from
    //  finality: https://github.com/paritytech/polkadot-sdk/issues/1570
    let mut last_processed_block_number = info.best_number;
    let segment_header_downloader = SegmentHeaderDownloader::new(node);

    while let Some(reason) = notifications.next().await {
        pause_sync.store(true, Ordering::Release);

        info!(?reason, "Received notification to sync from DSN");
        // TODO: Maybe handle failed block imports, additional helpful logging
        let import_froms_from_dsn_fut = import_blocks_from_dsn(
            &segment_headers_store,
            &segment_header_downloader,
            client,
            piece_getter,
            import_queue_service,
            &mut last_processed_segment_index,
            &mut last_processed_block_number,
            erasure_coding,
        );
        let wait_almost_synced_fut = async {
            loop {
                tokio::time::sleep(CHECK_ALMOST_SYNCED_INTERVAL).await;

                let info = client.info();
                let target_block_number =
                    NumberFor::<Block>::from(sync_target_block_number.load(Ordering::Relaxed));

                // If less blocks than confirmation depth to the tip of the chain, no need to worry about DSN sync
                // anymore, it will not be helpful anyway
                if target_block_number
                    .checked_sub(&info.best_number)
                    .map(|diff| diff < chain_constants.confirmation_depth_k().into())
                    .unwrap_or_default()
                {
                    break;
                }
            }
        };

        select! {
            result = import_froms_from_dsn_fut.fuse() => {
                if let Err(error) = result {
                    warn!(%error, "Error when syncing blocks from DSN");
                }
            }
            _ = wait_almost_synced_fut.fuse() => {
                // Almost synced, DSN sync can't possibly help here
            }
        }

        debug!("Finished DSN sync");

        // This will notify Substrate's sync mechanism and allow regular Substrate sync to continue
        // gracefully
        {
            let info = client.info();
            network_block.new_best_block_imported(info.best_hash, info.best_number);
        }
        pause_sync.store(false, Ordering::Release);

        while notifications.try_next().is_ok() {
            // Just drain extra messages if there are any
        }
    }

    Ok(())
}
