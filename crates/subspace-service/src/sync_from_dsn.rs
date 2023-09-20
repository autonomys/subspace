mod import_blocks;
mod piece_validator;
mod segment_header_downloader;

use crate::sync_from_dsn::import_blocks::import_blocks_from_dsn;
use crate::sync_from_dsn::piece_validator::SegmentCommitmentPieceValidator;
use crate::sync_from_dsn::segment_header_downloader::SegmentHeaderDownloader;
use atomic::Atomic;
use futures::channel::mpsc;
use futures::{FutureExt, StreamExt};
use sc_client_api::{AuxStore, BlockBackend, BlockchainEvents};
use sc_consensus::import_queue::ImportQueueService;
use sc_consensus_subspace::archiver::SegmentHeadersStore;
use sc_network::config::SyncMode;
use sc_network::{NetworkPeers, NetworkService};
use sp_api::{BlockT, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi};
use sp_runtime::Saturating;
use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::SegmentIndex;
use subspace_networking::utils::piece_provider::PieceProvider;
use subspace_networking::Node;
use tracing::{info, warn};

/// How much time to wait for new block to be imported before timing out and starting sync from DSN.
const NO_IMPORTED_BLOCKS_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Frequency with which to check whether node is online or not
const CHECK_ONLINE_STATUS_INTERVAL: Duration = Duration::from_secs(1);
/// Period of time during which node should be offline for DSN sync to kick-in
const MIN_OFFLINE_PERIOD: Duration = Duration::from_secs(60);

#[derive(Debug)]
enum NotificationReason {
    NoImportedBlocks,
    WentOnlineSubspace,
    WentOnlineSubstrate,
}

/// Create node observer that will track node state and send notifications to worker to start sync
/// from DSN.
#[allow(clippy::too_many_arguments)] // we don't follow this convention
pub(super) fn create_observer_and_worker<Block, AS, Client>(
    segment_headers_store: SegmentHeadersStore<AS>,
    network_service: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
    node: Node,
    client: Arc<Client>,
    mut import_queue_service: Box<dyn ImportQueueService<Block>>,
    sync_mode: Arc<Atomic<SyncMode>>,
    kzg: Kzg,
    dsn_sync_parallelism_level: usize,
) -> (
    impl Future<Output = ()> + Send + 'static,
    impl Future<Output = Result<(), sc_service::Error>> + Send + 'static,
)
where
    Block: BlockT,
    AS: AuxStore + Send + Sync + 'static,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + BlockchainEvents<Block>
        + ProvideRuntimeApi<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
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
            sync_mode,
            rx,
            &kzg,
            dsn_sync_parallelism_level,
        )
        .await
    };
    (observer_fut, worker_fut)
}

async fn create_observer<Block, Client>(
    network_service: &NetworkService<Block, <Block as BlockT>::Hash>,
    node: &Node,
    client: &Client,
    notifications_sender: mpsc::Sender<NotificationReason>,
) where
    Block: BlockT,
    Client: BlockchainEvents<Block> + Send + Sync + 'static,
{
    // Separate reactive observer for Subspace networking that is not a future
    let _handler_id = node.on_num_established_peer_connections_change({
        // Assuming node is offline by default
        let last_online = Atomic::new(None::<Instant>);
        let notifications_sender = notifications_sender.clone();

        Arc::new(move |&new_connections| {
            let is_online = new_connections > 0;
            let was_online = last_online
                .load(Ordering::AcqRel)
                .map(|last_online| last_online.elapsed() < MIN_OFFLINE_PERIOD)
                .unwrap_or_default();

            if is_online && !was_online {
                // Doesn't matter if sending failed here
                let _ = notifications_sender
                    .clone()
                    .try_send(NotificationReason::WentOnlineSubspace);
            }

            if is_online {
                last_online.store(Some(Instant::now()), Ordering::Release);
            }
        })
    });
    futures::select! {
        _ = create_imported_blocks_observer(client, notifications_sender.clone()).fuse() => {
            // Runs indefinitely
        }
        _ = create_substrate_network_observer(network_service, notifications_sender).fuse() => {
            // Runs indefinitely
        }
        // TODO: More sources
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

async fn create_substrate_network_observer<Block>(
    network_service: &NetworkService<Block, <Block as BlockT>::Hash>,
    mut notifications_sender: mpsc::Sender<NotificationReason>,
) where
    Block: BlockT,
{
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

#[allow(clippy::too_many_arguments)] // we don't follow this convention
async fn create_worker<Block, AS, IQS, Client>(
    segment_headers_store: SegmentHeadersStore<AS>,
    node: &Node,
    client: &Client,
    import_queue_service: &mut IQS,
    sync_mode: Arc<Atomic<SyncMode>>,
    mut notifications: mpsc::Receiver<NotificationReason>,
    kzg: &Kzg,
    dsn_sync_parallelism_level: usize,
) -> Result<(), sc_service::Error>
where
    Block: BlockT,
    AS: AuxStore + Send + Sync + 'static,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + ProvideRuntimeApi<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    IQS: ImportQueueService<Block> + ?Sized,
{
    // Corresponds to contents of block one, everyone has it, so we consider it being processed
    // right away
    let mut last_processed_segment_index = SegmentIndex::ZERO;
    // TODO: We'll be able to just take finalized block once we are able to decouple pruning from
    //  finality: https://github.com/paritytech/polkadot-sdk/issues/1570
    let mut last_processed_block_number = {
        let info = client.info();
        info.best_number.saturating_sub(
            client
                .runtime_api()
                .chain_constants(info.best_hash)
                .map_err(|error| error.to_string())?
                .confirmation_depth_k()
                .into(),
        )
    };
    let segment_header_downloader = SegmentHeaderDownloader::new(node);
    let piece_provider = PieceProvider::new(
        node.clone(),
        Some(SegmentCommitmentPieceValidator::<AS>::new(
            node,
            kzg,
            &segment_headers_store,
        )),
    );

    // Node starts as offline, we'll wait for it to go online shrtly after
    let mut initial_sync_mode = Some(sync_mode.swap(SyncMode::Paused, Ordering::AcqRel));
    while let Some(reason) = notifications.next().await {
        let prev_sync_mode = sync_mode.swap(SyncMode::Paused, Ordering::AcqRel);

        while notifications.try_next().is_ok() {
            // Just drain extra messages if there are any
        }

        info!(?reason, "Received notification to sync from DSN");
        // TODO: Maybe handle failed block imports, additional helpful logging
        if let Err(error) = import_blocks_from_dsn(
            &segment_headers_store,
            &segment_header_downloader,
            client,
            &piece_provider,
            import_queue_service,
            &mut last_processed_segment_index,
            &mut last_processed_block_number,
            dsn_sync_parallelism_level,
        )
        .await
        {
            warn!(%error, "Error when syncing blocks from DSN");
        }

        sync_mode.store(
            initial_sync_mode.take().unwrap_or(prev_sync_mode),
            Ordering::Release,
        );
    }

    Ok(())
}
