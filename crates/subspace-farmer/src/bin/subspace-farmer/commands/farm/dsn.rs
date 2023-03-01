use crate::DsnArgs;
use anyhow::Context;
use event_listener_primitives::HandlerId;
use futures::channel::mpsc;
use futures::StreamExt;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::{fs, io, thread};
use subspace_farmer::utils::farmer_piece_cache::FarmerPieceCache;
use subspace_farmer::utils::farmer_provider_record_processor::FarmerProviderRecordProcessor;
use subspace_farmer::utils::farmer_provider_storage::FarmerProviderStorage;
use subspace_farmer::utils::parity_db_store::ParityDbStore;
use subspace_farmer::utils::readers_and_pieces::ReadersAndPieces;
use subspace_farmer::{NodeClient, NodeRpcClient};
use subspace_farmer_components::piece_caching::PieceMemoryCache;
use subspace_networking::libp2p::identity::Keypair;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::{
    create, peer_id, BootstrappedNetworkingParameters, Config, Node, NodeRunner,
    ParityDbProviderStorage, PieceByHashRequest, PieceByHashRequestHandler, PieceByHashResponse,
    RootBlockBySegmentIndexesRequestHandler, RootBlockRequest, RootBlockResponse,
};
use tokio::runtime::Handle;
use tracing::{debug, error, info, Instrument, Span};

const MAX_CONCURRENT_ANNOUNCEMENTS_QUEUE: NonZeroUsize =
    NonZeroUsize::new(2000).expect("Not zero; qed");
const MAX_CONCURRENT_ANNOUNCEMENTS_PROCESSING: NonZeroUsize =
    NonZeroUsize::new(20).expect("Not zero; qed");
const MAX_CONCURRENT_RE_ANNOUNCEMENTS_PROCESSING: NonZeroUsize =
    NonZeroUsize::new(100).expect("Not zero; qed");
const ROOT_BLOCK_NUMBER_LIMIT: u64 = 1000;

#[allow(clippy::type_complexity)]
pub(super) fn configure_dsn(
    base_path: PathBuf,
    keypair: Keypair,
    DsnArgs {
        listen_on,
        bootstrap_nodes,
        piece_cache_size,
        provided_keys_limit,
        disable_private_ips,
        reserved_peers,
    }: DsnArgs,
    readers_and_pieces: &Arc<Mutex<Option<ReadersAndPieces>>>,
    node_client: NodeRpcClient,
    piece_memory_cache: PieceMemoryCache,
) -> Result<
    (
        Node,
        NodeRunner<FarmerProviderStorage<ParityDbProviderStorage, FarmerPieceCache>>,
        FarmerPieceCache,
    ),
    anyhow::Error,
> {
    let weak_readers_and_pieces = Arc::downgrade(readers_and_pieces);

    let piece_cache_db_path = base_path.join("piece_cache_db");
    // TODO: Remove this migration code in the future
    {
        let records_cache_db_path = base_path.join("records_cache_db");
        if records_cache_db_path.exists() {
            fs::rename(&records_cache_db_path, &piece_cache_db_path)?;
        }
    }
    let provider_db_path = base_path.join("providers_db");
    // TODO: Remove this migration code in the future
    {
        let provider_cache_db_path = base_path.join("provider_cache_db");
        if provider_cache_db_path.exists() {
            fs::rename(&provider_cache_db_path, &provider_db_path)?;
        }
    }

    let default_config = Config::default();
    let peer_id = peer_id(&keypair);

    info!(
        db_path = ?provider_db_path,
        keys_limit = ?provided_keys_limit,
        "Initializing provider storage..."
    );
    let persistent_provider_storage =
        ParityDbProviderStorage::new(&provider_db_path, provided_keys_limit, peer_id)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    info!(
        current_size = ?persistent_provider_storage.size(),
        "Provider storage initialized successfully"
    );

    info!(
        db_path = ?piece_cache_db_path,
        size = ?piece_cache_size,
        "Initializing piece cache..."
    );
    let piece_store =
        ParityDbStore::new(&piece_cache_db_path).map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let piece_cache = FarmerPieceCache::new(piece_store.clone(), piece_cache_size, peer_id);
    info!(
        current_size = ?piece_cache.size(),
        "Piece cache initialized successfully"
    );

    let farmer_provider_storage = FarmerProviderStorage::new(
        peer_id,
        readers_and_pieces.clone(),
        persistent_provider_storage,
        piece_cache.clone(),
    );

    let last_archived_segment_index = Arc::new(AtomicU64::default());
    tokio::spawn({
        let last_archived_segment_index = last_archived_segment_index.clone();
        let node_client = node_client.clone();

        async move {
            let archived_segments_notifications = node_client
                .subscribe_archived_segments()
                .await
                .map_err(|err| anyhow::anyhow!(err.to_string()))
                .context("Failed to subscribe to archived segments");

            match archived_segments_notifications {
                Ok(mut archived_segments_notifications) => {
                    while let Some(segment) = archived_segments_notifications.next().await {
                        last_archived_segment_index
                            .store(segment.root_block.segment_index(), Ordering::Relaxed);
                    }
                }
                Err(err) => {
                    error!(?err, "Failed to get archived segments notifications.")
                }
            }
        }
    });

    let config = Config {
        reserved_peers,
        keypair,
        listen_on,
        allow_non_global_addresses_in_dht: !disable_private_ips,
        networking_parameters_registry: BootstrappedNetworkingParameters::new(bootstrap_nodes)
            .boxed(),
        request_response_protocols: vec![
            PieceByHashRequestHandler::create(move |&PieceByHashRequest { piece_index_hash }| {
                debug!(?piece_index_hash, "Piece request received. Trying cache...");
                let multihash = piece_index_hash.to_multihash();

                let weak_readers_and_pieces = weak_readers_and_pieces.clone();
                let piece_store = piece_store.clone();
                let piece_memory_cache = piece_memory_cache.clone();

                async move {
                    if let Some(piece) = piece_memory_cache.get_piece(&piece_index_hash) {
                        return Some(PieceByHashResponse { piece: Some(piece) });
                    }

                    let piece_from_store = piece_store.get(&multihash.into());

                    if let Some(piece) = piece_from_store {
                        Some(PieceByHashResponse { piece: Some(piece) })
                    } else {
                        debug!(
                            ?piece_index_hash,
                            "No piece in the cache. Trying archival storage..."
                        );

                        let read_piece_fut = {
                            let readers_and_pieces = match weak_readers_and_pieces.upgrade() {
                                Some(readers_and_pieces) => readers_and_pieces,
                                None => {
                                    debug!("A readers and pieces are already dropped");
                                    return None;
                                }
                            };
                            let readers_and_pieces = readers_and_pieces.lock();
                            let readers_and_pieces = match readers_and_pieces.as_ref() {
                                Some(readers_and_pieces) => readers_and_pieces,
                                None => {
                                    debug!(
                                        ?piece_index_hash,
                                        "Readers and pieces are not initialized yet"
                                    );
                                    return None;
                                }
                            };

                            readers_and_pieces
                                .read_piece(&piece_index_hash)?
                                .instrument(Span::current())
                        };

                        let piece = read_piece_fut.await;

                        Some(PieceByHashResponse { piece })
                    }
                }
                .instrument(Span::current())
            }),
            RootBlockBySegmentIndexesRequestHandler::create(move |req| {
                debug!(?req, "Root blocks request received.");

                let node_client = node_client.clone();
                let last_archived_segment_index = last_archived_segment_index.clone();
                let req = req.clone();

                async move {
                    let segment_indexes = match req {
                        RootBlockRequest::SegmentIndexes { segment_indexes } => segment_indexes.clone(),
                        RootBlockRequest::LastRootBlocks { root_block_number } => {
                            if root_block_number > ROOT_BLOCK_NUMBER_LIMIT {
                                debug!(%root_block_number, "Root block number exceeded the limit.");
                                return None;
                            }

                            let last_segment_index =
                                last_archived_segment_index.load(Ordering::Relaxed);

                            // several last segment indexes available on the node
                            (0..=last_segment_index)
                                .rev()
                                .take(root_block_number as usize)
                                .collect::<Vec<_>>()
                        }
                    };

                    debug!(segment_indexes_count = ?segment_indexes.len(), "Root blocks request received.");

                    let internal_result = node_client.root_blocks(segment_indexes).await;

                    match internal_result {
                        Ok(root_blocks) => {
                            let mut result = Vec::new();
                            for root_block in root_blocks {
                                match root_block {
                                    None => {
                                        error!("Received empty optional root block!");

                                        return None;
                                    }
                                    Some(root_block) => {
                                        result.push(root_block);
                                    }
                                }
                            }

                            Some(RootBlockResponse {
                                root_blocks: result,
                            })
                        }
                        Err(error) => {
                            error!(%error, "Failed to get root blocks from cache");

                            None
                        }
                    }
                }
                .instrument(Span::current())
            }),
        ],
        provider_storage: farmer_provider_storage,
        ..default_config
    };

    create(config)
        .map(|(node, node_runner)| (node, node_runner, piece_cache))
        .map_err(Into::into)
}

/// Start processing announcements received by the network node, returns handle that will stop
/// processing on drop.
pub(crate) fn start_announcements_processor(
    node: Node,
    piece_cache: Arc<tokio::sync::Mutex<FarmerPieceCache>>,
    weak_readers_and_pieces: Weak<Mutex<Option<ReadersAndPieces>>>,
) -> io::Result<HandlerId> {
    let (provider_records_sender, mut provider_records_receiver) =
        mpsc::channel(MAX_CONCURRENT_ANNOUNCEMENTS_QUEUE.get());

    let handler_id = node.on_announcement(Arc::new({
        let provider_records_sender = Mutex::new(provider_records_sender);

        move |record, guard| {
            if let Err(error) = provider_records_sender
                .lock()
                .try_send((record.clone(), Arc::clone(guard)))
            {
                if error.is_disconnected() {
                    // Receiver exited, nothing left to be done
                    return;
                }
                let (record, _guard) = error.into_inner();
                // TODO: This should be made a warning, but due to
                //  https://github.com/libp2p/rust-libp2p/discussions/3411 it'll take us some time
                //  to resolve
                debug!(
                    ?record.key,
                    ?record.provider,
                    "Failed to add provider record to the channel."
                );
            };
        }
    }));

    let handle = Handle::current();
    let span = Span::current();
    let mut provider_record_processor = FarmerProviderRecordProcessor::new(
        node,
        piece_cache,
        weak_readers_and_pieces.clone(),
        MAX_CONCURRENT_ANNOUNCEMENTS_PROCESSING,
        MAX_CONCURRENT_RE_ANNOUNCEMENTS_PROCESSING,
    );

    // We are working with database internally, better to run in a separate thread
    thread::Builder::new()
        .name("ann-processor".to_string())
        .spawn(move || {
            let processor_fut = async {
                while let Some((provider_record, guard)) = provider_records_receiver.next().await {
                    if weak_readers_and_pieces.upgrade().is_none() {
                        // `ReadersAndPieces` was dropped, nothing left to be done
                        return;
                    }
                    provider_record_processor
                        .process_provider_record(provider_record, guard)
                        .await;
                }
            };

            handle.block_on(processor_fut.instrument(span));
        })?;

    Ok(handler_id)
}
