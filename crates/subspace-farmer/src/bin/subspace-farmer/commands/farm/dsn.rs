use crate::DsnArgs;
use event_listener_primitives::HandlerId;
use futures::channel::mpsc;
use futures::StreamExt;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::{fs, io, thread};
use subspace_farmer::utils::farmer_piece_cache::FarmerPieceCache;
use subspace_farmer::utils::farmer_provider_record_processor::FarmerProviderRecordProcessor;
use subspace_farmer::utils::farmer_provider_storage::FarmerProviderStorage;
use subspace_farmer::utils::parity_db_store::ParityDbStore;
use subspace_farmer::utils::readers_and_pieces::ReadersAndPieces;
use subspace_farmer::{NodeClient, NodeRpcClient};
use subspace_networking::libp2p::identity::Keypair;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::{
    create, peer_id, BootstrappedNetworkingParameters, Config, Node, NodeRunner,
    ParityDbProviderStorage, PieceByHashRequestHandler, PieceByHashResponse,
    RootBlockBySegmentIndexesRequestHandler, RootBlockResponse,
};
use tokio::runtime::Handle;
use tracing::{debug, error, info, warn, Instrument, Span};

const MAX_CONCURRENT_ANNOUNCEMENTS_QUEUE: usize = 2000;
const MAX_CONCURRENT_ANNOUNCEMENTS_PROCESSING: NonZeroUsize =
    NonZeroUsize::new(20).expect("Not zero; qed");

pub(super) async fn configure_dsn(
    base_path: PathBuf,
    keypair: Keypair,
    DsnArgs {
        listen_on,
        bootstrap_nodes,
        piece_cache_size,
        disable_private_ips,
        reserved_peers,
    }: DsnArgs,
    readers_and_pieces: &Arc<Mutex<Option<ReadersAndPieces>>>,
    node_client: NodeRpcClient,
) -> Result<
    (
        Node,
        NodeRunner<FarmerProviderStorage<ParityDbProviderStorage>>,
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
    let provider_cache_db_path = base_path.join("provider_cache_db");
    let provider_cache_size =
        piece_cache_size.saturating_mul(NonZeroUsize::new(10).expect("10 > 0")); // TODO: add proper value

    info!(
        ?piece_cache_db_path,
        ?piece_cache_size,
        ?provider_cache_db_path,
        ?provider_cache_size,
        "Record cache DB configured."
    );

    let piece_protocol_handle = Handle::current();
    let root_blocks_protocol_handle = Handle::current();
    let default_config = Config::default();
    let peer_id = peer_id(&keypair);

    let db_provider_storage =
        ParityDbProviderStorage::new(&provider_cache_db_path, provider_cache_size, peer_id)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    let farmer_provider_storage =
        FarmerProviderStorage::new(peer_id, readers_and_pieces.clone(), db_provider_storage);

    let piece_store =
        ParityDbStore::new(&piece_cache_db_path).map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let piece_cache = FarmerPieceCache::new(piece_store.clone(), piece_cache_size, peer_id);

    let config = Config {
        reserved_peers,
        keypair,
        listen_on,
        allow_non_global_addresses_in_dht: !disable_private_ips,
        networking_parameters_registry: BootstrappedNetworkingParameters::new(bootstrap_nodes)
            .boxed(),
        request_response_protocols: vec![
            PieceByHashRequestHandler::create(move |req| {
                let result = {
                    debug!(piece_index_hash = ?req.piece_index_hash, "Piece request received. Trying cache...");
                    let multihash = req.piece_index_hash.to_multihash();

                    let piece_from_cache = piece_store.get(&multihash.into());

                    if piece_from_cache.is_some() {
                        piece_from_cache
                    } else {
                        debug!(piece_index_hash = ?req.piece_index_hash, "No piece in the cache. Trying archival storage...");

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
                                        ?req.piece_index_hash,
                                        "Readers and pieces are not initialized yet"
                                    );
                                    return None;
                                }
                            };

                            readers_and_pieces.read_piece(&req.piece_index_hash)?
                        };

                        let handle = piece_protocol_handle.clone();
                        tokio::task::block_in_place(move || handle.block_on(read_piece_fut))
                    }
                };

                Some(PieceByHashResponse { piece: result })
            }),
            RootBlockBySegmentIndexesRequestHandler::create(move |req| {
                debug!(segment_indexes_count = ?req.segment_indexes.len(), "Root blocks request received.");

                let handle = root_blocks_protocol_handle.clone();
                let node_client = node_client.clone();
                let internal_result = tokio::task::block_in_place(move || {
                    handle.block_on(node_client.root_blocks(req.segment_indexes.clone()))
                });

                match internal_result {
                    Ok(root_blocks) => Some(RootBlockResponse { root_blocks }),
                    Err(error) => {
                        error!(%error, "Failed to get root blocks from cache");

                        None
                    }
                }
            }),
        ],
        provider_storage: farmer_provider_storage,
        ..default_config
    };

    create(config)
        .await
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
        mpsc::channel(MAX_CONCURRENT_ANNOUNCEMENTS_QUEUE);

    let handler_id = node.on_announcement(Arc::new({
        let provider_records_sender = Mutex::new(provider_records_sender);

        move |record| {
            if let Err(error) = provider_records_sender.lock().try_send(record.clone()) {
                if error.is_disconnected() {
                    // Receiver exited, nothing left to be done
                    return;
                }
                let record = error.into_inner();
                warn!(
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
    );

    // We are working with database internally, better to run in a separate thread
    thread::Builder::new()
        .name("ann-processor".to_string())
        .spawn(move || {
            let processor_fut = async {
                while let Some(provider_record) = provider_records_receiver.next().await {
                    if weak_readers_and_pieces.upgrade().is_none() {
                        // `ReadersAndPieces` was dropped, nothing left to be done
                        return;
                    }
                    provider_record_processor
                        .process_provider_record(provider_record)
                        .await;
                }
            };

            handle.block_on(processor_fut.instrument(span));
        })?;

    Ok(handler_id)
}
