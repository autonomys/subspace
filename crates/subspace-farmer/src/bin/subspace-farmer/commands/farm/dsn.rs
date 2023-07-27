use crate::DsnArgs;
use anyhow::Context;
use futures::StreamExt;
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use subspace_core_primitives::SegmentIndex;
use subspace_farmer::utils::archival_storage_info::ArchivalStorageInfo;
use subspace_farmer::utils::archival_storage_pieces::ArchivalStoragePieces;
use subspace_farmer::utils::farmer_piece_cache::FarmerPieceCache;
use subspace_farmer::utils::farmer_provider_storage::FarmerProviderStorage;
use subspace_farmer::utils::parity_db_store::ParityDbStore;
use subspace_farmer::utils::readers_and_pieces::ReadersAndPieces;
use subspace_farmer::{NodeClient, NodeRpcClient};
use subspace_networking::libp2p::identity::Keypair;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::{
    create, peer_id, Config, NetworkingParametersManager, Node, NodeRunner,
    ParityDbProviderStorage, PeerInfo, PeerInfoProvider, PieceByHashRequest,
    PieceByHashRequestHandler, PieceByHashResponse, SegmentHeaderBySegmentIndexesRequestHandler,
    SegmentHeaderRequest, SegmentHeaderResponse,
};
use tracing::{debug, error, info, Instrument};

const ROOT_BLOCK_NUMBER_LIMIT: u64 = 1000;

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub(super) fn configure_dsn(
    protocol_prefix: String,
    base_path: PathBuf,
    keypair: Keypair,
    DsnArgs {
        listen_on,
        bootstrap_nodes,
        piece_cache_size,
        provided_keys_limit,
        disable_private_ips,
        reserved_peers,
        in_connections,
        out_connections,
        pending_in_connections,
        pending_out_connections,
        target_connections,
    }: DsnArgs,
    readers_and_pieces: &Arc<Mutex<Option<ReadersAndPieces>>>,
    node_client: NodeRpcClient,
    archival_storage_pieces: ArchivalStoragePieces,
    archival_storage_info: ArchivalStorageInfo,
) -> Result<
    (
        Node,
        NodeRunner<FarmerProviderStorage<FarmerPieceCache>>,
        FarmerPieceCache,
    ),
    anyhow::Error,
> {
    let peer_id = peer_id(&keypair);

    let networking_parameters_registry = {
        let known_addresses_db_path = base_path.join("known_addresses_db");

        NetworkingParametersManager::new(&known_addresses_db_path).map(|manager| manager.boxed())?
    };

    let weak_readers_and_pieces = Arc::downgrade(readers_and_pieces);

    let piece_cache_db_path = base_path.join("piece_cache_db");
    let provider_db_path = base_path.join("providers_db");

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

    let farmer_provider_storage = FarmerProviderStorage::new(peer_id, piece_cache.clone());

    // TODO: Consider introducing and using global in-memory segment header cache (this comment is
    //  in multiple files)
    let last_archived_segment_index = Arc::new(AtomicU64::default());
    tokio::spawn({
        let last_archived_segment_index = last_archived_segment_index.clone();
        let node_client = node_client.clone();

        async move {
            let segment_headers_notifications = node_client
                .subscribe_archived_segment_headers()
                .await
                .map_err(|err| anyhow::anyhow!(err.to_string()))
                .context("Failed to subscribe to archived segments");

            match segment_headers_notifications {
                Ok(mut segment_headers_notifications) => {
                    while let Some(segment_header) = segment_headers_notifications.next().await {
                        let segment_index = segment_header.segment_index();

                        last_archived_segment_index
                            .store(u64::from(segment_index), Ordering::Relaxed);

                        if let Err(err) = node_client
                            .acknowledge_archived_segment_header(segment_index)
                            .await
                        {
                            error!(?err, %segment_index, "Failed to acknowledge archived segments notifications")
                        }
                    }
                }
                Err(err) => {
                    error!(?err, "Failed to get archived segments notifications.")
                }
            }
        }
    });

    let default_config = Config::new(
        protocol_prefix,
        keypair,
        farmer_provider_storage.clone(),
        Some(PeerInfoProvider::new_farmer(Box::new(
            archival_storage_pieces,
        ))),
    );
    let config = Config {
        reserved_peers,
        listen_on,
        allow_non_global_addresses_in_dht: !disable_private_ips,
        networking_parameters_registry: Some(networking_parameters_registry),
        request_response_protocols: vec![
            PieceByHashRequestHandler::create(
                move |_, &PieceByHashRequest { piece_index_hash }| {
                    debug!(?piece_index_hash, "Piece request received. Trying cache...");
                    let multihash = piece_index_hash.to_multihash();

                    let weak_readers_and_pieces = weak_readers_and_pieces.clone();
                    let piece_store = piece_store.clone();

                    async move {
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
                                    .in_current_span()
                            };

                            let piece = read_piece_fut.await;

                            Some(PieceByHashResponse { piece })
                        }
                    }
                    .in_current_span()
                },
            ),
            SegmentHeaderBySegmentIndexesRequestHandler::create(move |_, req| {
                debug!(?req, "Segment headers request received.");

                let node_client = node_client.clone();
                let last_archived_segment_index = last_archived_segment_index.clone();
                let req = req.clone();

                async move {
                    let segment_indexes = match req {
                        SegmentHeaderRequest::SegmentIndexes { segment_indexes } => {
                            segment_indexes.clone()
                        }
                        SegmentHeaderRequest::LastSegmentHeaders {
                            segment_header_number,
                        } => {
                            if segment_header_number > ROOT_BLOCK_NUMBER_LIMIT {
                                debug!(
                                    %segment_header_number,
                                    "Segment header number exceeded the limit."
                                );
                                return None;
                            }

                            let last_segment_index = SegmentIndex::from(
                                last_archived_segment_index.load(Ordering::Relaxed),
                            );

                            // several last segment indexes available on the node
                            (SegmentIndex::ZERO..=last_segment_index)
                                .rev()
                                .take(segment_header_number as usize)
                                .collect::<Vec<_>>()
                        }
                    };

                    debug!(
                        segment_indexes_count = ?segment_indexes.len(),
                        "Segment headers request received."
                    );

                    let internal_result = node_client.segment_headers(segment_indexes).await;

                    match internal_result {
                        Ok(segment_headers) => segment_headers
                            .into_iter()
                            .map(|maybe_segment_header| {
                                if maybe_segment_header.is_none() {
                                    error!("Received empty optional segment header!");
                                }
                                maybe_segment_header
                            })
                            .collect::<Option<Vec<_>>>()
                            .map(|segment_headers| SegmentHeaderResponse { segment_headers }),
                        Err(error) => {
                            error!(%error, "Failed to get segment headers from cache");

                            None
                        }
                    }
                }
                .in_current_span()
            }),
        ],
        max_established_outgoing_connections: out_connections,
        max_pending_outgoing_connections: pending_out_connections,
        max_established_incoming_connections: in_connections,
        max_pending_incoming_connections: pending_in_connections,
        general_target_connections: target_connections,
        // maintain permanent connections between farmers
        special_connected_peers_handler: Some(Arc::new(PeerInfo::is_farmer)),
        // other (non-farmer) connections
        general_connected_peers_handler: Some(Arc::new(|peer_info| {
            !PeerInfo::is_farmer(peer_info)
        })),
        bootstrap_addresses: bootstrap_nodes,
        ..default_config
    };

    create(config)
        .map(|(node, node_runner)| {
            node.on_new_listener(Arc::new({
                let node = node.clone();

                move |address| {
                    info!(
                        "DSN listening on {}",
                        address.clone().with(Protocol::P2p(node.id().into()))
                    );
                }
            }))
            .detach();

            node.on_peer_info(Arc::new({
                let archival_storage_info = archival_storage_info.clone();

                move |new_peer_info| {
                    let peer_id = new_peer_info.peer_id;
                    let peer_info = &new_peer_info.peer_info;

                    if let PeerInfo::Farmer { cuckoo_filter } = peer_info {
                        archival_storage_info.update_cuckoo_filter(peer_id, cuckoo_filter.clone());

                        debug!(%peer_id, ?peer_info, "Peer info cached",);
                    }
                }
            }))
            .detach();

            node.on_disconnected_peer(Arc::new({
                let archival_storage_info = archival_storage_info.clone();

                move |peer_id| {
                    if archival_storage_info.remove_peer_filter(peer_id) {
                        debug!(%peer_id, "Peer filter removed.",);
                    }
                }
            }))
            .detach();

            // Consider returning HandlerId instead of each `detach()` calls for other usages.
            (node, node_runner, piece_cache)
        })
        .map_err(Into::into)
}
