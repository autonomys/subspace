use crate::DsnArgs;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use subspace_farmer::piece_cache::PieceCache;
use subspace_farmer::utils::archival_storage_info::ArchivalStorageInfo;
use subspace_farmer::utils::archival_storage_pieces::ArchivalStoragePieces;
use subspace_farmer::utils::readers_and_pieces::ReadersAndPieces;
use subspace_farmer::{NodeClient, NodeRpcClient};
use subspace_networking::libp2p::identity::Keypair;
use subspace_networking::libp2p::kad::RecordKey;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::utils::strip_peer_id;
use subspace_networking::{
    compose, Config, NetworkingParametersManager, Node, NodeRunner, PeerInfo, PeerInfoProvider,
    PieceByIndexRequest, PieceByIndexRequestHandler, PieceByIndexResponse,
    SegmentHeaderBySegmentIndexesRequestHandler, SegmentHeaderRequest, SegmentHeaderResponse,
};
use subspace_rpc_primitives::MAX_SEGMENT_HEADERS_PER_REQUEST;
use tracing::{debug, error, info, Instrument};

/// How many segment headers can be requested at a time.
///
/// Must be the same as RPC limit since all requests go to the node anyway.
const SEGMENT_HEADER_NUMBER_LIMIT: u64 = MAX_SEGMENT_HEADERS_PER_REQUEST as u64;

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub(super) fn configure_dsn(
    protocol_prefix: String,
    base_path: PathBuf,
    keypair: Keypair,
    DsnArgs {
        listen_on,
        bootstrap_nodes,
        enable_private_ips,
        reserved_peers,
        in_connections,
        out_connections,
        pending_in_connections,
        pending_out_connections,
        target_connections,
        external_addresses,
    }: DsnArgs,
    weak_readers_and_pieces: Weak<Mutex<Option<ReadersAndPieces>>>,
    node_client: NodeRpcClient,
    archival_storage_pieces: ArchivalStoragePieces,
    archival_storage_info: ArchivalStorageInfo,
    piece_cache: PieceCache,
) -> Result<(Node, NodeRunner<PieceCache>), anyhow::Error> {
    let networking_parameters_registry = NetworkingParametersManager::new(
        &base_path.join("known_addresses.bin"),
        strip_peer_id(bootstrap_nodes.clone())
            .into_iter()
            .map(|(peer_id, _)| peer_id)
            .collect::<HashSet<_>>(),
    )
    .map(Box::new)?;

    let default_config = Config::new(
        protocol_prefix,
        keypair,
        piece_cache.clone(),
        Some(PeerInfoProvider::new_farmer(Box::new(
            archival_storage_pieces,
        ))),
    );
    let config = Config {
        reserved_peers,
        listen_on,
        allow_non_global_addresses_in_dht: enable_private_ips,
        networking_parameters_registry: Some(networking_parameters_registry),
        request_response_protocols: vec![
            PieceByIndexRequestHandler::create(move |_, &PieceByIndexRequest { piece_index }| {
                debug!(?piece_index, "Piece request received. Trying cache...");

                let weak_readers_and_pieces = weak_readers_and_pieces.clone();
                let piece_cache = piece_cache.clone();

                async move {
                    let key = RecordKey::from(piece_index.to_multihash());
                    let piece_from_store = piece_cache.get_piece(key).await;

                    if let Some(piece) = piece_from_store {
                        Some(PieceByIndexResponse { piece: Some(piece) })
                    } else {
                        debug!(
                            ?piece_index,
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
                                        ?piece_index,
                                        "Readers and pieces are not initialized yet"
                                    );
                                    return None;
                                }
                            };

                            readers_and_pieces
                                .read_piece(&piece_index)?
                                .in_current_span()
                        };

                        let piece = read_piece_fut.await;

                        Some(PieceByIndexResponse { piece })
                    }
                }
                .in_current_span()
            }),
            SegmentHeaderBySegmentIndexesRequestHandler::create(move |_, req| {
                debug!(?req, "Segment headers request received.");

                let node_client = node_client.clone();
                let req = req.clone();

                async move {
                    let internal_result = match req {
                        SegmentHeaderRequest::SegmentIndexes { segment_indexes } => {
                            debug!(
                                segment_indexes_count = ?segment_indexes.len(),
                                "Segment headers request received."
                            );

                            node_client.segment_headers(segment_indexes).await
                        }
                        SegmentHeaderRequest::LastSegmentHeaders {
                            mut segment_header_number,
                        } => {
                            if segment_header_number > SEGMENT_HEADER_NUMBER_LIMIT {
                                debug!(
                                    %segment_header_number,
                                    "Segment header number exceeded the limit."
                                );

                                segment_header_number = SEGMENT_HEADER_NUMBER_LIMIT;
                            }
                            node_client
                                .last_segment_headers(segment_header_number)
                                .await
                        }
                    };

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
        external_addresses,
        ..default_config
    };

    compose(config)
        .map(|(node, node_runner)| {
            node.on_new_listener(Arc::new({
                let node = node.clone();

                move |address| {
                    info!(
                        "DSN listening on {}",
                        address.clone().with(Protocol::P2p(node.id()))
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
            (node, node_runner)
        })
        .map_err(Into::into)
}
