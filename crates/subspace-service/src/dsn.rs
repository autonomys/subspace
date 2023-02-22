pub mod import_blocks;
mod node_provider_storage;

use crate::dsn::node_provider_storage::NodeProviderStorage;
use crate::piece_cache::PieceCache;
use crate::RootBlockCache;
use either::Either;
use futures::stream::FuturesUnordered;
use futures::{Stream, StreamExt};
use sc_client_api::AuxStore;
use sc_consensus_subspace::ArchivedSegmentNotification;
use sc_consensus_subspace_rpc::RootBlockProvider;
use sp_core::traits::SpawnNamed;
use sp_runtime::traits::Block as BlockT;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{PieceIndex, RootBlock, PIECES_IN_SEGMENT};
use subspace_networking::libp2p::{identity, Multiaddr};
use subspace_networking::utils::pieces::announce_single_piece_index_with_backoff;
use subspace_networking::{
    peer_id, BootstrappedNetworkingParameters, CreationError, MemoryProviderStorage, Node,
    NodeRunner, ParityDbProviderStorage, PieceByHashRequestHandler, PieceByHashResponse,
    RootBlockBySegmentIndexesRequestHandler, RootBlockResponse,
};
use tokio::sync::Semaphore;
use tracing::{error, info, trace, warn, Instrument};

/// Provider records cache size
const MAX_PROVIDER_RECORDS_LIMIT: usize = 100000; // ~ 10 MB

/// DSN configuration parameters.
#[derive(Clone, Debug)]
pub struct DsnConfig {
    /// Where local DSN node will listen for incoming connections.
    pub listen_on: Vec<Multiaddr>,

    /// Bootstrap nodes for DSN.
    pub bootstrap_nodes: Vec<Multiaddr>,

    /// Reserved nodes for DSN.
    pub reserved_peers: Vec<Multiaddr>,

    /// Identity keypair of a node used for authenticated connections.
    pub keypair: identity::Keypair,

    /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses in Kademlia DHT.
    pub allow_non_global_addresses_in_dht: bool,

    /// System base path.
    pub base_path: Option<PathBuf>,
}

type DsnProviderStorage<AS> =
    NodeProviderStorage<PieceCache<AS>, Either<ParityDbProviderStorage, MemoryProviderStorage>>;

pub(crate) async fn create_dsn_instance<Block, AS>(
    dsn_config: DsnConfig,
    piece_cache: PieceCache<AS>,
    root_block_cache: RootBlockCache<AS>,
) -> Result<(Node, NodeRunner<DsnProviderStorage<AS>>), CreationError>
where
    Block: BlockT,
    AS: AuxStore + Sync + Send + 'static,
{
    trace!("Subspace networking starting.");

    let peer_id = peer_id(&dsn_config.keypair);

    let external_provider_storage = if let Some(path) = dsn_config.base_path {
        let db_path = path.join("storage_providers_db");

        let cache_size: NonZeroUsize = NonZeroUsize::new(MAX_PROVIDER_RECORDS_LIMIT)
            .expect("Manual value should be greater than zero.");

        Either::Left(ParityDbProviderStorage::new(&db_path, cache_size, peer_id)?)
    } else {
        Either::Right(MemoryProviderStorage::new(peer_id))
    };

    let provider_storage =
        NodeProviderStorage::new(peer_id, piece_cache.clone(), external_provider_storage);

    let networking_config = subspace_networking::Config {
        keypair: dsn_config.keypair.clone(),
        listen_on: dsn_config.listen_on,
        allow_non_global_addresses_in_dht: dsn_config.allow_non_global_addresses_in_dht,
        networking_parameters_registry: BootstrappedNetworkingParameters::new(
            dsn_config.bootstrap_nodes,
        )
        .boxed(),
        request_response_protocols: vec![
            PieceByHashRequestHandler::create(move |req| {
                let result = match piece_cache.get_piece(req.piece_index_hash) {
                    Ok(maybe_piece) => maybe_piece,
                    Err(error) => {
                        error!(piece_index_hash = ?req.piece_index_hash, %error, "Failed to get piece from cache");
                        None
                    }
                };

                async { Some(PieceByHashResponse { piece: result }) }
            }),
            RootBlockBySegmentIndexesRequestHandler::create(move |req| {
                let internal_result = req
                    .segment_indexes
                    .iter()
                    .map(|segment_index| root_block_cache.get_root_block(*segment_index))
                    .collect::<Result<Vec<Option<RootBlock>>, _>>();

                let result = match internal_result {
                    Ok(root_blocks) => Some(RootBlockResponse { root_blocks }),
                    Err(error) => {
                        error!(%error, "Failed to get root blocks from cache");

                        None
                    }
                };

                async move { result }
            }),
        ],
        provider_storage,
        ..subspace_networking::Config::default()
    };

    subspace_networking::create(networking_config).await
}

/// Start an archiver that will listen for archived segments and send it to DSN network using
/// pub-sub protocol.
pub(crate) async fn start_dsn_archiver<Spawner>(
    mut archived_segment_notification_stream: impl Stream<Item = ArchivedSegmentNotification> + Unpin,
    node: Node,
    spawner: Spawner,
    segment_publish_concurrency: NonZeroUsize,
) where
    Spawner: SpawnNamed,
{
    trace!("Subspace DSN archiver started.");

    let segment_publish_semaphore = Arc::new(Semaphore::new(segment_publish_concurrency.get()));

    let mut last_published_segment_index: Option<u64> = None;
    while let Some(ArchivedSegmentNotification {
        archived_segment, ..
    }) = archived_segment_notification_stream.next().await
    {
        let segment_index = archived_segment.root_block.segment_index();
        let first_piece_index = segment_index * u64::from(PIECES_IN_SEGMENT);

        info!(%segment_index, "Processing a segment.");

        // skip repeating publication
        if let Some(last_published_segment_index) = last_published_segment_index {
            if last_published_segment_index == segment_index {
                info!(?segment_index, "Archived segment skipped.");
                continue;
            }
        }

        let publishing_permit = match segment_publish_semaphore.clone().acquire_owned().await {
            Ok(publishing_permit) => publishing_permit,
            Err(error) => {
                warn!(
                    %segment_index,
                    %error,
                    "Semaphore was closed, interrupting publishing"
                );
                return;
            }
        };

        spawner.spawn(
            "segment-publishing",
            Some("subspace-networking"),
            Box::pin({
                let node = node.clone();

                async move {
                    publish_pieces(&node, first_piece_index, segment_index, archived_segment).await;

                    // Release only after publishing is finished
                    drop(publishing_permit);
                }
                .in_current_span()
            }),
        );

        last_published_segment_index = Some(segment_index);
    }
}

// Publishes pieces-by-sector to DSN in bulk. Supports cancellation.
pub(crate) async fn publish_pieces(
    node: &Node,
    first_piece_index: PieceIndex,
    segment_index: u64,
    archived_segment: Arc<ArchivedSegment>,
) {
    let pieces_indexes = (first_piece_index..).take(archived_segment.pieces.count());

    let mut pieces_publishing_futures = pieces_indexes
        .map(|piece_index| announce_single_piece_index_with_backoff(piece_index, node))
        .collect::<FuturesUnordered<_>>();

    while pieces_publishing_futures.next().await.is_some() {
        // empty body
    }

    info!(%segment_index, "Piece publishing was successful.");
}
