use crate::piece_cache::PieceCache;
use backoff::future::retry;
use backoff::ExponentialBackoff;
use futures::stream::FuturesUnordered;
use futures::{Stream, StreamExt};
use sc_client_api::AuxStore;
use sc_consensus_subspace::ArchivedSegmentNotification;
use sp_core::traits::SpawnNamed;
use sp_runtime::traits::Block as BlockT;
use std::error::Error;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{PieceIndex, PieceIndexHash, PIECES_IN_SEGMENT};
use subspace_networking::libp2p::{identity, Multiaddr};
use subspace_networking::{
    peer_id, BootstrappedNetworkingParameters, CreationError, MemoryProviderStorage, Node,
    NodeRunner, PieceByHashRequestHandler, PieceByHashResponse, PieceKey, ToMultihash,
};
use tokio::sync::Semaphore;
use tokio::time::error::Elapsed;
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn, Instrument};

/// Max time allocated for putting piece from DSN before attempt is considered to fail
const PUBLISH_PIECE_TIMEOUT: Duration = Duration::from_secs(120);
/// Defines initial duration between put_piece calls.
const PUBLISH_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(1);
/// Defines max duration between put_piece calls.
const PUBLISH_PIECE_MAX_INTERVAL: Duration = Duration::from_secs(30);

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
}

pub(crate) async fn create_dsn_instance<Block, AS>(
    dsn_config: DsnConfig,
    piece_cache: PieceCache<AS>,
) -> Result<(Node, NodeRunner<MemoryProviderStorage>), CreationError>
where
    Block: BlockT,
    AS: AuxStore + Sync + Send + 'static,
{
    trace!("Subspace networking starting.");

    // TODO: This should be a wrapper that handles locally cached pieces
    let provider_storage = MemoryProviderStorage::new(peer_id(&dsn_config.keypair));

    let networking_config = subspace_networking::Config {
        keypair: dsn_config.keypair.clone(),
        listen_on: dsn_config.listen_on,
        allow_non_global_addresses_in_dht: dsn_config.allow_non_global_addresses_in_dht,
        networking_parameters_registry: BootstrappedNetworkingParameters::new(
            dsn_config.bootstrap_nodes,
        )
        .boxed(),
        request_response_protocols: vec![PieceByHashRequestHandler::create(move |req| {
            let result = if let PieceKey::Cache(piece_index_hash) = req.key {
                match piece_cache.get_piece(piece_index_hash) {
                    Ok(maybe_piece) => maybe_piece,
                    Err(error) => {
                        error!(key=?req.key, %error, "Failed to get piece from cache");
                        None
                    }
                }
            } else {
                debug!(key=?req.key, "Incorrect piece request - unsupported key type.");

                None
            };

            Some(PieceByHashResponse { piece: result })
        })],
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
        .map(|piece_index| publish_single_piece_with_backoff(node, piece_index))
        .collect::<FuturesUnordered<_>>();

    while pieces_publishing_futures.next().await.is_some() {
        // empty body
    }

    info!(%segment_index, "Piece publishing was successful.");
}

async fn publish_single_piece_with_backoff(
    node: &Node,
    piece_index: PieceIndex,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let backoff = ExponentialBackoff {
        initial_interval: PUBLISH_PIECE_INITIAL_INTERVAL,
        max_interval: PUBLISH_PIECE_MAX_INTERVAL,
        // Try until we get a valid piece
        max_elapsed_time: None,
        ..ExponentialBackoff::default()
    };

    retry(backoff, || async {
        let publish_timeout_result: Result<Result<(), _>, Elapsed> = timeout(
            PUBLISH_PIECE_TIMEOUT,
            publish_single_piece(node, piece_index),
        )
        .await;

        if let Ok(publish_result) = publish_timeout_result {
            if publish_result.is_ok() {
                return Ok(());
            }
        }

        debug!(%piece_index, "Couldn't publish a piece. Retrying...");

        Err(backoff::Error::transient(
            "Couldn't publish piece to DSN".into(),
        ))
    })
    .await
}

async fn publish_single_piece(
    node: &Node,
    piece_index: PieceIndex,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let key = PieceIndexHash::from_index(piece_index).to_multihash();

    match node.start_announcing(key).await {
        Ok(mut stream) => {
            if stream.next().await.is_some() {
                trace!(%piece_index, ?key, "Piece announcing succeeded");

                Ok(())
            } else {
                warn!(%piece_index, ?key, "Piece announcing failed");

                Err("Piece publishing was unsuccessful".into())
            }
        }
        Err(error) => {
            error!( %piece_index, ?key, "Piece announcing failed with an error: {}", error);

            Err("Piece publishing failed".into())
        }
    }
}
