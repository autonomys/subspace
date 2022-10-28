use futures::StreamExt;
use sc_consensus_subspace::{ArchivedSegmentNotification, SubspaceLink};
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::traits::Block as BlockT;
use std::num::NonZeroUsize;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndex, PieceIndexHash, PIECES_IN_SEGMENT};
use subspace_networking::libp2p::{identity, Multiaddr};
use subspace_networking::{
    BootstrappedNetworkingParameters, CreationError, CustomRecordStore,
    LimitedSizeRecordStorageWrapper, MemoryProviderStorage, MemoryRecordStorage,
    PieceByHashRequestHandler, PieceByHashResponse, PieceKey, ToMultihash,
};
use tracing::{debug, info, trace, Instrument};

const MAX_KADEMLIA_RECORDS_NUMBER: usize = 32768;

pub type PieceGetter = Arc<dyn (Fn(&PieceIndex) -> Option<Piece>) + Send + Sync + 'static>;

/// DSN configuration parameters.
#[derive(Clone, Debug)]
pub struct DsnConfig {
    /// DSN 'listen-on' multi-address
    pub dsn_listen_on: Vec<Multiaddr>,

    /// DSN 'bootstrap_node' multi-address
    pub dsn_bootstrap_node: Vec<Multiaddr>,

    /// Identity keypair of a node used for authenticated connections.
    pub keypair: identity::Keypair,

    /// Kademlia cache size (in items)
    pub record_cache_size: usize,
}

/// Start an archiver that will listen for archived segments and send it to DSN network using
/// pub-sub protocol.
pub async fn start_dsn_node<Block, Spawner>(
    subspace_link: &SubspaceLink<Block>,
    dsn_config: DsnConfig,
    spawner: Spawner,
    piece_getter: PieceGetter,
) -> Result<(), CreationError>
where
    Block: BlockT,
    Spawner: SpawnEssentialNamed,
{
    let span = tracing::info_span!(sc_tracing::logging::PREFIX_LOG_SPAN, name = "DSN");
    let _enter = span.enter();

    let record_size = NonZeroUsize::new(dsn_config.record_cache_size).unwrap_or(
        NonZeroUsize::new(MAX_KADEMLIA_RECORDS_NUMBER)
            .expect("We don't expect an error on manually set value."),
    );

    trace!("Subspace networking starting.");

    let networking_config = subspace_networking::Config::<
        CustomRecordStore<
            LimitedSizeRecordStorageWrapper<MemoryRecordStorage>,
            MemoryProviderStorage,
        >,
    > {
        keypair: dsn_config.keypair,
        listen_on: dsn_config.dsn_listen_on,
        allow_non_globals_in_dht: true,
        networking_parameters_registry: BootstrappedNetworkingParameters::new(
            dsn_config.dsn_bootstrap_node,
        )
        .boxed(),
        request_response_protocols: vec![PieceByHashRequestHandler::create(move |req| {
            let result = if let PieceKey::PieceIndex(idx) = req.key {
                piece_getter(&idx)
            } else {
                debug!(key=?req.key, "Incorrect piece request - unsupported key type.");

                None
            };

            Some(PieceByHashResponse { piece: result })
        })],
        record_store: CustomRecordStore::new(
            LimitedSizeRecordStorageWrapper::new(MemoryRecordStorage::default(), record_size),
            MemoryProviderStorage::default(),
        ),
        ..subspace_networking::Config::with_generated_keypair()
    };

    let (node, mut node_runner) = subspace_networking::create(networking_config).await?;

    info!("Subspace networking initialized: Node ID is {}", node.id());

    spawner.spawn_essential(
        "node-runner",
        Some("subspace-networking"),
        Box::pin(
            async move {
                node_runner.run().await;
            }
            .in_current_span(),
        ),
    );

    let mut archived_segment_notification_stream = subspace_link
        .archived_segment_notification_stream()
        .subscribe();

    spawner.spawn_essential(
        "archiver",
        Some("subspace-networking"),
        Box::pin(
            async move {
                trace!("Subspace DSN archiver started.");

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
                    let keys_iter = (first_piece_index..)
                        .take(archived_segment.pieces.count())
                        .map(|idx| (idx, PieceIndexHash::from_index(idx)))
                        .map(|(idx, hash)| (idx, hash.to_multihash()));

                    for ((_idx, key), piece) in keys_iter.zip(archived_segment.pieces.as_pieces()) {
                        //TODO: restore annoucing after https://github.com/libp2p/rust-libp2p/issues/3048
                        // trace!(?key, ?idx, "Announcing key...");
                        //
                        // let announcing_result = node.start_announcing(key).await;
                        //
                        // trace!(?key, "Announcing result: {:?}", announcing_result);

                        let put_value_result = node.put_value(key, piece.to_vec()).await;

                        trace!(?key, "Put value result: {:?}", put_value_result);

                        //TODO: ensure republication of failed announcements
                    }

                    last_published_segment_index = Some(segment_index);
                    info!(%segment_index, "Segment processed.");
                }
            }
            .in_current_span(),
        ),
    );

    Ok(())
}
