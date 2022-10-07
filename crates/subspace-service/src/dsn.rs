use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use sc_consensus_subspace::{ArchivedSegmentNotification, SubspaceLink};
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndex, PieceIndexHash, PIECES_IN_SEGMENT};
use subspace_networking::libp2p::{identity, Multiaddr};
use subspace_networking::{
    CreationError, PieceByHashRequestHandler, PieceByHashResponse, PieceKey, ToMultihash,
};
use tracing::{error, info, trace};

pub type PieceGetter = Arc<dyn (Fn(&PieceIndex) -> Option<Piece>) + Send + Sync + 'static>;

/// DSN configuration parameters.
#[derive(Clone, Debug)]
pub struct DsnConfig {
    /// DSN 'listen-on' multi-address
    pub dsn_listen_on: Vec<Multiaddr>,

    /// Identity keypair of a node used for authenticated connections.
    pub keypair: identity::Keypair,
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
    trace!(target: "dsn", "Subspace networking starting.");

    let networking_config = subspace_networking::Config {
        keypair: dsn_config.keypair,
        listen_on: dsn_config.dsn_listen_on,
        request_response_protocols: vec![PieceByHashRequestHandler::create(move |req| {
            let result = if let PieceKey::PieceIndex(idx) = req.key {
                piece_getter(&idx)
            } else {
                // TODO
                None
            };

            Some(PieceByHashResponse { piece: result })
        })],
        ..subspace_networking::Config::with_generated_keypair()
    };

    let (node, mut node_runner) = subspace_networking::create(networking_config).await?;

    let span = sc_tracing::tracing::info_span!(sc_tracing::logging::PREFIX_LOG_SPAN, name = "DSN");
    let _enter = span.enter();

    info!(target: "dsn", "Subspace networking initialized: Node ID is {}", node.id());

    spawner.spawn_essential("node-runner", Some("subspace-networking"), {
        let span = span.clone();
        Box::pin(async move {
            //   let _enter = span.enter();
            node_runner.run().instrument(span).await;
        })
    });

    let mut archived_segment_notification_stream = subspace_link
        .archived_segment_notification_stream()
        .subscribe();

    spawner.spawn_essential(
        "archiver",
        Some("subspace-networking"),
        Box::pin(async move {
            trace!(target: "dsn", "Subspace DSN archiver started.");

            let mut last_published_segment_index: Option<u64> = None;
            while let Some(ArchivedSegmentNotification {
                archived_segment, ..
            }) = archived_segment_notification_stream.next().await
            {
                let segment_index = archived_segment.root_block.segment_index();
                let first_piece_index = segment_index * u64::from(PIECES_IN_SEGMENT);

                // skip repeating publication
                if let Some(last_published_segment_index) = last_published_segment_index{
                    if last_published_segment_index == segment_index{
                        debug!(target: "dsn", ?segment_index, "Archived segment skipped.");
                        continue;
                    }
                }
                let keys_iter = (first_piece_index..)
                    .take(archived_segment.pieces.count())
                    .map(PieceIndexHash::from_index)
                    .map(|hash| hash.to_multihash());

                //TODO: rewrite announcing to batches to limit simultaneous request number
                let pieces_announcements = keys_iter
                    .map(|key| node.start_announcing(key).boxed())
                    .collect::<FuturesUnordered<_>>();

                //TODO: ensure republication of failed announcements
                match pieces_announcements
                    .collect::<Vec<_>>()
                    .await
                    .iter()
                    .find(|res| res.is_err())
                {
                    None => {
                        trace!(target: "dsn", ?segment_index, "Archived segment published.");
                    }
                    Some(err) => {
                        error!(target: "dsn", error = ?err, ?segment_index, "Failed to publish archived segment");
                    }
                }
                last_published_segment_index = Some(segment_index);
            }
        }),
    );

    Ok(())
}
