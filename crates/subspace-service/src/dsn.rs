use futures::StreamExt;
use parity_scale_codec::Encode;
use sc_consensus_subspace::{ArchivedSegmentNotification, SubspaceLink};
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::traits::Block as BlockT;
use subspace_networking::{CreationError, PUB_SUB_ARCHIVING_TOPIC};
use tracing::{error, info, trace};

/// Start an archiver that will listen for archived segments and send it to DSN network using
/// pub-sub protocol.
pub async fn start_dsn_node<Block, Spawner>(
    subspace_link: &SubspaceLink<Block>,
    networking_config: subspace_networking::Config,
    spawner: Spawner,
) -> Result<(), CreationError>
where
    Block: BlockT,
    Spawner: SpawnEssentialNamed,
{
    trace!(target: "dsn", "Subspace networking starting.");

    let (node, mut node_runner) = subspace_networking::create(networking_config).await?;

    info!(target: "dsn", "Subspace networking initialized: Node ID is {}", node.id());

    spawner.spawn_essential(
        "node-runner",
        Some("subspace-networking"),
        Box::pin(async move {
            node_runner.run().await;
        }),
    );

    let mut archived_segment_notification_stream = subspace_link
        .archived_segment_notification_stream()
        .subscribe();

    spawner.spawn_essential(
        "archiver",
        Some("subspace-networking"),
        Box::pin(async move {
            trace!(target: "dsn", "Subspace DSN archiver started.");

            while let Some(ArchivedSegmentNotification {
                archived_segment, ..
            }) = archived_segment_notification_stream.next().await
            {
                trace!(target: "dsn", "ArchivedSegmentNotification received");
                let data = archived_segment.encode().to_vec();

                match node.publish(PUB_SUB_ARCHIVING_TOPIC.clone(), data).await {
                    Ok(_) => {
                        trace!(target: "dsn", "Archived segment published.");
                    }
                    Err(err) => {
                        error!(target: "dsn", error = ?err, "Failed to publish archived segment");
                    }
                }
            }
        }),
    );

    Ok(())
}
