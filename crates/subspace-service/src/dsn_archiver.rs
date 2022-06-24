use futures::StreamExt;
use parity_scale_codec::Encode;
use sc_consensus_subspace::{ArchivedSegmentNotification, SubspaceLink};
use sc_service::TaskManager;
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::traits::Block as BlockT;
use subspace_networking::PUB_SUB_ARCHIVING_TOPIC;
use tracing::{error, info, trace};

/// Start an archiver that will listen for archived segments and send it to DSN network using
/// pub-sub protocol.
pub fn start_subspace_dsn_archiver<Block>(
    subspace_link: &SubspaceLink<Block>,
    node_config: subspace_networking::Config,
    task_manager: &TaskManager,
) where
    Block: BlockT,
{
    let subscription_processing_spawner = task_manager.spawn_essential_handle();
    let node_runner_spawner = task_manager.spawn_essential_handle();

    subscription_processing_spawner.spawn_essential(
        "subspace-archiver-DSN",
        None,
        Box::pin({
            trace!("DSN archiver started.");
            let mut archived_segment_notification_stream = subspace_link
                .archived_segment_notification_stream()
                .subscribe();

            async move {
                let (node, node_runner) = match subspace_networking::create(node_config).await {
                    Ok(res) => res,
                    Err(err) => {
                        return error!(error = ?err, "DSN Node creation failed.");
                    }
                };

                info!("DSN initialized: DSN Node ID is {}", node.id());

                node_runner_spawner.spawn_essential_blocking(
                    "DSN node runner",
                    None,
                    Box::pin(async move {
                        node_runner.run().await;
                    }),
                );

                while let Some(ArchivedSegmentNotification {
                    archived_segment, ..
                }) = archived_segment_notification_stream.next().await
                {
                    trace!("ArchivedSegmentNotification received");
                    let data = archived_segment.encode().to_vec();

                    match node.publish(PUB_SUB_ARCHIVING_TOPIC.clone(), data).await {
                        Ok(_) => {
                            trace!("Archived segment published.");
                        }
                        Err(err) => {
                            error!(error = ?err, "Failed to publish archived segment");
                        }
                    }
                }
            }
        }),
    );
}
