use crate::node_client::NodeClient;
use crate::single_disk_farm::identity::Identity;
use futures::StreamExt;
use std::future::Future;
use subspace_rpc_primitives::{RewardSignatureResponse, RewardSigningInfo};
use tracing::{info, warn};

pub(super) async fn reward_signing<NC>(
    node_client: NC,
    identity: Identity,
) -> Result<impl Future<Output = ()>, Box<dyn std::error::Error + Send + Sync>>
where
    NC: NodeClient,
{
    info!("Subscribing to reward signing notifications");

    let mut reward_signing_info_notifications = node_client.subscribe_reward_signing().await?;

    let reward_signing_fut = async move {
        while let Some(RewardSigningInfo { hash, public_key }) =
            reward_signing_info_notifications.next().await
        {
            // Multiple plots might have solved, only sign with correct one
            if identity.public_key().to_bytes() != *public_key {
                continue;
            }

            let signature = identity.sign_reward_hash(&hash);

            match node_client
                .submit_reward_signature(RewardSignatureResponse {
                    hash,
                    signature: Some(signature.to_bytes().into()),
                })
                .await
            {
                Ok(_) => {
                    info!("Successfully signed reward hash 0x{}", hex::encode(hash));
                }
                Err(error) => {
                    warn!(
                        %error,
                        "Failed to send signature for reward hash 0x{}",
                        hex::encode(hash),
                    );
                }
            }
        }
    };

    Ok(reward_signing_fut)
}
