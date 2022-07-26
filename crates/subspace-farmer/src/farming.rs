//! A farming process, that is interruptable (via dropping it)
//! and possible to wait on (custom `wait` method)
#[cfg(test)]
mod tests;

use crate::commitments::Commitments;
use crate::identity::Identity;
use crate::plot::Plot;
use crate::rpc_client::RpcClient;
use crate::single_disk_farm::SingleDiskSemaphore;
use crate::single_plot_farm::SinglePlotFarmId;
use crate::utils::AbortingJoinHandle;
use crate::CommitmentError;
use futures::future::{Fuse, FusedFuture};
use futures::{FutureExt, StreamExt};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;
use subspace_core_primitives::{PublicKey, Salt, Solution};
use subspace_rpc_primitives::{
    RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};
use subspace_verification::is_within_solution_range;
use thiserror::Error;
use tracing::{debug, error, info, info_span, trace, warn, Instrument};

const TAGS_SEARCH_LIMIT: usize = 10;

#[derive(Debug, Error)]
pub enum FarmingError {
    #[error("jsonrpsee error: {0}")]
    RpcError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Error joining task: {0}")]
    JoinTask(tokio::task::JoinError),
    #[error("Plot read error: {0}")]
    PlotRead(std::io::Error),
}

/// `Farming` structure is an abstraction of the farming process for a single replica plot farming.
///
/// Farming instance can be stopped by dropping or it is possible to wait for it to exit on its own.
///
/// At high level it receives a new challenge from the consensus and tries to find solution for it
/// in its `Commitments` database.
pub struct Farming {
    handle: Fuse<AbortingJoinHandle<Result<(), FarmingError>>>,
}

/// Assumes `plot`, `commitment`, `client` and `identity` are already initialized
impl Farming {
    /// Returns an instance of farming, and also starts a concurrent background farming task
    pub async fn start<T: RpcClient + Sync + Send + 'static>(
        single_plot_farm_id: SinglePlotFarmId,
        plot: Plot,
        commitments: Commitments,
        client: T,
        single_disk_semaphore: SingleDiskSemaphore,
        identity: Identity,
        reward_address: PublicKey,
    ) -> Self {
        let (initialized_sender, initialized_receiver) = async_oneshot::oneshot();

        // Get a handle for the background task, so that we can wait on it later if we want to
        let farming_handle = tokio::spawn(
            async move {
                subscribe_to_slot_info(
                    single_plot_farm_id,
                    initialized_sender,
                    &client,
                    &plot,
                    &commitments,
                    single_disk_semaphore,
                    &identity,
                    reward_address,
                )
                .await
            }
            .in_current_span(),
        );

        // Wait for initialization to finish, result doesn't matter here
        let _ = initialized_receiver.await;

        Farming {
            handle: AbortingJoinHandle::new(farming_handle).fuse(),
        }
    }

    /// Waits for the background farming to finish
    pub async fn wait(&mut self) -> Result<(), FarmingError> {
        if self.handle.is_terminated() {
            return Ok(());
        }
        (&mut self.handle).await.map_err(FarmingError::JoinTask)?
    }
}

/// Salts will change, this struct allows to keep track of them
#[derive(Default)]
struct Salts {
    current: Option<Salt>,
    next: Option<Salt>,
}

/// Subscribes to slots, and tries to find a solution for them
#[allow(clippy::too_many_arguments)]
async fn subscribe_to_slot_info<T: RpcClient>(
    single_plot_farm_id: SinglePlotFarmId,
    mut initialized_sender: async_oneshot::Sender<()>,
    client: &T,
    plot: &Plot,
    commitments: &Commitments,
    single_disk_semaphore: SingleDiskSemaphore,
    identity: &Identity,
    reward_address: PublicKey,
) -> Result<(), FarmingError> {
    info!("Subscribing to slot info notifications");
    let mut slot_info_notifications = client
        .subscribe_slot_info()
        .await
        .map_err(FarmingError::RpcError)?;

    let mut reward_signing_info_notifications = client
        .subscribe_reward_signing()
        .await
        .map_err(FarmingError::RpcError)?;

    if let Err(_closed) = initialized_sender.send(()) {
        return Ok(());
    }

    let _reward_signing_task = AbortingJoinHandle::new(tokio::spawn({
        let identity = identity.clone();
        let client = client.clone();

        async move {
            while let Some(RewardSigningInfo { hash, public_key }) =
                reward_signing_info_notifications.next().await
            {
                // Multiple plots might have solved, only sign with correct one
                if identity.public_key().to_bytes() != public_key {
                    continue;
                }

                let signature = identity.sign_reward_hash(&hash);

                match client
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
        }
        .in_current_span()
    }));

    let mut salts = Salts::default();

    while let Some(slot_info) = slot_info_notifications.next().await {
        debug!(?slot_info, "New slot");

        update_commitments(
            single_plot_farm_id,
            plot,
            commitments,
            &mut salts,
            &slot_info,
            &single_disk_semaphore,
        );

        let maybe_solution_handle = tokio::task::spawn_blocking({
            let identity = identity.clone();
            let commitments = commitments.clone();
            let plot = plot.clone();

            move || {
                let (local_challenge, target) =
                    identity.derive_local_challenge_and_target(slot_info.global_challenge);

                // Try to first find a block authoring solution, then if not found try to find a
                // vote
                let voting_tags = commitments.find_by_range(
                    target,
                    slot_info.voting_solution_range,
                    slot_info.salt,
                    TAGS_SEARCH_LIMIT,
                );

                let maybe_tag = if voting_tags.len() < TAGS_SEARCH_LIMIT {
                    // We found all tags within voting solution range
                    voting_tags.into_iter().next()
                } else {
                    let (tag, piece_offset) = voting_tags
                        .into_iter()
                        .next()
                        .expect("Due to if condition vector is not empty; qed");

                    if is_within_solution_range(target, tag, slot_info.solution_range) {
                        // Found a tag within solution range for blocks
                        Some((tag, piece_offset))
                    } else {
                        // There might be something that is within solution range for blocks
                        commitments
                            .find_by_range(
                                target,
                                slot_info.solution_range,
                                slot_info.salt,
                                TAGS_SEARCH_LIMIT,
                            )
                            .into_iter()
                            .next()
                            .or(Some((tag, piece_offset)))
                    }
                };

                match maybe_tag {
                    Some((tag, piece_offset)) => {
                        let (encoding, piece_index) = plot
                            .read_piece_with_index(piece_offset)
                            .map_err(FarmingError::PlotRead)?;
                        let solution = Solution {
                            public_key: identity.public_key().to_bytes().into(),
                            reward_address,
                            piece_index,
                            encoding,
                            tag_signature: identity.create_tag_signature(tag),
                            local_challenge,
                            tag,
                        };
                        debug!("Solution found");
                        trace!(?solution, "Solution found");

                        Ok(Some(solution))
                    }
                    None => {
                        debug!("Solution not found");
                        Ok(None)
                    }
                }
            }
        });

        let maybe_solution = maybe_solution_handle.await.unwrap()?;

        client
            .submit_solution_response(SolutionResponse {
                slot_number: slot_info.slot_number,
                maybe_solution,
            })
            .await
            .map_err(FarmingError::RpcError)?;
    }

    Ok(())
}

/// Compare salts in `slot_info` to those known from `salts` and start update plot commitments
/// accordingly if necessary (in background)
fn update_commitments(
    single_plot_farm_id: SinglePlotFarmId,
    plot: &Plot,
    commitments: &Commitments,
    salts: &mut Salts,
    slot_info: &SlotInfo,
    single_disk_semaphore: &SingleDiskSemaphore,
) {
    let mut current_recommitment_done_receiver = None;
    // Check if current salt has changed
    if salts.current != Some(slot_info.salt) {
        salts.current.replace(slot_info.salt);

        // If previous `salts.next` is not the same as current (expected behavior), need to
        // re-commit
        if salts.next != Some(slot_info.salt) {
            let (current_recommitment_done_sender, receiver) = mpsc::channel::<()>();

            current_recommitment_done_receiver.replace(receiver);

            let salt = slot_info.salt;
            let plot = plot.clone();
            let commitments = commitments.clone();
            let single_disk_semaphore = single_disk_semaphore.clone();
            let span = info_span!("recommit", new_salt = %hex::encode(salt));

            let result = thread::Builder::new()
                .name(format!(
                    "recommit-{}-{single_plot_farm_id}",
                    hex::encode(salt)
                ))
                .spawn(move || {
                    let _single_disk_semaphore_guard = single_disk_semaphore.acquire();
                    let _span_guard = span.enter();

                    let started = Instant::now();
                    info!("Salt updated, recommitting in background");

                    if let Err(error) = commitments.create(salt, plot) {
                        error!(%error, "Failed to create commitment");
                        if matches!(error, CommitmentError::Stop) {
                            return;
                        }
                    } else {
                        info!(
                            took_seconds = started.elapsed().as_secs_f32(),
                            "Finished recommitment",
                        );
                    }

                    // We don't care if anyone is listening on the other side
                    let _ = current_recommitment_done_sender.send(());
                });

            if let Err(error) = result {
                error!(%error, "Failed to spawn recommitment thread")
            }
        }
    }

    if let Some(new_next_salt) = slot_info.next_salt {
        if salts.next != Some(new_next_salt) {
            salts.next.replace(new_next_salt);

            let plot = plot.clone();
            let commitments = commitments.clone();
            let single_disk_semaphore = single_disk_semaphore.clone();
            let span = info_span!("recommit", next_salt = %hex::encode(new_next_salt));

            let result = thread::Builder::new()
                .name(format!(
                    "recommit-{}-{single_plot_farm_id}",
                    hex::encode(new_next_salt)
                ))
                .spawn(move || {
                    // Wait for current recommitment to finish if it is in progress
                    if let Some(receiver) = current_recommitment_done_receiver {
                        // Do not care about result here either
                        let _ = receiver.recv();
                    }

                    let _single_disk_semaphore_guard = single_disk_semaphore.acquire();
                    let _span_guard = span.enter();

                    let started = Instant::now();
                    info!("Salt will be updated, recommitting in background");
                    if let Err(error) = commitments.create(new_next_salt, plot) {
                        error!(
                            %error,
                            "Recommitting salt in background failed",
                        );
                        return;
                    }
                    info!(
                        took_seconds = started.elapsed().as_secs_f32(),
                        "Finished recommitment in background",
                    );
                });

            if let Err(error) = result {
                error!(%error, "Failed to spawn recommitment thread")
            }
        }
    }
}
