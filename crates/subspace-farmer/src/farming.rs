//! A farming process, that is interruptable (via dropping it)
//! and possible to wait on (custom `wait` method)
#[cfg(test)]
mod tests;

use crate::commitments::Commitments;
use crate::identity::Identity;
use crate::plot::Plot;
use crate::rpc::RpcClient;
use futures::{future, future::Either};
use log::{debug, error, info, trace, warn};
use std::sync::mpsc;
use std::time::Instant;
use subspace_core_primitives::{LocalChallenge, PublicKey, Salt, Solution};
use subspace_rpc_primitives::{BlockSignature, BlockSigningInfo, SlotInfo, SolutionResponse};
use thiserror::Error;
use tokio::task::JoinHandle;

#[derive(Debug, Error)]
pub enum FarmingError {
    #[error("jsonrpsee error: {0}")]
    RpcError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Error joining task: {0}")]
    JoinTask(tokio::task::JoinError),
    #[error("Plot read error: {0}")]
    PlotRead(std::io::Error),
}
/// `Farming` struct is the abstraction of the farming process
///
/// Farming Instance that stores a channel to stop/pause the background farming task
/// and a handle to make it possible to wait on this background task
pub struct Farming {
    stop_sender: async_oneshot::Sender<()>,
    handle: Option<JoinHandle<Result<(), FarmingError>>>,
}

/// Assumes `plot`, `commitment`, `client` and `identity` are already initialized
impl Farming {
    /// Returns an instance of farming, and also starts a concurrent background farming task
    pub fn start<T: RpcClient + Sync + Send + 'static>(
        plot: Plot,
        commitments: Commitments,
        client: T,
        identity: Identity,
        reward_adress: PublicKey,
    ) -> Self {
        // Oneshot channels, that will be used for interrupt/stop the process
        let (stop_sender, stop_receiver) = async_oneshot::oneshot();

        // Get a handle for the background task, so that we can wait on it later if we want to
        let farming_handle = tokio::spawn(async move {
            match future::select(
                Box::pin(subscribe_to_slot_info(
                    &client,
                    &plot,
                    &commitments,
                    &identity,
                    reward_adress,
                )),
                stop_receiver,
            )
            .await
            {
                Either::Left((farming_result, _)) => {
                    if let Err(val) = farming_result {
                        return Err(val);
                    }
                }
                // either Sender is dropped, or a stop message is received.
                // in both cases, we stop the process and return Ok(())
                Either::Right((_, _)) => {
                    info!("Farming stopped!");
                }
            }
            Ok(())
        });

        Farming {
            stop_sender,
            handle: Some(farming_handle),
        }
    }

    /// Waits for the background farming to finish
    pub async fn wait(mut self) -> Result<(), FarmingError> {
        self.handle
            .take()
            .unwrap()
            .await
            .map_err(FarmingError::JoinTask)?
    }
}

impl Drop for Farming {
    fn drop(&mut self) {
        let _ = self.stop_sender.send(());
    }
}

/// Salts will change, this struct allows to keep track of them
#[derive(Default)]
struct Salts {
    current: Option<Salt>,
    next: Option<Salt>,
}

/// Subscribes to slots, and tries to find a solution for them
async fn subscribe_to_slot_info<T: RpcClient>(
    client: &T,
    plot: &Plot,
    commitments: &Commitments,
    identity: &Identity,
    reward_address: PublicKey,
) -> Result<(), FarmingError> {
    info!("Subscribing to slot info notifications");
    let mut slot_info_notifications = client
        .subscribe_slot_info()
        .await
        .map_err(FarmingError::RpcError)?;

    let mut salts = Salts::default();

    while let Some(slot_info) = slot_info_notifications.recv().await {
        debug!("New slot: {:?}", slot_info);

        update_commitments(plot, commitments, &mut salts, &slot_info);

        let maybe_solution_handle = tokio::task::spawn_blocking({
            let identity = identity.clone();
            let commitments = commitments.clone();
            let plot = plot.clone();

            move || {
                let local_challenge = derive_local_challenge(slot_info.global_challenge, &identity);
                match commitments.find_by_range(
                    local_challenge.derive_target(),
                    slot_info.solution_range,
                    slot_info.salt,
                ) {
                    Some((tag, piece_index)) => {
                        let encoding = plot.read(piece_index).map_err(FarmingError::PlotRead)?;
                        let solution = Solution {
                            public_key: identity.public_key().to_bytes().into(),
                            reward_address,
                            piece_index,
                            encoding,
                            signature: identity.sign_farmer_solution(&tag).to_bytes().into(),
                            local_challenge,
                            tag,
                        };
                        debug!("Solution found");
                        trace!("Solution found: {:?}", solution);

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

        // When solution is found, wait for block signing request.
        if maybe_solution.is_some() {
            debug!("Subscribing to sign block notifications");
            let mut block_signing_info_notifications = client
                .subscribe_block_signing()
                .await
                .map_err(FarmingError::RpcError)?;

            tokio::spawn({
                let identity = identity.clone();
                let client = client.clone();

                async move {
                    if let Some(BlockSigningInfo { header_hash }) =
                        block_signing_info_notifications.recv().await
                    {
                        let signature = identity.block_signing(&header_hash);

                        match client
                            .submit_block_signature(BlockSignature {
                                header_hash,
                                signature: Some(signature.to_bytes().into()),
                            })
                            .await
                        {
                            Ok(_) => {
                                info!(
                                    "Successfully signed block 0x{} and sent signature to node",
                                    hex::encode(header_hash)
                                );
                            }
                            Err(error) => {
                                warn!(
                                    "Failed to send signature for block 0x{}: {}",
                                    hex::encode(header_hash),
                                    error
                                );
                            }
                        }
                    }
                }
            });
        }

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
    plot: &Plot,
    commitments: &Commitments,
    salts: &mut Salts,
    slot_info: &SlotInfo,
) {
    let mut current_recommitment_done_receiver = None;
    // Check if current salt has changed
    if salts.current != Some(slot_info.salt) {
        salts.current.replace(slot_info.salt);

        // If previous `salts.next` is not the same as current (expected behavior), need to re-commit
        if salts.next != Some(slot_info.salt) {
            let (current_recommitment_done_sender, receiver) = mpsc::channel::<()>();

            current_recommitment_done_receiver.replace(receiver);

            tokio::task::spawn_blocking({
                let salt = slot_info.salt;
                let plot = plot.clone();
                let commitments = commitments.clone();

                move || {
                    let started = Instant::now();
                    info!(
                        "Salt updated to {}, recommitting in background",
                        hex::encode(salt)
                    );

                    if let Err(error) = commitments.create(salt, plot) {
                        error!(
                            "Failed to create commitment for {}: {}",
                            hex::encode(salt),
                            error
                        );
                    } else {
                        info!(
                            "Finished recommitment for {} in {} seconds",
                            hex::encode(salt),
                            started.elapsed().as_secs_f32()
                        );
                    }

                    // We don't care if anyone is listening on the other side
                    let _ = current_recommitment_done_sender.send(());
                }
            });
        }
    }

    if let Some(new_next_salt) = slot_info.next_salt {
        if salts.next != Some(new_next_salt) {
            salts.next.replace(new_next_salt);

            tokio::task::spawn_blocking({
                let plot = plot.clone();
                let commitments = commitments.clone();

                move || {
                    // Wait for current recommitment to finish if it is in progress
                    if let Some(receiver) = current_recommitment_done_receiver {
                        // Do not care about result here either
                        let _ = receiver.recv();
                    }

                    let started = Instant::now();
                    info!(
                        "Salt will update to {} soon, recommitting in background",
                        hex::encode(new_next_salt)
                    );
                    if let Err(error) = commitments.create(new_next_salt, plot) {
                        error!(
                            "Recommitting salt in background failed for {}: {}",
                            hex::encode(new_next_salt),
                            error
                        );
                        return;
                    }
                    info!(
                        "Finished recommitment in background for {} in {} seconds",
                        hex::encode(new_next_salt),
                        started.elapsed().as_secs_f32()
                    );
                }
            });
        }
    }
}

/// Derive local challenge for farmer's identity from the global challenge.
fn derive_local_challenge<C: AsRef<[u8]>>(
    global_challenge: C,
    identity: &Identity,
) -> LocalChallenge {
    identity
        .sign_farmer_solution(global_challenge.as_ref())
        .to_bytes()
        .into()
}
