//! A farming process, that is interruptable (via dropping it)
//! and possible to wait on (custom `wait` method)
#[cfg(test)]
mod tests;

use crate::commitments::Commitments;
use crate::identity::Identity;
use crate::plot::Plot;
use crate::rpc::RpcClient;
use futures::{future, future::Either};
use log::{debug, error, info, trace};
use std::time::Instant;
use subspace_core_primitives::{LocalChallenge, Salt};
use subspace_rpc_primitives::{SlotInfo, Solution, SolutionResponse};
use thiserror::Error;
use tokio::task::JoinHandle;
#[cfg(test)]
use tokio::time::{sleep, Duration};

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
    ) -> Self {
        // Oneshot channels, that will be used for interrupt/stop the process
        let (stop_sender, stop_receiver) = async_oneshot::oneshot();

        // Get a handle for the background task, so that we can wait on it later if we want to
        let farming_handle = tokio::spawn(async {
            match future::select(
                Box::pin(async move {
                    subscribe_to_slot_info(&client, &plot, &commitments, &identity).await
                }),
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
) -> Result<(), FarmingError> {
    info!("Subscribing to slot info");
    let mut new_slots = client
        .subscribe_slot_info()
        .await
        .map_err(FarmingError::RpcError)?;

    let mut salts = Salts::default();
    #[cfg(test)]
    let mut latest_salt: Salt = Salt::default();

    while let Some(slot_info) = new_slots.recv().await {
        debug!("New slot: {:?}", slot_info);

        update_commitments(plot, commitments, &mut salts, &slot_info);

        // if salt will change, wait for background recommitment to finish first
        #[cfg(test)]
        if slot_info.next_salt.unwrap() != latest_salt {
            latest_salt = slot_info.next_salt.unwrap();
            let mut current_commitment_notifier =
                commitments.clone().on_recommitment(slot_info.salt).await;
            let mut upcoming_commitment_notifier =
                commitments.clone().on_recommitment(latest_salt).await;
            tokio::select! {
                _ = current_commitment_notifier.recv() => {
                    // also wait for the recommitment for the upcoming salt
                    // it locks the commitment database, and can cause racy behavior otherwise
                    tokio::select! {
                        _ = upcoming_commitment_notifier.recv() => {
                        },
                        _ = sleep(Duration::from_secs(1)) => { panic!("Cannot finish the 2nd recommitments..."); }
                    }
                },
                _ = sleep(Duration::from_secs(1)) => { panic!("Cannot finish the 1st recommitments..."); }
            }
        }

        let local_challenge = derive_local_challenge(slot_info.global_challenge, identity);

        // for the current challenge, we will either find `Some(solution)` or we can't find one (`None`)
        let maybe_solution = match commitments
            .find_by_range(
                local_challenge.derive_target(),
                slot_info.solution_range,
                slot_info.salt,
            )
            .await
        {
            Some((tag, piece_index)) => {
                let encoding = plot
                    .read(piece_index)
                    .await
                    .map_err(FarmingError::PlotRead)?;
                let solution = Solution {
                    public_key: identity.public_key().to_bytes().into(),
                    piece_index,
                    encoding,
                    signature: identity.sign(&tag).to_bytes().into(),
                    local_challenge,
                    tag,
                };
                debug!("Solution found");
                trace!("Solution found: {:?}", solution);

                Some(solution)
            }
            None => {
                debug!("Solution not found");
                None
            }
        };

        client
            .submit_solution_response(SolutionResponse {
                slot_number: slot_info.slot_number,
                maybe_solution,
                secret_key: identity.secret_key().to_bytes().into(),
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
    // Check if current salt has changed
    if salts.current != Some(slot_info.salt) {
        salts.current.replace(slot_info.salt);

        // If previous `salts.next` is not the same as current (expected behavior), need to re-commit
        if salts.next != Some(slot_info.salt) {
            tokio::spawn({
                let salt = slot_info.salt;
                let plot = plot.clone();
                let commitments = commitments.clone();

                async move {
                    let started = Instant::now();
                    info!(
                        "Salt updated to {}, recommitting in background",
                        hex::encode(salt)
                    );

                    if let Err(error) = commitments.create(salt, plot).await {
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
                }
            });
        }
    }

    if let Some(new_next_salt) = slot_info.next_salt {
        if salts.next != Some(new_next_salt) {
            salts.next.replace(new_next_salt);

            tokio::spawn({
                let plot = plot.clone();
                let commitments = commitments.clone();

                async move {
                    let started = Instant::now();
                    info!(
                        "Salt will update to {} soon, recommitting in background",
                        hex::encode(new_next_salt)
                    );
                    if let Err(error) = commitments.create(new_next_salt, plot).await {
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
    identity.sign(global_challenge.as_ref()).to_bytes().into()
}
