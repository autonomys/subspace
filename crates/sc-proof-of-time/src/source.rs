use crate::gossip::{GossipCheckpoints, PotGossipWorker};
use crate::verifier::PotVerifier;
use atomic::Atomic;
use derive_more::{Deref, DerefMut, From};
use futures::channel::mpsc;
use futures::executor::block_on;
use futures::{select, SinkExt, StreamExt};
use sc_client_api::{BlockImportNotification, BlockchainEvents};
use sc_network::PeerId;
use sc_network_gossip::{Network as GossipNetwork, Syncing as GossipSyncing};
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus_slots::Slot;
#[cfg(feature = "pot")]
use sp_consensus_subspace::digests::extract_pre_digest;
#[cfg(feature = "pot")]
use sp_consensus_subspace::ChainConstants;
#[cfg(feature = "pot")]
use sp_consensus_subspace::PotParametersChange;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi as SubspaceRuntimeApi};
use sp_runtime::traits::Block as BlockT;
#[cfg(feature = "pot")]
use sp_runtime::traits::{Header, Zero};
use std::marker::PhantomData;
use std::num::NonZeroU32;
#[cfg(feature = "pot")]
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use subspace_core_primitives::{PotCheckpoints, PotProof, PotSeed, SlotNumber};
use subspace_proof_of_time::PotError;
use tracing::{debug, error};

const LOCAL_PROOFS_CHANNEL_CAPACITY: usize = 10;
const SLOTS_CHANNEL_CAPACITY: usize = 10;
const GOSSIP_OUTGOING_CHANNEL_CAPACITY: usize = 10;

/// Proof of time slot information
pub struct PotSlotInfo {
    /// Slot number
    pub slot: Slot,
    /// Proof of time checkpoints
    pub checkpoints: PotCheckpoints,
}

/// Proof of time slot information
struct TimekeeperCheckpoints {
    /// Slot number
    slot: Slot,
    /// Proof of time seed
    seed: PotSeed,
    /// Iterations per slot
    slot_iterations: NonZeroU32,
    /// Proof of time checkpoints
    checkpoints: PotCheckpoints,
}

#[derive(Debug)]
struct NextSlotInput {
    slot: Slot,
    slot_iterations: NonZeroU32,
    seed: PotSeed,
}

/// Stream with proof of time slots
#[derive(Debug, Deref, DerefMut, From)]
pub struct PotSlotInfoStream(mpsc::Receiver<PotSlotInfo>);

/// Source of proofs of time.
///
/// Depending on configuration may produce proofs of time locally, send/receive via gossip and keep
/// up to day with blockchain reorgs.
#[derive(Debug)]
#[must_use = "Proof of time source doesn't do anything unless run() method is called"]
pub struct PotSource<Block, Client> {
    client: Arc<Client>,
    #[cfg(feature = "pot")]
    chain_constants: ChainConstants,
    timekeeper_checkpoints_receiver: mpsc::Receiver<TimekeeperCheckpoints>,
    outgoing_messages_sender: mpsc::Sender<GossipCheckpoints>,
    incoming_messages_receiver: mpsc::Receiver<(PeerId, GossipCheckpoints)>,
    slot_sender: mpsc::Sender<PotSlotInfo>,
    /// Rough current number of slot iterations used by gossip for verification purposes
    #[cfg(feature = "pot")]
    current_slot_iterations: Arc<Atomic<NonZeroU32>>,
    // TODO: Make this shared with Timekeeper so it can follow latest parameters automatically,
    //  this will help implementing Timekeeper "reset"
    next_slot_input: NextSlotInput,
    #[cfg(feature = "pot")]
    // TODO: Make this shared with Timekeeper so it can follow latest parameters automatically,
    //  this will help implementing Timekeeper "reset"
    parameters_change: Option<PotParametersChange>,
    _block: PhantomData<Block>,
}

impl<Block, Client> PotSource<Block, Client>
where
    Block: BlockT,
    Client: BlockchainEvents<Block> + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: SubspaceRuntimeApi<Block, FarmerPublicKey>,
{
    pub fn new<Network, GossipSync>(
        is_timekeeper: bool,
        client: Arc<Client>,
        pot_verifier: PotVerifier,
        network: Network,
        sync: Arc<GossipSync>,
    ) -> Result<(Self, PotGossipWorker<Block>, PotSlotInfoStream), ApiError>
    where
        Network: GossipNetwork<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
    {
        #[cfg(feature = "pot")]
        let chain_constants;
        #[cfg(feature = "pot")]
        let mut maybe_next_parameters_change;
        let start_slot;
        let start_seed;
        let slot_iterations;
        #[cfg(feature = "pot")]
        {
            let best_hash = client.info().best_hash;
            let runtime_api = client.runtime_api();
            chain_constants = runtime_api.chain_constants(best_hash)?;

            let best_header = client.header(best_hash)?.ok_or_else(|| {
                ApiError::UnknownBlock(format!("Parent block {best_hash} not found"))
            })?;
            let best_pre_digest = extract_pre_digest(&best_header)
                .map_err(|error| ApiError::Application(error.into()))?;

            start_slot = if best_header.number().is_zero() {
                Slot::from(1)
            } else {
                // Next slot after the best one seen
                best_pre_digest.slot() + chain_constants.block_authoring_delay() + Slot::from(1)
            };

            let pot_parameters = runtime_api.pot_parameters(best_hash)?;
            maybe_next_parameters_change = pot_parameters.next_parameters_change();

            if let Some(parameters_change) = maybe_next_parameters_change
                && parameters_change.slot == start_slot
            {
                start_seed = best_pre_digest.pot_info().future_proof_of_time().seed_with_entropy(&parameters_change.entropy);
                slot_iterations = parameters_change.slot_iterations;
                maybe_next_parameters_change.take();
            } else {
                start_seed = if best_header.number().is_zero() {
                    pot_verifier.genesis_seed()
                } else {
                    best_pre_digest.pot_info().future_proof_of_time().seed()
                };
                slot_iterations = pot_parameters.slot_iterations();
            }
        }
        #[cfg(not(feature = "pot"))]
        {
            start_slot = Slot::from(1);
            start_seed = pot_verifier.genesis_seed();
            slot_iterations = NonZeroU32::new(100_000_000).expect("Not zero; qed");
        }

        let (timekeeper_checkpoints_sender, timekeeper_checkpoints_receiver) =
            mpsc::channel(LOCAL_PROOFS_CHANNEL_CAPACITY);
        let (slot_sender, slot_receiver) = mpsc::channel(SLOTS_CHANNEL_CAPACITY);
        if is_timekeeper {
            let pot_verifier = pot_verifier.clone();

            thread::Builder::new()
                .name("timekeeper".to_string())
                .spawn(move || {
                    if let Err(error) = run_timekeeper(
                        start_seed,
                        start_slot,
                        slot_iterations,
                        pot_verifier,
                        timekeeper_checkpoints_sender,
                    ) {
                        error!(%error, "Timekeeper exited with an error");
                    }
                })
                .expect("Thread creation must not panic");
        }

        let current_slot_iterations = Arc::new(Atomic::new(slot_iterations));

        let (outgoing_messages_sender, outgoing_messages_receiver) =
            mpsc::channel(GOSSIP_OUTGOING_CHANNEL_CAPACITY);
        let (incoming_messages_sender, incoming_messages_receiver) =
            mpsc::channel(GOSSIP_OUTGOING_CHANNEL_CAPACITY);
        let gossip = PotGossipWorker::new(
            outgoing_messages_receiver,
            incoming_messages_sender,
            pot_verifier,
            Arc::clone(&current_slot_iterations),
            network,
            sync,
        );

        let source = Self {
            client,
            #[cfg(feature = "pot")]
            chain_constants,
            timekeeper_checkpoints_receiver,
            outgoing_messages_sender,
            incoming_messages_receiver,
            slot_sender,
            #[cfg(feature = "pot")]
            current_slot_iterations,
            next_slot_input: NextSlotInput {
                slot: start_slot,
                slot_iterations,
                seed: start_seed,
            },
            #[cfg(feature = "pot")]
            parameters_change: maybe_next_parameters_change,
            _block: PhantomData,
        };

        Ok((source, gossip, PotSlotInfoStream(slot_receiver)))
    }

    /// Run proof of time source
    pub async fn run(mut self) {
        let mut import_notification_stream = self.client.import_notification_stream();

        loop {
            select! {
                // List of blocks that the client has finalized.
                timekeeper_checkpoints = self.timekeeper_checkpoints_receiver.select_next_some() => {
                    self.handle_timekeeper_checkpoints(timekeeper_checkpoints).await;
                }
                // List of blocks that the client has finalized.
                maybe_gossip_checkpoints = self.incoming_messages_receiver.next() => {
                    if let Some((sender, gossip_checkpoints)) = maybe_gossip_checkpoints {
                        self.handle_gossip_checkpoints(sender, gossip_checkpoints).await;
                    } else {
                        debug!("Incoming gossip messages stream ended, exiting");
                        return;
                    }
                }
                maybe_import_notification = import_notification_stream.next() => {
                    if let Some(import_notification) = maybe_import_notification {
                        self.handle_import_notification(import_notification).await;
                    } else {
                        debug!("Import notifications stream ended, exiting");
                        return;
                    }
                }
            }
        }
    }

    async fn handle_timekeeper_checkpoints(
        &mut self,
        timekeeper_checkpoints: TimekeeperCheckpoints,
    ) {
        let TimekeeperCheckpoints {
            seed,
            slot_iterations,
            slot,
            checkpoints,
        } = timekeeper_checkpoints;

        if self
            .outgoing_messages_sender
            .try_send(GossipCheckpoints {
                slot,
                seed,
                slot_iterations,
                checkpoints,
            })
            .is_err()
        {
            debug!(%slot, "Gossip is not able to keep-up with slot production");
        }

        // It doesn't matter if receiver is dropped
        let _ = self
            .slot_sender
            .send(PotSlotInfo { slot, checkpoints })
            .await;

        self.update_next_slot_input(slot, checkpoints.output());
    }

    // TODO: Follow both verified and unverified checkpoints to start secondary timekeeper ASAP in
    //  case verification succeeds
    async fn handle_gossip_checkpoints(
        &mut self,
        _sender: PeerId,
        gossip_checkpoints: GossipCheckpoints,
    ) {
        if gossip_checkpoints.slot == self.next_slot_input.slot
            && gossip_checkpoints.slot_iterations == self.next_slot_input.slot_iterations
            && gossip_checkpoints.seed == self.next_slot_input.seed
        {
            // It doesn't matter if receiver is dropped
            let _ = self
                .slot_sender
                .send(PotSlotInfo {
                    slot: gossip_checkpoints.slot,
                    checkpoints: gossip_checkpoints.checkpoints,
                })
                .await;

            self.update_next_slot_input(
                gossip_checkpoints.slot,
                gossip_checkpoints.checkpoints.output(),
            );
        }
    }

    #[cfg(not(feature = "pot"))]
    async fn handle_import_notification(
        &mut self,
        _import_notification: BlockImportNotification<Block>,
    ) {
    }

    #[cfg(feature = "pot")]
    async fn handle_import_notification(
        &mut self,
        import_notification: BlockImportNotification<Block>,
    ) {
        let pre_digest = match extract_pre_digest(&import_notification.header) {
            Ok(pre_digest) => pre_digest,
            Err(error) => {
                error!(
                    %error,
                    block_number = %import_notification.header.number(),
                    block_hash = %import_notification.hash,
                    "Failed to extract pre-digest from header"
                );
                return;
            }
        };
        let pot_parameters = match self
            .client
            .runtime_api()
            .pot_parameters(import_notification.hash)
        {
            Ok(pot_parameters) => pot_parameters,
            Err(error) => {
                error!(
                    %error,
                    block_number = %import_notification.header.number(),
                    block_hash = %import_notification.hash,
                    "Failed to get proof of time parameters"
                );
                return;
            }
        };

        #[cfg(feature = "pot")]
        self.parameters_change = pot_parameters.next_parameters_change();

        let best_slot = pre_digest.slot() + self.chain_constants.block_authoring_delay();

        // In case block import is ahead of timekeeper and gossip, update next slot input
        if best_slot + Slot::from(1) >= self.next_slot_input.slot {
            self.update_next_slot_input(best_slot, pre_digest.pot_info().future_proof_of_time());
        }
    }

    fn update_next_slot_input(&mut self, best_slot: Slot, best_proof: PotProof) {
        let next_slot = best_slot + Slot::from(1);
        let next_slot_iterations;
        let next_seed;

        #[cfg(feature = "pot")]
        // The change to number of iterations might have happened before `next_slot`
        if let Some(parameters_change) = self.parameters_change
            && parameters_change.slot <= next_slot
        {
            next_slot_iterations = parameters_change.slot_iterations;
            // Only if entropy injection happens on this exact slot we need to mix it in
            if parameters_change.slot == next_slot {
                next_seed = best_proof.seed_with_entropy(&parameters_change.entropy);

                self.parameters_change.take();
            } else {
                next_seed = best_proof.seed();
            }
        } else {
            next_slot_iterations = self.next_slot_input.slot_iterations;
            next_seed = best_proof.seed();
        }
        #[cfg(not(feature = "pot"))]
        {
            next_slot_iterations = self.next_slot_input.slot_iterations;
            next_seed = best_proof.seed();
        }

        self.next_slot_input = NextSlotInput {
            slot: next_slot,
            slot_iterations: next_slot_iterations,
            seed: next_seed,
        };
        #[cfg(feature = "pot")]
        self.current_slot_iterations
            .store(self.next_slot_input.slot_iterations, Ordering::Relaxed);

        // TODO: Try to get higher time slot using verifier, we are behind and need to catch up
        //  and may have already received newer proofs via gossip
    }
}

/// Runs timekeeper, must be running on a fast dedicated CPU core
fn run_timekeeper(
    mut seed: PotSeed,
    slot: Slot,
    slot_iterations: NonZeroU32,
    pot_verifier: PotVerifier,
    mut proofs_sender: mpsc::Sender<TimekeeperCheckpoints>,
) -> Result<(), PotError> {
    let mut slot = SlotNumber::from(slot);
    loop {
        let checkpoints = subspace_proof_of_time::prove(seed, slot_iterations)?;

        pot_verifier.inject_verified_checkpoints(seed, slot_iterations, checkpoints);

        let slot_info = TimekeeperCheckpoints {
            seed,
            slot_iterations,
            slot: Slot::from(slot),
            checkpoints,
        };

        seed = checkpoints.output().seed();

        if let Err(error) = proofs_sender.try_send(slot_info) {
            if let Err(error) = block_on(proofs_sender.send(error.into_inner())) {
                debug!(%error, "Couldn't send checkpoints, channel is closed");
                return Ok(());
            }
        }

        slot += 1;
    }
}
