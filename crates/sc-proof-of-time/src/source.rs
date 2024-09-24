pub mod gossip;
mod state;
mod timekeeper;

use crate::source::gossip::{GossipProof, PotGossipWorker, ToGossipMessage};
use crate::source::state::{PotState, PotStateUpdateOutcome};
use crate::source::timekeeper::{run_timekeeper, TimekeeperProof};
use crate::verifier::PotVerifier;
use core_affinity::CoreId;
use derive_more::{Deref, DerefMut};
use futures::channel::mpsc;
use futures::{select, StreamExt};
use sc_client_api::BlockchainEvents;
use sc_network::{NotificationService, PeerId};
use sc_network_gossip::{Network as GossipNetwork, Syncing as GossipSyncing};
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{extract_pre_digest, extract_subspace_digest_items};
use sp_consensus_subspace::{
    ChainConstants, FarmerSignature, PotNextSlotInput, SubspaceApi as SubspaceRuntimeApi,
};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, Zero};
use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::Arc;
use std::thread;
use subspace_core_primitives::{PotCheckpoints, PublicKey};
use thread_priority::{set_current_thread_priority, ThreadPriority};
use tokio::sync::broadcast;
use tracing::{debug, error, trace, warn};

const LOCAL_PROOFS_CHANNEL_CAPACITY: usize = 10;
const SLOTS_CHANNEL_CAPACITY: usize = 10;
const GOSSIP_OUTGOING_CHANNEL_CAPACITY: usize = 10;
const GOSSIP_INCOMING_CHANNEL_CAPACITY: usize = 10;

/// Proof of time slot information
#[derive(Clone)]
pub struct PotSlotInfo {
    /// Slot number
    pub slot: Slot,
    /// Proof of time checkpoints
    pub checkpoints: PotCheckpoints,
}

/// Stream with proof of time slots
#[derive(Debug, Deref, DerefMut)]
pub struct PotSlotInfoStream(broadcast::Receiver<PotSlotInfo>);

/// Worker producing proofs of time.
///
/// Depending on configuration may produce proofs of time locally, send/receive via gossip and keep
/// up to day with blockchain reorgs.
#[derive(Debug)]
#[must_use = "Proof of time source doesn't do anything unless run() method is called"]
pub struct PotSourceWorker<Block, Client, SO> {
    client: Arc<Client>,
    sync_oracle: SO,
    chain_constants: ChainConstants,
    timekeeper_proofs_receiver: mpsc::Receiver<TimekeeperProof>,
    to_gossip_sender: mpsc::Sender<ToGossipMessage>,
    from_gossip_receiver: mpsc::Receiver<(PeerId, GossipProof)>,
    last_slot_sent: Slot,
    slot_sender: broadcast::Sender<PotSlotInfo>,
    state: Arc<PotState>,
    _block: PhantomData<Block>,
}

impl<Block, Client, SO> PotSourceWorker<Block, Client, SO>
where
    Block: BlockT,
    Client: BlockchainEvents<Block> + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: SubspaceRuntimeApi<Block, PublicKey>,
    SO: SyncOracle + Clone + Send + Sync + 'static,
{
    // TODO: Struct for arguments
    #[allow(clippy::too_many_arguments)]
    pub fn new<Network, GossipSync>(
        is_timekeeper: bool,
        timekeeper_cpu_cores: HashSet<usize>,
        client: Arc<Client>,
        pot_verifier: PotVerifier,
        network: Network,
        notification_service: Box<dyn NotificationService>,
        sync: Arc<GossipSync>,
        sync_oracle: SO,
    ) -> Result<(Self, PotGossipWorker<Block>, PotSlotInfoStream), ApiError>
    where
        Network: GossipNetwork<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
    {
        let best_hash = client.info().best_hash;
        let runtime_api = client.runtime_api();
        let chain_constants = runtime_api.chain_constants(best_hash)?;

        let best_header = client
            .header(best_hash)?
            .ok_or_else(|| ApiError::UnknownBlock(format!("Parent block {best_hash} not found")))?;
        let best_pre_digest = extract_pre_digest(&best_header)
            .map_err(|error| ApiError::Application(error.into()))?;

        let parent_slot = if best_header.number().is_zero() {
            Slot::from(0)
        } else {
            // The best one seen
            best_pre_digest.slot() + chain_constants.block_authoring_delay()
        };

        let pot_parameters = runtime_api.pot_parameters(best_hash)?;
        let maybe_next_parameters_change = pot_parameters.next_parameters_change();

        let pot_input = if best_header.number().is_zero() {
            PotNextSlotInput {
                slot: parent_slot + Slot::from(1),
                slot_iterations: pot_parameters.slot_iterations(),
                seed: pot_verifier.genesis_seed(),
            }
        } else {
            PotNextSlotInput::derive(
                pot_parameters.slot_iterations(),
                parent_slot,
                best_pre_digest.pot_info().future_proof_of_time(),
                &maybe_next_parameters_change,
            )
        };

        let state = Arc::new(PotState::new(
            pot_input,
            maybe_next_parameters_change,
            pot_verifier.clone(),
        ));

        let (timekeeper_proofs_sender, timekeeper_proofs_receiver) =
            mpsc::channel(LOCAL_PROOFS_CHANNEL_CAPACITY);
        let (slot_sender, slot_receiver) = broadcast::channel(SLOTS_CHANNEL_CAPACITY);
        if is_timekeeper {
            let state = Arc::clone(&state);
            let pot_verifier = pot_verifier.clone();

            thread::Builder::new()
                .name("timekeeper".to_string())
                .spawn(move || {
                    if let Some(core) = timekeeper_cpu_cores.into_iter().next() {
                        if !core_affinity::set_for_current(CoreId { id: core }) {
                            warn!(
                                %core,
                                "Failed to set core affinity, timekeeper will run on random CPU \
                                core",
                            );
                        }
                    }

                    if let Err(error) = set_current_thread_priority(ThreadPriority::Max) {
                        warn!(
                            %error,
                            "Failed to set thread priority, timekeeper performance may be \
                            negatively impacted by other software running on this machine",
                        );
                    }

                    if let Err(error) =
                        run_timekeeper(state, pot_verifier, timekeeper_proofs_sender)
                    {
                        error!(%error, "Timekeeper exited with an error");
                    }
                })
                .expect("Thread creation must not panic");
        }

        let (to_gossip_sender, to_gossip_receiver) =
            mpsc::channel(GOSSIP_OUTGOING_CHANNEL_CAPACITY);
        let (from_gossip_sender, from_gossip_receiver) =
            mpsc::channel(GOSSIP_INCOMING_CHANNEL_CAPACITY);
        let gossip_worker = PotGossipWorker::new(
            to_gossip_receiver,
            from_gossip_sender,
            pot_verifier,
            Arc::clone(&state),
            network,
            notification_service,
            sync,
            sync_oracle.clone(),
        );

        let source_worker = Self {
            client,
            sync_oracle,
            chain_constants,
            timekeeper_proofs_receiver,
            to_gossip_sender,
            from_gossip_receiver,
            last_slot_sent: Slot::from(0),
            slot_sender,
            state,
            _block: PhantomData,
        };

        let pot_slot_info_stream = PotSlotInfoStream(slot_receiver);

        Ok((source_worker, gossip_worker, pot_slot_info_stream))
    }

    /// Run proof of time source
    pub async fn run(mut self) {
        let mut import_notification_stream = self.client.import_notification_stream();

        loop {
            select! {
                // List of blocks that the client has finalized.
                timekeeper_proof = self.timekeeper_proofs_receiver.select_next_some() => {
                    self.handle_timekeeper_proof(timekeeper_proof);
                }
                // List of blocks that the client has finalized.
                maybe_gossip_proof = self.from_gossip_receiver.next() => {
                    if let Some((sender, gossip_proof)) = maybe_gossip_proof {
                        self.handle_gossip_proof(sender, gossip_proof);
                    } else {
                        debug!("Incoming gossip messages stream ended, exiting");
                        return;
                    }
                }
                maybe_import_notification = import_notification_stream.next() => {
                    if let Some(import_notification) = maybe_import_notification {
                        if !import_notification.is_new_best {
                            // Ignore blocks that don't extend the chain
                            continue;
                        }
                        self.handle_block_import_notification(
                            import_notification.hash,
                            &import_notification.header,
                        );
                    } else {
                        debug!("Import notifications stream ended, exiting");
                        return;
                    }
                }
            }
        }
    }

    fn handle_timekeeper_proof(&mut self, proof: TimekeeperProof) {
        let TimekeeperProof {
            slot,
            seed,
            slot_iterations,
            checkpoints,
        } = proof;

        if self.sync_oracle.is_major_syncing() {
            trace!(
                ?slot,
                %seed,
                %slot_iterations,
                output = %checkpoints.output(),
                "Ignore timekeeper proof due to major syncing",
            );

            return;
        }

        debug!(
            ?slot,
            %seed,
            %slot_iterations,
            output = %checkpoints.output(),
            "Received timekeeper proof",
        );

        if self
            .to_gossip_sender
            .try_send(ToGossipMessage::Proof(GossipProof {
                slot,
                seed,
                slot_iterations,
                checkpoints,
            }))
            .is_err()
        {
            debug!(
                %slot,
                "Gossip is not able to keep-up with slot production (timekeeper)",
            );
        }

        if slot > self.last_slot_sent {
            self.last_slot_sent = slot;

            // We don't care if block production is too slow or block production is not enabled on this
            // node at all
            let _ = self.slot_sender.send(PotSlotInfo { slot, checkpoints });
        }
    }

    // TODO: Follow both verified and unverified checkpoints to start secondary timekeeper ASAP in
    //  case verification succeeds
    fn handle_gossip_proof(&mut self, _sender: PeerId, proof: GossipProof) {
        let expected_next_slot_input = PotNextSlotInput {
            slot: proof.slot,
            slot_iterations: proof.slot_iterations,
            seed: proof.seed,
        };

        if let Ok(next_slot_input) = self.state.try_extend(
            expected_next_slot_input,
            proof.slot,
            proof.checkpoints.output(),
            None,
        ) {
            if proof.slot > self.last_slot_sent {
                self.last_slot_sent = proof.slot;

                // We don't care if block production is too slow or block production is not enabled on
                // this node at all
                let _ = self.slot_sender.send(PotSlotInfo {
                    slot: proof.slot,
                    checkpoints: proof.checkpoints,
                });
            }

            if self
                .to_gossip_sender
                .try_send(ToGossipMessage::NextSlotInput(next_slot_input))
                .is_err()
            {
                debug!(
                    slot = %proof.slot,
                    next_slot = %next_slot_input.slot,
                    "Gossip is not able to keep-up with slot production (gossip)",
                );
            }
        }
    }

    fn handle_block_import_notification(
        &mut self,
        block_hash: Block::Hash,
        header: &Block::Header,
    ) {
        let subspace_digest_items = match extract_subspace_digest_items::<
            Block::Header,
            PublicKey,
            FarmerSignature,
        >(header)
        {
            Ok(pre_digest) => pre_digest,
            Err(error) => {
                error!(
                    %error,
                    block_number = %header.number(),
                    %block_hash,
                    "Failed to extract Subspace digest items from header"
                );
                return;
            }
        };

        let best_slot =
            subspace_digest_items.pre_digest.slot() + self.chain_constants.block_authoring_delay();
        let best_proof = subspace_digest_items
            .pre_digest
            .pot_info()
            .future_proof_of_time();

        // This will do one of 3 things depending on circumstances:
        // * if block import is ahead of timekeeper and gossip, it will update next slot input
        // * if block import is on a different PoT chain, it will update next slot input to the
        //   correct fork (reorg)
        // * if block import is on the same PoT chain this will essentially do nothing
        match self.state.update(
            best_slot,
            best_proof,
            Some(subspace_digest_items.pot_parameters_change),
        ) {
            PotStateUpdateOutcome::NoChange => {
                trace!(
                    %best_slot,
                    "Block import didn't result in proof of time chain changes",
                );
            }
            PotStateUpdateOutcome::Extension { from, to } => {
                warn!(
                    from_next_slot = %from.slot,
                    to_next_slot = %to.slot,
                    "Proof of time chain was extended from block import",
                );

                if self
                    .to_gossip_sender
                    .try_send(ToGossipMessage::NextSlotInput(to))
                    .is_err()
                {
                    debug!(
                        next_slot = %to.slot,
                        "Gossip is not able to keep-up with slot production (block import)",
                    );
                }
            }
            PotStateUpdateOutcome::Reorg { from, to } => {
                warn!(
                    from_next_slot = %from.slot,
                    to_next_slot = %to.slot,
                    "Proof of time chain reorg happened",
                );

                if self
                    .to_gossip_sender
                    .try_send(ToGossipMessage::NextSlotInput(to))
                    .is_err()
                {
                    debug!(
                        next_slot = %to.slot,
                        "Gossip is not able to keep-up with slot production (block import)",
                    );
                }
            }
        }
    }

    /// Subscribe to pot slot notifications.
    pub fn subscribe_pot_slot_info_stream(&self) -> broadcast::Receiver<PotSlotInfo> {
        self.slot_sender.subscribe()
    }
}
