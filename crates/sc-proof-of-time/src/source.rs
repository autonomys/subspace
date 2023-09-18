pub mod gossip;
mod state;
mod timekeeper;

use crate::source::gossip::{GossipProof, PotGossipWorker, ToGossipMessage};
use crate::source::state::{NextSlotInput, PotState};
use crate::source::timekeeper::{run_timekeeper, TimekeeperProof};
use crate::verifier::PotVerifier;
use derive_more::{Deref, DerefMut};
use futures::channel::mpsc;
use futures::{select, StreamExt};
use sc_client_api::BlockchainEvents;
use sc_network::PeerId;
use sc_network_gossip::{Network as GossipNetwork, Syncing as GossipSyncing};
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_consensus_slots::Slot;
#[cfg(feature = "pot")]
use sp_consensus_subspace::digests::extract_pre_digest;
#[cfg(feature = "pot")]
use sp_consensus_subspace::digests::extract_subspace_digest_items;
#[cfg(feature = "pot")]
use sp_consensus_subspace::ChainConstants;
#[cfg(feature = "pot")]
use sp_consensus_subspace::FarmerSignature;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi as SubspaceRuntimeApi};
use sp_runtime::traits::Block as BlockT;
#[cfg(feature = "pot")]
use sp_runtime::traits::Header as HeaderT;
#[cfg(feature = "pot")]
use sp_runtime::traits::Zero;
use std::marker::PhantomData;
#[cfg(not(feature = "pot"))]
use std::num::NonZeroU32;
use std::sync::Arc;
use std::thread;
use subspace_core_primitives::PotCheckpoints;
#[cfg(feature = "pot")]
use tracing::warn;
use tracing::{debug, error};

const LOCAL_PROOFS_CHANNEL_CAPACITY: usize = 10;
const SLOTS_CHANNEL_CAPACITY: usize = 10;
const GOSSIP_OUTGOING_CHANNEL_CAPACITY: usize = 10;
const GOSSIP_INCOMING_CHANNEL_CAPACITY: usize = 10;

/// Proof of time slot information
pub struct PotSlotInfo {
    /// Slot number
    pub slot: Slot,
    /// Proof of time checkpoints
    pub checkpoints: PotCheckpoints,
}

/// Stream with proof of time slots
#[derive(Debug, Deref, DerefMut)]
pub struct PotSlotInfoStream(mpsc::Receiver<PotSlotInfo>);

/// Worker producing proofs of time.
///
/// Depending on configuration may produce proofs of time locally, send/receive via gossip and keep
/// up to day with blockchain reorgs.
#[derive(Debug)]
#[must_use = "Proof of time source doesn't do anything unless run() method is called"]
pub struct PotSourceWorker<Block, Client> {
    client: Arc<Client>,
    #[cfg(feature = "pot")]
    chain_constants: ChainConstants,
    timekeeper_proofs_receiver: mpsc::Receiver<TimekeeperProof>,
    to_gossip_sender: mpsc::Sender<ToGossipMessage>,
    from_gossip_receiver: mpsc::Receiver<(PeerId, GossipProof)>,
    slot_sender: mpsc::Sender<PotSlotInfo>,
    state: Arc<PotState>,
    _block: PhantomData<Block>,
}

impl<Block, Client> PotSourceWorker<Block, Client>
where
    Block: BlockT,
    Client: BlockchainEvents<Block> + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: SubspaceRuntimeApi<Block, FarmerPublicKey>,
{
    pub fn new<Network, GossipSync, SO>(
        is_timekeeper: bool,
        client: Arc<Client>,
        pot_verifier: PotVerifier,
        network: Network,
        sync: Arc<GossipSync>,
        sync_oracle: SO,
    ) -> Result<(Self, PotGossipWorker<Block>, PotSlotInfoStream), ApiError>
    where
        Network: GossipNetwork<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
        SO: SyncOracle + Send + Sync + 'static,
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

        let state = Arc::new(PotState::new(
            NextSlotInput {
                slot: start_slot,
                slot_iterations,
                seed: start_seed,
            },
            #[cfg(feature = "pot")]
            maybe_next_parameters_change,
            pot_verifier.clone(),
        ));

        let (timekeeper_proofs_sender, timekeeper_proofs_receiver) =
            mpsc::channel(LOCAL_PROOFS_CHANNEL_CAPACITY);
        let (slot_sender, slot_receiver) = mpsc::channel(SLOTS_CHANNEL_CAPACITY);
        if is_timekeeper {
            let state = Arc::clone(&state);
            let pot_verifier = pot_verifier.clone();

            thread::Builder::new()
                .name("timekeeper".to_string())
                .spawn(move || {
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
            sync,
            sync_oracle,
        );

        let source_worker = Self {
            client,
            #[cfg(feature = "pot")]
            chain_constants,
            timekeeper_proofs_receiver,
            to_gossip_sender,
            from_gossip_receiver,
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

        // We don't care if block production is too slow or block production is not enabled on this
        // node at all
        let _ = self.slot_sender.try_send(PotSlotInfo { slot, checkpoints });
    }

    // TODO: Follow both verified and unverified checkpoints to start secondary timekeeper ASAP in
    //  case verification succeeds
    fn handle_gossip_proof(&mut self, _sender: PeerId, proof: GossipProof) {
        let expected_next_slot_input = NextSlotInput {
            slot: proof.slot,
            slot_iterations: proof.slot_iterations,
            seed: proof.seed,
        };

        if let Ok(next_slot_input) = self.state.try_extend(
            expected_next_slot_input,
            proof.slot,
            proof.checkpoints.output(),
            #[cfg(feature = "pot")]
            None,
        ) {
            // We don't care if block production is too slow or block production is not enabled on
            // this node at all
            let _ = self.slot_sender.try_send(PotSlotInfo {
                slot: proof.slot,
                checkpoints: proof.checkpoints,
            });

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

    #[cfg(not(feature = "pot"))]
    fn handle_block_import_notification(
        &mut self,
        _block_hash: Block::Hash,
        _header: &Block::Header,
    ) {
    }

    #[cfg(feature = "pot")]
    fn handle_block_import_notification(
        &mut self,
        block_hash: Block::Hash,
        header: &Block::Header,
    ) {
        let subspace_digest_items = match extract_subspace_digest_items::<
            Block::Header,
            FarmerPublicKey,
            FarmerPublicKey,
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
        //   correct fork
        // * if block import is on the same PoT chain this will essentially do nothing
        if let Some(next_slot_input) = self.state.update(
            best_slot,
            best_proof,
            #[cfg(feature = "pot")]
            Some(subspace_digest_items.pot_parameters_change),
        ) {
            warn!("Proof of time chain reorg happened");

            if self
                .to_gossip_sender
                .try_send(ToGossipMessage::NextSlotInput(next_slot_input))
                .is_err()
            {
                debug!(
                    next_slot = %next_slot_input.slot,
                    "Gossip is not able to keep-up with slot production (block import)",
                );
            }
        }
    }
}
