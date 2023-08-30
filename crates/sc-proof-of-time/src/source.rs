use derive_more::{Deref, DerefMut, From};
use futures::channel::mpsc;
use futures::executor::block_on;
use futures::SinkExt;
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{FarmerPublicKey, SubspaceApi as SubspaceRuntimeApi};
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::thread;
use subspace_core_primitives::{PotCheckpoints, PotSeed, SlotNumber};
use subspace_proof_of_time::PotError;
use tracing::{debug, error};

/// Proof of time slot information
pub struct PotSlotInfo {
    /// Slot number
    pub slot: Slot,
    /// Proof of time checkpoints
    pub checkpoints: PotCheckpoints,
}

/// Stream with proof of time slots
#[derive(Debug, Deref, DerefMut, From)]
pub struct PotSlotInfoStream(mpsc::Receiver<PotSlotInfo>);

/// Configuration for proof of time source
#[derive(Debug, Clone)]
pub struct PotSourceConfig {
    /// Is this node a Timekeeper
    pub is_timekeeper: bool,
    /// External entropy, used initially when PoT chain starts to derive the first seed
    pub external_entropy: Vec<u8>,
}

/// Source of proofs of time.
///
/// Depending on configuration may produce proofs of time locally, send/receive via gossip and keep
/// up to day with blockchain reorgs.
#[derive(Debug)]
pub struct PotSource<Block, Client> {
    // TODO: Use this in `fn run`
    #[allow(dead_code)]
    client: Arc<Client>,
    _block: PhantomData<Block>,
}

impl<Block, Client> PotSource<Block, Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: SubspaceRuntimeApi<Block, FarmerPublicKey>,
{
    pub fn new(
        config: PotSourceConfig,
        client: Arc<Client>,
    ) -> Result<(Self, PotSlotInfoStream), ApiError> {
        let PotSourceConfig {
            // TODO: Respect this boolean flag
            is_timekeeper: _,
            external_entropy,
        } = config;
        let info = client.info();
        // TODO: All 3 are incorrect and should be able to continue after node restart
        let start_slot = SlotNumber::MIN;
        let start_seed = PotSeed::from_genesis(info.genesis_hash.as_ref(), &external_entropy);
        #[cfg(feature = "pot")]
        let best_hash = info.best_hash;
        #[cfg(feature = "pot")]
        let runtime_api = client.runtime_api();
        #[cfg(feature = "pot")]
        let iterations = runtime_api
            .pot_parameters(best_hash)?
            .iterations(Slot::from(start_slot));
        #[cfg(not(feature = "pot"))]
        let iterations = NonZeroU32::new(100_000_000).expect("Not zero; qed");

        // TODO: Correct capacity
        let (slot_sender, slot_receiver) = mpsc::channel(10);
        thread::Builder::new()
            .name("timekeeper".to_string())
            .spawn(move || {
                if let Err(error) = run_timekeeper(start_seed, start_slot, iterations, slot_sender)
                {
                    error!(%error, "Timekeeper exited with an error");
                }
            })
            .expect("Thread creation must not panic");

        Ok((
            Self {
                client,
                _block: PhantomData,
            },
            PotSlotInfoStream(slot_receiver),
        ))
    }

    /// Run proof of time source
    pub async fn run(self) {
        // TODO: Aggregate multiple sources of proofs of time (multiple timekeepers, gossip,
        //  blockchain itself)
        std::future::pending().await
    }
}

/// Runs timekeeper, must be running on a fast dedicated CPU core
fn run_timekeeper(
    mut seed: PotSeed,
    mut slot: SlotNumber,
    iterations: NonZeroU32,
    mut slot_sender: mpsc::Sender<PotSlotInfo>,
) -> Result<(), PotError> {
    loop {
        let checkpoints = subspace_proof_of_time::prove(seed, iterations)?;

        seed = checkpoints.output().seed();

        let slot_info = PotSlotInfo {
            slot: Slot::from(slot),
            checkpoints,
        };

        if let Err(error) = slot_sender.try_send(slot_info) {
            if let Err(error) = block_on(slot_sender.send(error.into_inner())) {
                debug!(%error, "Couldn't send checkpoints, channel is closed");
                return Ok(());
            }
        }

        slot += 1;
    }
}
