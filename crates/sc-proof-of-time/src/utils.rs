//! Common utils.

use parity_scale_codec::Decode;
use parking_lot::{Mutex, RwLock};
use sc_network::PeerId;
use sc_network_gossip::{
    GossipEngine, MessageIntent, Syncing as GossipSyncing, ValidationResult, Validator,
    ValidatorContext,
};
use sp_blockchain::{HeaderBackend, Info};
use sp_consensus::SyncOracle;
use sp_consensus_subspace::digests::extract_pre_digest;
use sp_core::twox_256;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT, Zero};
use std::collections::HashSet;
use std::sync::Arc;
use subspace_core_primitives::{NonEmptyVec, PotProof};
use tracing::info;

pub(crate) const GOSSIP_PROTOCOL: &str = "/subspace/subspace-proof-of-time";
pub(crate) const LOG_TARGET: &str = "subspace-proof-of-time";

type MessageHash = [u8; 32];

/// PoT message topic.
pub(crate) fn topic<Block: BlockT>() -> Block::Hash {
    <<Block::Header as HeaderT>::Hashing as HashT>::hash(b"subspace-proof-of-time-gossip")
}

/// Validator for gossiped messages
#[derive(Debug)]
pub(crate) struct PotGossipVaidator {
    pending: RwLock<HashSet<MessageHash>>,
}

impl PotGossipVaidator {
    /// Creates the validator.
    pub(crate) fn new() -> Self {
        Self {
            pending: RwLock::new(HashSet::new()),
        }
    }

    /// Called when the message is broadcast.
    pub(crate) fn on_broadcast(&self, msg: &[u8]) {
        let hash = twox_256(msg);
        let mut pending = self.pending.write();
        pending.insert(hash);
    }
}

impl<Block: BlockT> Validator<Block> for PotGossipVaidator {
    fn validate(
        &self,
        _context: &mut dyn ValidatorContext<Block>,
        _sender: &PeerId,
        mut data: &[u8],
    ) -> ValidationResult<Block::Hash> {
        match PotProof::decode(&mut data) {
            Ok(_) => ValidationResult::ProcessAndKeep(topic::<Block>()),
            Err(_) => ValidationResult::Discard,
        }
    }

    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_topic, data| {
            let hash = twox_256(data);
            let pending = self.pending.read();
            !pending.contains(&hash)
        })
    }

    fn message_allowed<'a>(
        &'a self,
    ) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_who, _intent, _topic, data| {
            let hash = twox_256(data);
            let mut pending = self.pending.write();
            if pending.contains(&hash) {
                pending.remove(&hash);
                true
            } else {
                false
            }
        })
    }
}

/// PoT gossip components.
#[derive(Clone)]
pub struct PotGossip<Block: BlockT> {
    pub(crate) engine: Arc<Mutex<GossipEngine<Block>>>,
    pub(crate) validator: Arc<PotGossipVaidator>,
}

impl<Block: BlockT> PotGossip<Block> {
    pub fn new<Network, GossipSync>(network: Network, sync: Arc<GossipSync>) -> Self
    where
        Network: sc_network_gossip::Network<Block> + Send + Sync + Clone + 'static,
        GossipSync: GossipSyncing<Block> + 'static,
    {
        let validator = Arc::new(PotGossipVaidator::new());
        let engine = Arc::new(Mutex::new(GossipEngine::new(
            network,
            sync,
            GOSSIP_PROTOCOL,
            validator.clone(),
            None,
        )));
        Self { engine, validator }
    }
}

/// Helper to retrieve the PoT state from latest tip.
pub(crate) async fn get_consensus_tip_proofs<Block, Client, SO>(
    client: Arc<Client>,
    sync_oracle: Arc<SO>,
    chain_info_fn: Arc<dyn Fn() -> Info<Block> + Send + Sync>,
) -> Result<NonEmptyVec<PotProof>, String>
where
    Block: BlockT,
    Client: HeaderBackend<Block>,
    SO: SyncOracle + Send + Sync + Clone + 'static,
{
    // Wait for sync to complete
    let delay = tokio::time::Duration::from_secs(1);
    info!("get_consensus_tip_proofs(): waiting for sync to complete ...");
    let info = loop {
        while sync_oracle.is_major_syncing() {
            tokio::time::sleep(delay).await;
        }

        // Get the hdr of the best block hash
        let info = (chain_info_fn)();
        if !info.best_number.is_zero() {
            break info;
        }
        info!("get_consensus_tip_proofs(): chain_info: {info:?}, to retry ...");
        tokio::time::sleep(delay).await;
    };

    let header = client
        .header(info.best_hash)
        .map_err(|err| format!("get_consensus_tip_proofs(): failed to get hdr: {err:?}, {info:?}"))?
        .ok_or(format!("get_consensus_tip_proofs(): missing hdr: {info:?}"))?;

    // Get the pre-digest from the block hdr
    let pre_digest = extract_pre_digest(&header).map_err(|err| {
        format!("get_consensus_tip_proofs(): failed to get pre digest: {err:?}, {info:?}")
    })?;

    info!(
        "get_consensus_tip_proofs(): {info:?}, pre_digest: slot = {}, num_proofs = {}",
        pre_digest.slot,
        pre_digest.proof_of_time.len()
    );
    NonEmptyVec::new(pre_digest.proof_of_time).map_err(|err| format!("{err:?}"))
}
