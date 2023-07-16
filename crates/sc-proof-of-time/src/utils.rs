//! Common utils.

use parity_scale_codec::Decode;
use parking_lot::RwLock;
use sc_network::PeerId;
use sc_network_gossip::{MessageIntent, ValidationResult, Validator, ValidatorContext};
use sp_core::twox_256;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use std::collections::HashSet;
use subspace_core_primitives::PotProof;

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
