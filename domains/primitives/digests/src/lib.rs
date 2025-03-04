#![cfg_attr(not(feature = "std"), no_std)]

use parity_scale_codec::{Decode, Encode};
use sp_runtime::{ConsensusEngineId, DigestItem};

const DOMAIN_REGISTRY_ENGINE_ID: ConsensusEngineId = *b"RGTR";

/// Trait to provide simpler abstractions to create predigests for runtime.
pub trait AsPredigest {
    /// Return `consensus_block_hash`
    fn as_consensus_block_info<Hash: Decode>(&self) -> Option<Hash>;

    /// Creates a new digest of the consensus block that derive the domain block.
    fn consensus_block_info<Hash: Encode>(consensus_block_hash: Hash) -> Self;
}

impl AsPredigest for DigestItem {
    fn as_consensus_block_info<Hash: Decode>(&self) -> Option<Hash> {
        self.pre_runtime_try_to(&DOMAIN_REGISTRY_ENGINE_ID)
    }

    fn consensus_block_info<Hash: Encode>(consensus_block_hash: Hash) -> Self {
        DigestItem::PreRuntime(DOMAIN_REGISTRY_ENGINE_ID, consensus_block_hash.encode())
    }
}
