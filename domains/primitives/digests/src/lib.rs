#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use sp_runtime::{ConsensusEngineId, DigestItem};

const DOMAIN_REGISTRY_ENGINE_ID: ConsensusEngineId = *b"RGTR";

/// Trait to provide simpler abstractions to create predigests for runtime.
pub trait AsPredigest {
    /// Return a pair of (primary_block_number, primary_block_hash).
    fn as_primary_block_info<Number: Decode, Hash: Decode>(&self) -> Option<(Number, Hash)>;

    /// Creates a new digest of primary block info for system domain.
    fn primary_block_info<Number: Encode, Hash: Encode>(info: (Number, Hash)) -> Self;
}

impl AsPredigest for DigestItem {
    /// Return a pair of (primary_block_number, primary_block_hash).
    fn as_primary_block_info<Number: Decode, Hash: Decode>(&self) -> Option<(Number, Hash)> {
        self.pre_runtime_try_to(&DOMAIN_REGISTRY_ENGINE_ID)
    }

    fn primary_block_info<Number: Encode, Hash: Encode>(info: (Number, Hash)) -> Self {
        DigestItem::PreRuntime(DOMAIN_REGISTRY_ENGINE_ID, info.encode())
    }
}
