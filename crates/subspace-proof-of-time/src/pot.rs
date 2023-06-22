//! Common defines.

use sp_core::{Blake2Hasher, Hasher, H256};
use std::ops::BitXor;

/// The 128 bit key for the AES encryption.
#[derive(Clone, Debug)]
pub struct AesKey(pub [u8; 16]);

impl From<&AesSeed> for AesKey {
    fn from(seed: &AesSeed) -> AesKey {
        Self(h256_to_arr(Blake2Hasher::hash(&seed.0)))
    }
}

/// Input to AES.
#[derive(Clone, Debug)]
pub struct AesSeed(pub [u8; 16]);

impl From<H256> for AesSeed {
    fn from(hash: H256) -> Self {
        Self(h256_to_arr(hash))
    }
}

/// Output from AES.
#[derive(Clone, Debug)]
pub struct AesCipherText(pub [u8; 16]);

/// Config params for PoT.
#[derive(Debug)]
pub struct PotConfig {
    /// Frequency of entropy injection from consensus.
    pub randomness_update_interval_blocks: u32,

    /// Starting point for entropy injection from consensus.
    pub injection_depth_blocks: u32,

    /// Number of slots it takes for updated global randomness to
    /// take effect.
    pub global_randomness_reveal_lag_slots: u32,

    /// Number of slots it takes for injected randomness to
    /// take effect.
    pub pot_injection_lag_slots: u32,

    /// Number of checkpoints per proof.
    pub num_checkpoints: u32,

    /// Number of EAS iterations per checkpoints.
    /// Total iterations per proof = num_checkpoints * checkpoint_iterations.
    pub checkpoint_iterations: u32,
}

/// Proof of time.
/// TODO: versioning.
#[derive(Debug)]
pub struct ProofOfTime {
    /// Slot the proof was evaluated for.
    pub slot_number: u32,

    /// The seed used for evaluation.
    pub seed: AesSeed,

    /// The actual cipher output from each stage.
    pub checkpoints: Vec<AesCipherText>,

    /// Hash of last block at injection point.
    pub injected_block_hash: H256,
}

impl ProofOfTime {
    pub fn output(&self) -> AesCipherText {
        self.checkpoints
            .last()
            .cloned()
            .expect("Invalid proof of time")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProofOfTimeError {
    #[error("Unexpected number of checkpoints: {expected}, {actual}")]
    CheckpointMismatch { expected: u32, actual: u32 },
}

/// Converts H256 -> [u8; 16]
pub fn h256_to_arr(hash: H256) -> [u8; 16] {
    let hash = hash.to_fixed_bytes();

    let mut h: [u8; 16] = Default::default();
    h.copy_from_slice(&hash[0..16]);
    let h = u128::from_be_bytes(h);

    let mut l: [u8; 16] = Default::default();
    l.copy_from_slice(&hash[16..32]);
    let l = u128::from_be_bytes(l);

    let r = h.bitxor(&l);
    r.to_be_bytes()
}
