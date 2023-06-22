//! Clock maker related functionality.

use crate::aes::AESWrapper;
use crate::pot::{AesKey, AesSeed, PotConfig, ProofOfTime};
use sc_client_api::BlockImportNotification;
use sp_core::{Blake2Hasher, Hasher, H256};
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};

pub const INITIAL_KEY: [u8; 16] = [
    0x9a, 0x84, 0x94, 0x0f, 0xfe, 0xf5, 0xb0, 0xd7, 0x01, 0x99, 0xfc, 0x67, 0xf4, 0x6e, 0xa2, 0x7a,
];

pub struct ClockMakerImpl<Block> {
    /// Proof of time config.
    config: PotConfig,

    /// AES helper.
    aes: AESWrapper,

    /// Last proof produced by us.
    last_proof: ProofOfTime,

    /// Pending entropy update from consensus chain.
    /// (future slot number at which to update, block hash to inject).
    pending_update: Option<(u32, H256)>,

    _p: std::marker::PhantomData<Block>,
}

impl<Block> ClockMakerImpl<Block>
where
    Block: BlockT,
    Block::Hash: Into<H256>,
{
    /// Creates the clock maker.
    pub fn new(config: PotConfig, genesis_block_hash: Block::Hash) -> Self {
        let aes = AESWrapper::new(config.num_checkpoints, config.checkpoint_iterations);

        // Build the initial proof.
        // seed = hash(genesis block hash), key = INITIAL_KEY.
        let genesis_block_hash: H256 = genesis_block_hash.into();
        let proof = aes.create_proof(
            genesis_block_hash.into(),
            AesKey(INITIAL_KEY),
            0,
            genesis_block_hash,
        );

        Self {
            config,
            aes,
            last_proof: proof,
            pending_update: None,
            _p: Default::default(),
        }
    }

    /// Processing per time slot.
    fn on_slot(&mut self) {
        let next_slot_number = self.last_proof.slot_number + 1;
        let mut seed = AesSeed(self.last_proof.output().0);
        let mut injected_block_hash = self.last_proof.injected_block_hash;

        // Update the (seed, injected_block_hash) if we reached the update slot.
        let mut updated = false;
        if let Some((slot_number, block_hash)) = self.pending_update {
            if slot_number == next_slot_number {
                seed = Self::update_seed(&seed, block_hash);
                injected_block_hash = block_hash;
                updated = true;
            }
        }
        if updated {
            self.pending_update = None;
        }

        // Compute the next proof
        let key = AesKey::from(&seed);
        self.last_proof = self
            .aes
            .create_proof(seed, key, next_slot_number, injected_block_hash);

        // TODO: send message to farmers.
    }

    /// Processes the block import notification.
    fn on_block_import(&mut self, notification: BlockImportNotification<Block>) {
        let block_number = notification.header.number();
        let injection_depth: NumberFor<Block> = self.config.injection_depth_blocks.into();
        let update_interval = self.config.randomness_update_interval_blocks.into();
        if self.pending_update.is_some()
            || *block_number < injection_depth
            || (*block_number - injection_depth) % update_interval != 0_u32.into()
        {
            return;
        }

        let slot_number = 0; // TODO: get slot number for block.
        self.pending_update = Some((slot_number, notification.hash.into()));
    }

    /// Builds the seed from previous seed and the injected_block_hash_update.
    fn update_seed(seed: &AesSeed, block_hash: H256) -> AesSeed {
        let mut bytes = seed.0.to_vec();
        bytes.append(&mut block_hash.as_bytes().to_vec());
        Blake2Hasher::hash(&bytes).into()
    }
}
