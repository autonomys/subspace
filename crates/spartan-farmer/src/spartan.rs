#![warn(missing_debug_implementations, missing_docs)]
//! This is an adaptation of [SLOTH](https://eprint.iacr.org/2015/366) (slow-timed hash function) into a time-asymmetric permutation using a standard CBC block cipher. This code is largely based on the C implementation used in [PySloth](https://github.com/randomchain/pysloth/blob/master/sloth.c) which is the same as used in the paper.

use ::sloth256_189::cpu;
use ::sloth256_189::cuda;

const PIECE_SIZE: usize = 4096; // length of a single piece
const HASH_SIZE: usize = 32; // length of public_key_hash
const GPU_PIECE_BLOCK: usize = 1024; // piece amount should be multiples of 1024 for GPU

/// Spartan struct used to encode and validate
#[derive(Debug, Clone)]
pub struct Spartan {
    genesis_piece: [u8; PIECE_SIZE],
    cuda_available: bool,
}

impl Spartan {
    /// New instance with 256-bit prime and 4096-byte genesis piece size
    pub fn new(genesis_piece: [u8; PIECE_SIZE]) -> Self {
        let cuda_available = cuda::is_cuda_available();
        Spartan {
            genesis_piece,
            cuda_available,
        }
    }
}

impl Spartan {
    /// returns true if CUDA is available
    pub fn is_cuda_available(&self) -> bool {
        self.cuda_available
    }

    /// Create an encoding based on genesis piece using provided encoding key hash, nonce and
    /// desired number of rounds
    pub fn encode(
        &self,
        encoding_key_hash: [u8; HASH_SIZE],
        nonce: u64,
        rounds: usize,
    ) -> [u8; PIECE_SIZE] {
        let mut expanded_iv = encoding_key_hash;
        for (i, &byte) in nonce.to_le_bytes().iter().rev().enumerate() {
            expanded_iv[HASH_SIZE - i - 1] ^= byte;
        }

        let mut encoding = self.genesis_piece;

        cpu::encode(&mut encoding, &expanded_iv, rounds).unwrap();

        encoding
    }
    /// encodes given batch of pieces using GPU, and CPU for the leftovers
    pub fn cuda_batch_encode(
        &self,
        pieces: &mut [u8],
        encoding_key_hash: [u8; HASH_SIZE],
        nonce_array: &[u64],
        rounds: usize,
    ) {
        // each expanded_iv will be in format [u8; 32], so `piece_amount` expanded_iv's
        // should consume [u8; 32 * piece_amount] space.
        let piece_amount = pieces.len() / PIECE_SIZE;
        let mut expanded_iv_vector: Vec<u8> = Vec::with_capacity(piece_amount * HASH_SIZE);
        let mut expanded_iv;
        for nonce in nonce_array {
            // same encoding_key_hash will be used for each expanded_iv
            expanded_iv = encoding_key_hash;

            // select the nonce from nonce_array, xor it with the encoding_key_hash
            nonce
                .to_le_bytes()
                .iter()
                .rev()
                .zip(expanded_iv.iter_mut().rev())
                .for_each(|(nonce_byte, expanded_iv_byte)| *expanded_iv_byte ^= nonce_byte);
            //*/
            expanded_iv_vector.extend(expanded_iv);
        }

        // If there any leftovers from 1024x pieces, cpu will handle them
        let cpu_encode_end_index = piece_amount % GPU_PIECE_BLOCK;

        // CPU encoding:
        for x in 0..cpu_encode_end_index {
            cpu::encode(
                &mut pieces[x * PIECE_SIZE..(x + 1) * PIECE_SIZE],
                &expanded_iv_vector[x * HASH_SIZE..(x + 1) * HASH_SIZE],
                rounds,
            )
            .unwrap();
        }

        // GPU encoding:
        cuda::encode(
            &mut pieces[cpu_encode_end_index * PIECE_SIZE..],
            &expanded_iv_vector[cpu_encode_end_index * HASH_SIZE..],
            rounds,
        )
        .unwrap();
    }

    /// Check if previously created encoding is valid
    pub fn is_valid(
        &self,
        encoding: &mut [u8],
        encoding_key_hash: [u8; HASH_SIZE],
        nonce: u64,
        rounds: usize,
    ) -> bool {
        let mut expanded_iv = encoding_key_hash;
        for (i, &byte) in nonce.to_le_bytes().iter().rev().enumerate() {
            expanded_iv[HASH_SIZE - i - 1] ^= byte;
        }

        cpu::decode(encoding, &expanded_iv, rounds).unwrap();

        encoding == self.genesis_piece
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    fn random_bytes<const BYTES: usize>() -> [u8; BYTES] {
        let mut bytes = [0u8; BYTES];
        rand::thread_rng().fill(&mut bytes[..]);
        bytes
    }

    #[test]
    fn test_random_piece() {
        let genesis_piece = random_bytes();
        let encoding_key = random_bytes();
        let nonce = rand::random();

        let spartan = Spartan::new(genesis_piece);
        let mut encoding = spartan.encode(encoding_key, nonce, 1);

        assert!(spartan.is_valid(&mut encoding, encoding_key, nonce, 1));
    }

    #[test]
    // CUDA accepts multiples of 1024 pieces, and any remainder piece will be handled on CPU
    // this test aims to process 1024 pieces in GPU, and 2 pieces in CPU, hence 1026 pieces.
    fn test_1026_piece() {
        let genesis_piece = random_bytes();
        let mut piece_array: Vec<u8> = Vec::with_capacity(PIECE_SIZE * 1026);
        let encoding_key_hash = random_bytes();
        let nonce: u64 = rand::random();
        let nonce_array = vec![nonce; 1026];

        let spartan = Spartan::new(genesis_piece);

        for _ in 0..1026 {
            piece_array.extend_from_slice(&genesis_piece);
        }

        spartan.cuda_batch_encode(
            &mut piece_array,
            encoding_key_hash,
            nonce_array.as_slice(),
            1,
        );

        for x in 0..1026 {
            assert!(spartan.is_valid(
                &mut piece_array[x * PIECE_SIZE..(x + 1) * PIECE_SIZE],
                encoding_key_hash,
                nonce_array[x],
                1
            ));
        }
    }
}
