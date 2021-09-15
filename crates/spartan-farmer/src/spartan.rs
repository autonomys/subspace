#![warn(missing_debug_implementations, missing_docs)]
//! This is an adaptation of [SLOTH](https://eprint.iacr.org/2015/366) (slow-timed hash function) into a time-asymmetric permutation using a standard CBC block cipher. This code is largely based on the C implementation used in [PySloth](https://github.com/randomchain/pysloth/blob/master/sloth.c) which is the same as used in the paper.

use sloth256_189::cpu;
use sloth256_189::cuda;

/// Spartan struct used to encode and validate
#[derive(Debug, Clone)]
pub struct Spartan {
    genesis_piece: [u8; 4096],
}

impl Spartan {
    /// New instance with 256-bit prime and 4096-byte genesis piece size
    pub fn new(genesis_piece: [u8; 4096]) -> Self {
        Spartan { genesis_piece }
    }
}

impl Spartan {
    /// Create an encoding based on genesis piece using provided encoding key hash, nonce and
    /// desired number of rounds
    pub fn encode(&self, encoding_key_hash: [u8; 32], nonce: u64, rounds: usize) -> [u8; 4096] {
        let mut expanded_iv = encoding_key_hash;
        for (i, &byte) in nonce.to_le_bytes().iter().rev().enumerate() {
            expanded_iv[32 - i - 1] ^= byte;
        }

        let mut encoding = self.genesis_piece;

        if cuda::check_cuda() {
            cuda::encode(&mut encoding, &expanded_iv, rounds).unwrap();
        } else {
            cpu::encode(&mut encoding, &expanded_iv, rounds).unwrap();
        }
        encoding
    }

    pub fn batch_encode(
        &self,
        piece_amount: usize,
        pieces: &mut [u8],
        encoding_key_hash: [u8; 32],
        nonce_array: &mut [u64],
        rounds: usize,
    ) {
        let mut expanded_iv_vector: Vec<u8> = Vec::with_capacity(len * 32);
        for x in 0..piece_amount {
            let mut expanded_iv = encoding_key_hash;
            for (i, &byte) in nonce_array[x].to_le_bytes().iter().rev().enumerate() {
                expanded_iv[32 - i - 1] ^= byte;
            }
            expanded_iv_vector.extend(expanded_iv);
        }
        if cuda::is_cuda_available() {
            // TODO
            // tweak the this with respect to CPU and GPU performance
            // so the load balancing can be done better
            // right now it puts all the hard work to GPU
            // and handles the remaining dust in CPU
            let cpu_encode_end_index = piece_amount % 1024;

            // Do this in parallel with the GPU encode
            for x in 0..cpu_encode_end_index {
                cpu::encode(
                    &mut pieces[x * 4096..(x + 1) * 4096],
                    &expanded_iv_vector[x * 32..(x + 1) * 32],
                    rounds,
                )
                .unwrap();
            }

            // Do this in parallel with the CPU encode
            cuda::encode(
                &mut pieces[cpu_encode_end_index * 4096..],
                &expanded_iv_vector[cpu_encode_end_index * 32..],
                rounds,
            )
            .unwrap();
        }
        // if there is no CUDA in this device
        else {
            // do all the pieces in CPU (currently)
            for x in 0..piece_amount {
                cpu::encode(
                    &mut pieces[x * 4096..(x + 1) * 4096],
                    &expanded_iv_vector[x * 32..(x + 1) * 32],
                    rounds,
                )
                .unwrap();
            }
        }
    }

    /// Check if previously created encoding is valid
    pub fn is_valid(
        &self,
        mut encoding: [u8; 4096],
        encoding_key_hash: [u8; 32],
        nonce: u64,
        rounds: usize,
    ) -> bool {
        let mut expanded_iv = encoding_key_hash;
        for (i, &byte) in nonce.to_le_bytes().iter().rev().enumerate() {
            expanded_iv[32 - i - 1] ^= byte;
        }

        cpu::decode(&mut encoding, &expanded_iv, rounds);

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
        let encoding = spartan.encode(encoding_key, nonce, 1);

        assert!(spartan.is_valid(encoding, encoding_key, nonce, 1));
    }
}
