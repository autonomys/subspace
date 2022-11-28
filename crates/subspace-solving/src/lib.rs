// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Set of modules that implement utilities for solving and verifying of solutions in
//! [Subspace Network Blockchain](https://subspace.network).

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use merlin::Transcript;
use schnorrkel::vrf::{VRFInOut, VRFOutput, VRFProof};
use schnorrkel::{Keypair, PublicKey, SignatureResult};
use subspace_core_primitives::crypto::blake2b_256_hash_list;
use subspace_core_primitives::{Blake2b256Hash, ChunkSignature, Randomness, Scalar};

const CHUNK_SIGNATURE_LABEL: &[u8] = b"subspace_chunk_signature";

/// Signing context used for creating reward signatures by farmers.
pub const REWARD_SIGNING_CONTEXT: &[u8] = b"subspace_reward";

// TODO: Separate type for global challenge
/// Derive global slot challenge from global randomness.
pub fn derive_global_challenge(global_randomness: &Randomness, slot: u64) -> Blake2b256Hash {
    blake2b_256_hash_list(&[global_randomness, &slot.to_le_bytes()])
}

/// Transcript used for creation and verification of VRF signatures for chunks.
pub fn create_chunk_signature_transcript(chunk_bytes: &[u8; Scalar::FULL_BYTES]) -> Transcript {
    let mut transcript = Transcript::new(CHUNK_SIGNATURE_LABEL);
    transcript.append_message(b"chunk", chunk_bytes);
    transcript
}

/// Create tag signature using farmer's keypair.
pub fn create_chunk_signature(
    keypair: &Keypair,
    chunk_bytes: &[u8; Scalar::FULL_BYTES],
) -> ChunkSignature {
    let (in_out, proof, _) = keypair.vrf_sign(create_chunk_signature_transcript(chunk_bytes));

    ChunkSignature {
        output: in_out.output.to_bytes(),
        proof: proof.to_bytes(),
    }
}

/// Verify that chunk signature was created correctly.
pub fn verify_chunk_signature(
    chunk_bytes: &[u8; Scalar::FULL_BYTES],
    chunk_signature: &ChunkSignature,
    public_key: &PublicKey,
) -> SignatureResult<VRFInOut> {
    public_key
        .vrf_verify(
            create_chunk_signature_transcript(chunk_bytes),
            &VRFOutput(chunk_signature.output),
            &VRFProof::from_bytes(&chunk_signature.proof)?,
        )
        .map(|(in_out, _)| in_out)
}
