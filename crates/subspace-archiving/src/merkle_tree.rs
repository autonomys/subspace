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

//! This module includes Merkle Tree implementation used in Subspace
extern crate alloc;

use alloc::borrow::Cow;
use alloc::vec::Vec;
use blake2_rfc::blake2b::Blake2b;
use core::hash::Hasher;
use core::iter;
use core::ops::Deref;
use subspace_core_primitives::{crypto, Blake2b256Hash, BLAKE2B_256_HASH_SIZE};

#[derive(Debug, Clone)]
struct Blake2b256Algorithm(Blake2b);

impl Default for Blake2b256Algorithm {
    fn default() -> Self {
        Self(Blake2b::new(BLAKE2B_256_HASH_SIZE))
    }
}

impl Hasher for Blake2b256Algorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl merkle_light::hash::Algorithm<Blake2b256Hash> for Blake2b256Algorithm {
    #[inline]
    fn hash(&mut self) -> Blake2b256Hash {
        self.0
            .clone()
            .finalize()
            .as_bytes()
            .try_into()
            .expect("Initialized with correct length; qed")
    }

    #[inline]
    fn reset(&mut self) {
        *self = Self::default();
    }
}

type InternalMerkleTree = merkle_light::merkle::MerkleTree<Blake2b256Hash, Blake2b256Algorithm>;

/// Merkle Proof-based witness
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Witness<'a> {
    /// Number of leaves in the Merkle Tree that corresponds to this witness
    merkle_num_leaves: u32,
    /// The witness itself
    witness: Cow<'a, [u8]>,
}

impl<'a> Witness<'a> {
    /// Create witness from vector of bytes, will return bytes back as error in case length is
    /// incorrect
    pub fn new(witness: Cow<'a, [u8]>) -> Result<Self, Cow<'a, [u8]>> {
        if witness.len() % BLAKE2B_256_HASH_SIZE != 0 {
            return Err(witness);
        }

        Ok(Self {
            merkle_num_leaves: 2_u32.pow((witness.len() / BLAKE2B_256_HASH_SIZE) as u32),
            witness,
        })
    }

    /// Check whether witness is valid for a specific leaf hash (none of these parameters are stored
    /// in the witness itself) given its position within a segment
    pub fn is_valid(&self, root: Blake2b256Hash, position: u32, leaf_hash: Blake2b256Hash) -> bool {
        if position >= self.merkle_num_leaves {
            return false;
        }

        // Hash one more time as Merkle Tree implementation does
        // Merkle Tree leaf hash prefix is `0x00`
        let leaf_hash = crypto::blake2b_256_hash_pair(&[0x00], &leaf_hash);

        // Reconstruct lemma for verification
        let lemma =
            iter::once(leaf_hash)
                .chain(self.witness.chunks_exact(BLAKE2B_256_HASH_SIZE).map(
                    |hash| -> Blake2b256Hash {
                        hash.try_into()
                            .expect("Hash is always of correct length with above constant; qed")
                    },
                ))
                .chain(iter::once(root))
                .collect();

        // There is no path inside of witness, but by knowing position and number of leaves we can
        // recover it
        let path = {
            let mut path = Vec::with_capacity(self.merkle_num_leaves as usize);
            let mut local_position = position;

            for _ in 0..self.merkle_num_leaves.ilog2() {
                path.push(local_position % 2 == 0);
                local_position /= 2;
            }

            path
        };

        let proof = merkle_light::proof::Proof::<Blake2b256Hash>::new(lemma, path);

        proof.validate::<Blake2b256Algorithm>()
    }
}

impl<'a> Deref for Witness<'a> {
    type Target = Cow<'a, [u8]>;

    fn deref(&self) -> &Self::Target {
        &self.witness
    }
}

impl<'a> From<Witness<'a>> for Cow<'a, [u8]> {
    fn from(witness: Witness<'a>) -> Self {
        witness.witness
    }
}

/// Errors that can happen when creating a witness
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum MerkleTreeWitnessError {
    /// Wrong position
    #[cfg_attr(
        feature = "thiserror",
        error("Wrong position, there is just {0} leaves available")
    )]
    WrongPosition(usize),
}

/// Merkle Tree
#[derive(Debug, Clone)]
pub struct MerkleTree {
    merkle_tree: InternalMerkleTree,
}

impl MerkleTree {
    /// Creates new merkle tree from a list of hashes
    pub fn new<I>(hashes: I) -> Self
    where
        I: IntoIterator<Item = Blake2b256Hash>,
    {
        Self {
            merkle_tree: InternalMerkleTree::new(hashes.into_iter()),
        }
    }

    /// Creates new merkle tree from a list of source objects
    pub fn from_data<T, I>(data: I) -> Self
    where
        T: AsRef<[u8]>,
        I: IntoIterator<Item = T>,
    {
        Self::new(
            data.into_iter()
                .map(|item| crypto::blake2b_256_hash(item.as_ref())),
        )
    }

    /// Get Merkle Root
    pub fn root(&self) -> Blake2b256Hash {
        self.merkle_tree.root()
    }

    /// Creates a Merkle Tree proof-based witness for a leaf at specified position, returns error if
    /// leaf with such position doesn't exist
    pub fn get_witness(&self, position: usize) -> Result<Witness<'static>, MerkleTreeWitnessError> {
        if position >= self.merkle_tree.leafs() {
            return Err(MerkleTreeWitnessError::WrongPosition(
                self.merkle_tree.leafs(),
            ));
        }

        let proof = self.merkle_tree.gen_proof(position);

        // The first lemma element is root and the last is the item itself, we skip both here
        let lemma = proof.lemma().iter().skip(1).rev().skip(1).rev();
        let mut witness = Vec::with_capacity(lemma.len() * BLAKE2B_256_HASH_SIZE);

        for l in lemma {
            witness.extend_from_slice(l);
        }

        Ok(Witness::new(witness.into())
            .expect("Witness is never expected to have incorrect length"))
    }
}
