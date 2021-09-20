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

use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::convert::TryInto;
use std::hash::Hasher;
use std::iter;
use std::ops::Deref;
use subspace_core_primitives::{crypto, Piece, Sha256Hash, SHA256_HASH_SIZE};
use thiserror::Error;
use typenum::{U0, U2};

#[derive(Default, Clone)]
struct Sha256Algorithm(Sha256);

impl Hasher for Sha256Algorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl merkletree::hash::Algorithm<Sha256Hash> for Sha256Algorithm {
    #[inline]
    fn hash(&mut self) -> Sha256Hash {
        self.0.clone().finalize()[..]
            .try_into()
            .expect("Sha256 output is always 32 bytes; qed")
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }
}

type InternalMerkleTree = merkletree::merkle::MerkleTree<
    Sha256Hash,
    Sha256Algorithm,
    merkletree::store::VecStore<Sha256Hash>,
>;

/// Merkle Proof-based witness
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Witness<'a> {
    merkle_num_leaves: usize,
    witness: Cow<'a, [u8]>,
}

impl<'a> Witness<'a> {
    /// Create witness from vector of bytes, will return bytes back as error in case length is
    /// incorrect
    pub fn new(witness: Cow<'a, [u8]>) -> Result<Self, Cow<'a, [u8]>> {
        if witness.len() % SHA256_HASH_SIZE != 0 {
            return Err(witness);
        }

        Ok(Self {
            merkle_num_leaves: 2_usize.pow((witness.len() / SHA256_HASH_SIZE) as u32),
            witness,
        })
    }

    /// Check whether witness is valid for a specific leaf hash (none of these parameters are stored
    /// in the witness itself) given its index within a segment
    pub fn is_valid(&self, root: Sha256Hash, index: usize, leaf_hash: Sha256Hash) -> bool {
        if index >= self.merkle_num_leaves {
            return false;
        }

        // Hash one more time as Merkle Tree implementation does
        let leaf_hash = {
            let mut hasher = Sha256::new();
            // Merkle Tree leaf hash prefix
            hasher.update(&[0x00]);
            hasher.update(leaf_hash);
            hasher.finalize()[..]
                .try_into()
                .expect("Sha256 output is always 32 bytes; qed")
        };

        // Reconstruct lemma for verification
        let lemma = iter::once(leaf_hash)
            .chain(
                self.witness
                    .chunks_exact(SHA256_HASH_SIZE)
                    .map(|hash| -> Sha256Hash {
                        hash.try_into()
                            .expect("Hash is always of correct length with above constant; qed")
                    }),
            )
            .chain(iter::once(root))
            .collect();

        // There is no path inside of witness, but by knowing index and number of leaves we can
        // recover it
        let path = {
            let mut path = Vec::with_capacity(self.merkle_num_leaves);
            let mut local_index = index;

            for _ in 0..self.merkle_num_leaves.log2() {
                path.push(if local_index % 2 == 0 { 0 } else { 1 });
                local_index /= 2;
            }

            path
        };

        let proof = merkletree::proof::Proof::<Sha256Hash, U2>::new::<U0, U0>(None, lemma, path)
            .expect("Prepared data above are always correct; qed");

        proof.validate::<Sha256Algorithm>().unwrap_or_default()
    }

    // TODO: Move this to archiver module, it doesn't belong here
    /// Validate witness embedded within a piece
    pub fn is_piece_valid(
        piece: &Piece,
        root: Sha256Hash,
        index: usize,
        merkle_num_leaves: usize,
        record_size: usize,
    ) -> bool {
        let witness = Witness {
            merkle_num_leaves,
            witness: Cow::Borrowed(&piece[record_size..]),
        };
        let leaf_hash = crypto::sha256_hash(&piece[..record_size]);

        witness.is_valid(root, index, leaf_hash)
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
#[derive(Debug, Error, Copy, Clone, Eq, PartialEq)]
pub enum MerkleTreeWitnessError {
    /// Wrong index
    #[error("Wrong index, there is just {0} leaves available")]
    WrongIndex(usize),
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
        I: IntoIterator<Item = Sha256Hash>,
    {
        Self {
            merkle_tree: InternalMerkleTree::new(hashes.into_iter())
                .expect("This version of the tree from the library never returns error; qed"),
        }
    }

    /// Creates new merkle tree from a list of source objects
    pub fn from_data<T, I>(data: I) -> Self
    where
        T: AsRef<[u8]>,
        I: IntoIterator<Item = T>,
    {
        Self::new(data.into_iter().map(|d| crypto::sha256_hash(d.as_ref())))
    }

    /// Get Merkle Root
    pub fn root(&self) -> Sha256Hash {
        self.merkle_tree.root()
    }

    /// Creates a Merkle Tree proof-based witness for a leaf at specified index, returns error if
    /// leaf with such index doesn't exist
    pub fn get_witness(&self, index: usize) -> Result<Witness<'static>, MerkleTreeWitnessError> {
        if index >= self.merkle_tree.leafs() {
            return Err(MerkleTreeWitnessError::WrongIndex(self.merkle_tree.leafs()));
        }

        let proof = self
            .merkle_tree
            .gen_proof(index)
            .expect("This version of the tree from the library never returns error; qed");

        // The first lemma element is root and the last is the item itself, we skip both here
        let lemma = proof.lemma().iter().skip(1).rev().skip(1).rev();
        let mut witness = Vec::with_capacity(lemma.len() * SHA256_HASH_SIZE);

        for l in lemma {
            witness.extend_from_slice(l);
        }

        Ok(Witness::new(witness.into())
            .expect("Witness is never expected to have incorrect length"))
    }
}
