//! This module includes Merkle Tree implementation used in Subspace

use crate::{HASH_OUTPUT_BYTES, MERKLE_NUM_LEAVES, RECORD_SIZE, WITNESS_SIZE};
use ring::digest;
use sp_consensus_spartan::spartan::Piece;
use std::borrow::Cow;
use std::convert::TryInto;
use std::hash::Hasher;
use std::iter;
use std::ops::Deref;
use thiserror::Error;
use typenum::{U0, U2};

type Sha256Hash = [u8; 32];

#[derive(Clone)]
struct Sha256Algorithm(digest::Context);

impl Default for Sha256Algorithm {
    fn default() -> Sha256Algorithm {
        Sha256Algorithm(digest::Context::new(&digest::SHA256))
    }
}

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
        self.0
            .clone()
            .finish()
            .as_ref()
            .try_into()
            .expect("Sha256 output is always 32 bytes; qed")
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = digest::Context::new(&digest::SHA256);
    }
}

type InternalMerkleTree = merkletree::merkle::MerkleTree<
    Sha256Hash,
    Sha256Algorithm,
    merkletree::store::VecStore<Sha256Hash>,
>;

/// Merkle Proof-based witness
#[derive(Debug, Clone)]
pub struct Witness<'a>(Cow<'a, [u8]>);

impl<'a> Witness<'a> {
    /// Create witness from vector of bytes, will return bytes back as error in case length is
    /// incorrect
    pub fn new(bytes: Cow<'a, [u8]>) -> Result<Self, Cow<'a, [u8]>> {
        if bytes.len() != WITNESS_SIZE {
            return Err(bytes);
        }

        Ok(Self(bytes))
    }

    /// Check whether witness is valid for a specific leaf hash (none of these parameters are stored
    /// in the witness itself) given its index within a segment
    pub fn is_valid(&self, root: Sha256Hash, index: usize, leaf_hash: Sha256Hash) -> bool {
        if index >= MERKLE_NUM_LEAVES {
            return false;
        }

        // Reconstruct lemma for verification
        let lemma = iter::once(root)
            .chain(
                self.0
                    .chunks_exact(HASH_OUTPUT_BYTES)
                    .map(|hash| -> Sha256Hash {
                        hash.try_into()
                            .expect("Hash is always of correct length with above constant; qed")
                    }),
            )
            .chain(iter::once(leaf_hash))
            .collect();

        // There is no path inside of witness, but by knowing index and number of leaves we can
        // recover it
        let path = {
            let mut path = Vec::with_capacity(MERKLE_NUM_LEAVES as usize);
            let mut mid_point = MERKLE_NUM_LEAVES;

            for _ in 0..MERKLE_NUM_LEAVES {
                mid_point /= 2;
                path.push(if index < mid_point { 0 } else { 1 });
            }

            // Path should go from leaves to the root, so let's reverse it
            path.reverse();
            path
        };

        let proof = merkletree::proof::Proof::<Sha256Hash, U2>::new::<U0, U0>(None, lemma, path)
            .expect("Prepared data above are always correct; qed");

        proof.validate::<Sha256Algorithm>().unwrap_or_default()
    }

    /// validate witness embedded within a piece
    pub fn is_piece_valid(piece: &Piece, root: Sha256Hash, index: usize) -> bool {
        let witness = Witness(Cow::Borrowed(&piece[RECORD_SIZE..]));
        let leaf_hash = digest::digest(&digest::SHA256, &piece[..RECORD_SIZE])
            .as_ref()
            .try_into()
            .expect("Sha256 output is always 32 bytes; qed");

        witness.is_valid(root, index, leaf_hash)
    }
}

impl<'a> Deref for Witness<'a> {
    type Target = Cow<'a, [u8]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> From<Witness<'a>> for Cow<'a, [u8]> {
    fn from(witness: Witness<'a>) -> Self {
        witness.0
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
    pub fn new<T>(data: T) -> Self
    where
        T: IntoIterator<Item = Sha256Hash>,
    {
        Self {
            merkle_tree: InternalMerkleTree::new(data)
                .expect("This version of the tree from the library never returns error; qed"),
        }
    }

    /// Creates new merkle tree from a list of source objects
    pub fn from_data<T, I>(data: I) -> Self
    where
        T: AsRef<[u8]>,
        I: IntoIterator<Item = T>,
    {
        Self::new(data.into_iter().map(|d| {
            digest::digest(&digest::SHA256, d.as_ref())
                .as_ref()
                .try_into()
                .expect("Sha256 output is always 32 bytes; qed")
        }))
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

        let mut witness = Vec::with_capacity(WITNESS_SIZE);

        // The first lemma element is root and the last is the item itself, we skip both here
        for lemma in proof.lemma().iter().skip(1).rev().skip(1).rev() {
            witness.extend_from_slice(lemma);
        }

        Ok(Witness::new(witness.into())
            .expect("Witness is never expected to have incorrect length"))
    }
}
