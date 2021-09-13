//! This module includes Merkle Tree implementation used in Subspace

use itertools::Itertools;
use ring::digest;
use std::convert::TryInto;
use std::hash::Hasher;
use std::mem;

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

// TODO: Custom struct that supports verification with root and leaf nodes removed
type InternalMerkleTree = merkletree::merkle::MerkleTree<
    Sha256Hash,
    Sha256Algorithm,
    merkletree::store::VecStore<Sha256Hash>,
>;

/// Merkle Proof
#[derive(Debug, Clone)]
pub struct Proof {
    /// Path of this proof
    pub path: Vec<u8>,
    /// Lemma of this proof
    pub lemma: Vec<Sha256Hash>,
}

// TODO: Proof verification, construction from witness

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

    /// Get Merkle root
    pub fn root(&self) -> Sha256Hash {
        self.merkle_tree.root()
    }

    /// Creates a proof for a leaf at specified index, returns error if leaf with such index doesn't
    /// exist
    pub fn get_proof(&self, index: usize) -> Result<Proof, ()> {
        if index >= self.merkle_tree.leafs() {
            return Err(());
        }

        let proof = self
            .merkle_tree
            .gen_proof(index)
            .expect("This version of the tree from the library never returns error; qed");

        Ok(Proof {
            path: proof.path().iter().map(|p| *p as u8).collect(),
            lemma: proof
                .lemma()
                .iter()
                .skip(1)
                .rev()
                .skip(1)
                .rev()
                .cloned()
                .collect(),
        })
    }

    /// Creates a Merkle Tree proof-based witness for a leaf at specified index, returns error if
    /// leaf with such index doesn't exist
    pub fn get_witness(&self, index: usize) -> Result<Vec<u8>, ()> {
        if index >= self.merkle_tree.leafs() {
            return Err(());
        }

        let proof = self
            .merkle_tree
            .gen_proof(index)
            .expect("This version of the tree from the library never returns error; qed");

        let mut witness = Vec::with_capacity(
            (1 + mem::size_of::<Sha256Hash>()) * self.merkle_tree.leafs().log2(),
        );
        for (path, lemma) in proof
            .path()
            .iter()
            .zip_eq(proof.lemma().iter().skip(1).rev().skip(1).rev())
        {
            witness.extend_from_slice(&[*path as u8]);
            witness.extend_from_slice(lemma);
        }

        Ok(witness)
    }
}
