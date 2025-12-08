//! Primitives for Subspace MMR.

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(result_flattening)]

#[cfg(all(feature = "std", feature = "runtime-benchmarks"))]
pub mod benchmarking;
#[cfg(feature = "std")]
pub mod host_functions;
mod runtime_interface;

#[cfg(feature = "std")]
pub use runtime_interface::domain_mmr_runtime_interface::HostFunctions as DomainHostFunctions;
#[cfg(feature = "std")]
pub use runtime_interface::subspace_mmr_runtime_interface::HostFunctions;
pub use runtime_interface::{domain_mmr_runtime_interface, subspace_mmr_runtime_interface};

#[cfg(not(feature = "std"))]
extern crate alloc;

use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::DecodeWithMemTracking;
use sp_mmr_primitives::{EncodableOpaqueLeaf, LeafProof as MmrProof};

/// MMR leaf structure
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum MmrLeaf<BlockNumber, Hash> {
    /// V0 version of leaf data
    V0(LeafDataV0<BlockNumber, Hash>),
}

impl<BlockNumber: Clone, Hash: Clone> MmrLeaf<BlockNumber, Hash> {
    pub fn state_root(&self) -> Hash {
        match self {
            MmrLeaf::V0(leaf) => leaf.state_root.clone(),
        }
    }

    pub fn block_number(&self) -> BlockNumber {
        match self {
            MmrLeaf::V0(leaf) => leaf.block_number.clone(),
        }
    }
}

/// MMR v0 leaf data
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct LeafDataV0<BlockNumber, Hash> {
    pub block_number: BlockNumber,
    pub block_hash: Hash,
    /// Can be used to prove specific storage after block was pruned
    pub state_root: Hash,
    /// Can be used to prove block body
    pub extrinsics_root: Hash,
}

/// Consensus chain MMR leaf and its Proof at specific block.
///
/// The verifier is not required to contains any the MMR offchain data but this proof
/// will be expired after `N` blocks where `N` is the number of MMR root stored in the
// consensus chain runtime.
#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq, TypeInfo, DecodeWithMemTracking)]
pub struct ConsensusChainMmrLeafProof<CBlockNumber, CBlockHash, MmrHash> {
    /// Consensus block info from which this proof was generated.
    pub consensus_block_number: CBlockNumber,
    pub consensus_block_hash: CBlockHash,
    /// Encoded MMR leaf
    pub opaque_mmr_leaf: EncodableOpaqueLeaf,
    /// MMR proof for the leaf above.
    pub proof: MmrProof<MmrHash>,
}

/// Trait to verify MMR proofs
pub trait MmrProofVerifier<MmrHash, CBlockNumber: Decode, CBlockHash: Decode> {
    /// Returns consensus state root if the given MMR proof is valid
    fn verify_proof_and_extract_leaf(
        mmr_leaf_proof: ConsensusChainMmrLeafProof<CBlockNumber, CBlockHash, MmrHash>,
    ) -> Option<MmrLeaf<CBlockNumber, CBlockHash>>;

    fn verify_proof_stateless(
        _mmr_root: MmrHash,
        _mmr_leaf_proof: ConsensusChainMmrLeafProof<CBlockNumber, CBlockHash, MmrHash>,
    ) -> Option<MmrLeaf<CBlockNumber, CBlockHash>> {
        None
    }

    fn extract_leaf_without_verifying(
        mmr_leaf_proof: ConsensusChainMmrLeafProof<CBlockNumber, CBlockHash, MmrHash>,
    ) -> Option<MmrLeaf<CBlockNumber, CBlockHash>> {
        mmr_leaf_proof
            .opaque_mmr_leaf
            .into_opaque_leaf()
            .try_decode()
    }
}

impl<MmrHash, CBlockNumber: Decode, CBlockHash: Decode>
    MmrProofVerifier<MmrHash, CBlockNumber, CBlockHash> for ()
{
    fn verify_proof_and_extract_leaf(
        _mmr_leaf_proof: ConsensusChainMmrLeafProof<CBlockNumber, CBlockHash, MmrHash>,
    ) -> Option<MmrLeaf<CBlockNumber, CBlockHash>> {
        None
    }
}
