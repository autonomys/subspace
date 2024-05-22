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

//! Primitives for Subspace MMR.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod host_functions;
mod runtime_interface;
#[cfg(feature = "std")]
pub use runtime_interface::domain_mmr_runtime_interface::HostFunctions as DomainHostFunctions;
#[cfg(feature = "std")]
pub use runtime_interface::subspace_mmr_runtime_interface::HostFunctions;
pub use runtime_interface::{domain_mmr_runtime_interface, subspace_mmr_runtime_interface};

use codec::{Codec, Decode, Encode};
use scale_info::TypeInfo;
use sp_mmr_primitives::{EncodableOpaqueLeaf, Proof as MmrProof};
use sp_runtime::generic::OpaqueDigestItemId;
use sp_runtime::DigestItem;

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

/// MMR specific digest item.
#[derive(PartialEq, Eq, Clone, Encode, Decode, TypeInfo)]
pub enum MmrDigestItem<MmrRootHash: Codec> {
    NewMmrRoot(MmrRootHash),
}

/// MMR specific digest items interface.
pub trait MmrDigest<MmrRootHash> {
    fn new_mmr_root(root: MmrRootHash) -> Self;
    fn as_new_mmr_root(&self) -> Option<MmrRootHash>;
}

impl<MmrRootHash: Codec> MmrDigest<MmrRootHash> for DigestItem {
    fn new_mmr_root(root: MmrRootHash) -> Self {
        DigestItem::Other(MmrDigestItem::NewMmrRoot(root).encode())
    }

    fn as_new_mmr_root(&self) -> Option<MmrRootHash> {
        match self.try_to::<MmrDigestItem<MmrRootHash>>(OpaqueDigestItemId::Other) {
            Some(MmrDigestItem::NewMmrRoot(root)) => Some(root),
            _ => None,
        }
    }
}

/// Consensus chain MMR leaf and its Proof at specific block.
///
/// The verifier is not required to contains any the MMR offchain data but this proof
/// will be expired after `N` blocks where `N` is the number of MMR root stored in the
// consensus chain runtime.
#[derive(Debug, Encode, Decode, Eq, PartialEq, TypeInfo)]
pub struct ConsensusChainMmrLeafProof<CBlockNumber, CBlockHash, MmrHash> {
    /// Consensus block info from which this proof was generated.
    pub consensus_block_number: CBlockNumber,
    pub consensus_block_hash: CBlockHash,
    /// Encoded MMR leaf
    pub opaque_mmr_leaf: EncodableOpaqueLeaf,
    /// MMR proof for the leaf above.
    pub proof: MmrProof<MmrHash>,
}

// TODO: update upstream `EncodableOpaqueLeaf` to derive clone.
impl<CBlockNumber: Clone, CBlockHash: Clone, MmrHash: Clone> Clone
    for ConsensusChainMmrLeafProof<CBlockNumber, CBlockHash, MmrHash>
{
    fn clone(&self) -> Self {
        Self {
            consensus_block_number: self.consensus_block_number.clone(),
            consensus_block_hash: self.consensus_block_hash.clone(),
            opaque_mmr_leaf: EncodableOpaqueLeaf(self.opaque_mmr_leaf.0.clone()),
            proof: self.proof.clone(),
        }
    }
}

/// Trait to verify MMR proofs
pub trait MmrProofVerifier<MmrHash, CBlockNumber, CBlockHash> {
    /// Returns consensus state root if the given MMR proof is valid
    fn verify_proof_and_extract_leaf(
        mmr_leaf_proof: ConsensusChainMmrLeafProof<CBlockNumber, CBlockHash, MmrHash>,
    ) -> Option<MmrLeaf<CBlockNumber, CBlockHash>>;
}

impl<MmrHash, CBlockNumber, CBlockHash> MmrProofVerifier<MmrHash, CBlockNumber, CBlockHash> for () {
    fn verify_proof_and_extract_leaf(
        _mmr_leaf_proof: ConsensusChainMmrLeafProof<CBlockNumber, CBlockHash, MmrHash>,
    ) -> Option<MmrLeaf<CBlockNumber, CBlockHash>> {
        None
    }
}
