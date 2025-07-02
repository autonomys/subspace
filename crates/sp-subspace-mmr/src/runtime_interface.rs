//! Runtime interface for Subspace-specific MMR operations.
//! Used to verify MMR proofs in the domain runtime, based on the consensus MMR state.

#[cfg(all(feature = "std", not(feature = "runtime-benchmarks")))]
use crate::host_functions::SubspaceMmrExtension;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use scale_info::prelude::vec::Vec;
use sp_core::H256;
#[cfg(all(feature = "std", not(feature = "runtime-benchmarks")))]
use sp_externalities::ExternalitiesExt;
use sp_mmr_primitives::EncodableOpaqueLeaf;
use sp_runtime_interface::runtime_interface;
use subspace_core_primitives::BlockNumber;

/// MMR related runtime interface
#[runtime_interface]
pub trait SubspaceMmrRuntimeInterface {
    /// Returns the MMR leaf for the given consensus block.
    fn get_mmr_leaf_data(&mut self, consensus_block_hash: H256) -> Option<LeafData> {
        #[cfg(not(feature = "runtime-benchmarks"))]
        {
            self.extension::<SubspaceMmrExtension>()
                .expect("No `SubspaceMmrExtension` associated for the current context!")
                .get_mmr_leaf_data(consensus_block_hash)
        }

        // We assume this implementation costs slightly less than the real implementation,
        // but it's the best we can do for now.
        // TODO: when custom extensions are supported in benchmarks, remove this code and call
        // directly into SubspaceMmrExtension.
        // <https://github.com/paritytech/polkadot-sdk/issues/137>
        #[cfg(feature = "runtime-benchmarks")]
        {
            crate::benchmarking::mock_subspace_mmr_extension()
                .get_mmr_leaf_data(consensus_block_hash)
        }
    }

    /// Returns the consensus block hash for a given block number.
    fn consensus_block_hash(&mut self, block_number: BlockNumber) -> Option<H256> {
        #[cfg(not(feature = "runtime-benchmarks"))]
        {
            self.extension::<SubspaceMmrExtension>()
                .expect("No `SubspaceMmrExtension` associated for the current context!")
                .consensus_block_hash(block_number)
        }

        // We assume this implementation costs slightly less than the real implementation,
        // but it's the best we can do for now.
        // TODO: when custom extensions are supported, call directly into SubspaceMmrExtension.
        #[cfg(feature = "runtime-benchmarks")]
        {
            crate::benchmarking::mock_subspace_mmr_extension().consensus_block_hash(block_number)
        }
    }
}

/// Leaf data sent back from host function.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, Default)]
pub struct LeafData {
    pub state_root: H256,
    pub extrinsics_root: H256,
}

#[runtime_interface]
pub trait DomainMmrRuntimeInterface {
    /// Verifies the given MMR proof using the leaves provided.
    fn verify_mmr_proof(
        &mut self,
        leaves: Vec<EncodableOpaqueLeaf>,
        encoded_proof: Vec<u8>,
    ) -> bool {
        #[cfg(not(feature = "runtime-benchmarks"))]
        {
            self.extension::<SubspaceMmrExtension>()
                .expect("No `SubspaceMmrExtension` associated for the current context!")
                .verify_mmr_proof(leaves, encoded_proof)
        }

        // We assume this implementation costs slightly less than the real implementation,
        // but it's the best we can do for now.
        // TODO: when custom extensions are supported, call directly into SubspaceMmrExtension.
        #[cfg(feature = "runtime-benchmarks")]
        {
            crate::benchmarking::mock_subspace_mmr_extension()
                .verify_mmr_proof(leaves, encoded_proof)
        }
    }

    // Return `true` if the given consensus block is finalized.
    fn is_consensus_block_finalized(&mut self, block_number: BlockNumber) -> bool {
        #[cfg(not(feature = "runtime-benchmarks"))]
        {
            self.extension::<SubspaceMmrExtension>()
                .expect("No `SubspaceMmrExtension` associated for the current context!")
                .is_consensus_block_finalized(block_number)
        }

        // This implementation obviously costs less than the real implementation, but it's the best
        // we can do for now.
        // TODO: when custom extensions are supported, call directly into SubspaceMmrExtension.
        #[cfg(feature = "runtime-benchmarks")]
        {
            crate::benchmarking::mock_subspace_mmr_extension()
                .is_consensus_block_finalized(block_number)
        }
    }
}
