#[cfg(feature = "std")]
use crate::host_functions::SubspaceMmrExtension;
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::H256;
#[cfg(feature = "std")]
use sp_externalities::ExternalitiesExt;
use sp_runtime_interface::runtime_interface;

/// MMR related runtime interface
#[runtime_interface]
pub trait SubspaceMmrRuntimeInterface {
    /// Returns the MMR leaf.
    #[allow(dead_code)]
    fn get_mmr_leaf_data(&mut self, consensus_block_hash: H256) -> Option<LeafData> {
        self.extension::<SubspaceMmrExtension>()
            .expect("No `SubspaceMmrExtension` associated for the current context!")
            .get_mmr_leaf_data(consensus_block_hash)
    }
}

/// Leaf data sent back from host function.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, Default)]
pub struct LeafData {
    pub state_root: H256,
    pub extrinsics_root: H256,
}
